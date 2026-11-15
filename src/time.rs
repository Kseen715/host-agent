//! Wall-clock time as Prometheus and Loki take it, and Docker's
//! RFC 3339 timestamps read without a date library.

use crate::zone::Zone;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn now_ns() -> i64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |since| since.as_nanos() as i64)
}

pub fn now_ms() -> i64 {
    now_ns() / 1_000_000
}

/// `2026-10-25T17:29:39.083219699Z` (or with an offset) as nanoseconds
/// since the epoch.
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[10] != b'T' || b[13] != b':' {
        return None;
    }
    let num = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let days = days_from_civil(num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let seconds = days * 86_400 + num(11, 13)? * 3600 + num(14, 16)? * 60;
    let mut nanos = (seconds + num(17, 19)?) * 1_000_000_000;

    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        let mut scale = 100_000_000;
        for digit in fraction[..digits].bytes().take(9) {
            nanos += i64::from(digit - b'0') * scale;
            scale /= 10;
        }
        rest = &fraction[digits..];
    }
    Some(nanos - offset_seconds(rest)? * 1_000_000_000)
}

/// `Z`, `+03:00` or `-05:00`.
fn offset_seconds(text: &str) -> Option<i64> {
    if text == "Z" {
        return Some(0);
    }
    let sign = match text.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let hours: i64 = text.get(1..3)?.parse().ok()?;
    let minutes: i64 = text.get(4..6)?.parse().ok()?;
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard
/// Hinnant's algorithm).
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `seconds` since the epoch as UTC's year, month, day, hour, minute,
/// second (Howard Hinnant's civil_from_days).
pub fn civil(seconds: i64) -> [i64; 6] {
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524
        - day_of_era / 146_096)
        / 365;
    let day_of_year =
        day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = (month_from_march + 2) % 12 + 1;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    [
        year,
        month,
        day,
        of_day / 3600,
        of_day / 60 % 60,
        of_day % 60,
    ]
}

/// The year of `seconds` since the epoch.
pub fn year_of(seconds: i64) -> i64 {
    let days = seconds.div_euclid(86_400);
    let mut year = 1970 + days * 400 / 146_097;
    while days_from_civil(year, 1, 1) > days {
        year -= 1;
    }
    while days_from_civil(year + 1, 1, 1) <= days {
        year += 1;
    }
    year
}

/// A Go or Prometheus duration: `90s`, `1h30m`, `500ms`, `7d`.
pub fn parse_duration(text: &str) -> Option<Duration> {
    let mut rest = text.trim();
    if rest == "0" {
        return Some(Duration::ZERO);
    }
    if rest.is_empty() {
        return None;
    }
    let mut seconds = 0.0;
    while !rest.is_empty() {
        let number = |c: char| c.is_ascii_digit() || c == '.';
        let end = rest.find(|c| !number(c)).unwrap_or(rest.len());
        let value: f64 = rest[..end].parse().ok()?;
        rest = &rest[end..];
        let end = rest.find(number).unwrap_or(rest.len());
        let scale = match &rest[..end] {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86_400.0,
            "w" => 604_800.0,
            "y" => 31_536_000.0,
            _ => return None,
        };
        seconds += value * scale;
        rest = &rest[end..];
    }
    Some(Duration::from_secs_f64(seconds))
}

/// Go's named layouts, as stage.timestamp's `format` takes them.
pub fn named_layout(name: &str) -> &str {
    match name {
        "ANSIC" => "Mon Jan _2 15:04:05 2006",
        "UnixDate" => "Mon Jan _2 15:04:05 MST 2006",
        "RubyDate" => "Mon Jan 02 15:04:05 -0700 2006",
        "RFC822" => "02 Jan 06 15:04 MST",
        "RFC822Z" => "02 Jan 06 15:04 -0700",
        "RFC850" => "Monday, 02-Jan-06 15:04:05 MST",
        "RFC1123" => "Mon, 02 Jan 2006 15:04:05 MST",
        "RFC1123Z" => "Mon, 02 Jan 2006 15:04:05 -0700",
        "RFC3339" => "2006-01-02T15:04:05Z07:00",
        "RFC3339Nano" => "2006-01-02T15:04:05.999999999Z07:00",
        "Kitchen" => "3:04PM",
        "Stamp" => "Jan _2 15:04:05",
        "StampMilli" => "Jan _2 15:04:05.000",
        "StampMicro" => "Jan _2 15:04:05.000000",
        "StampNano" => "Jan _2 15:04:05.000000000",
        layout => layout,
    }
}

/// The elements of Go's reference time, longest first where one
/// starts another.
const ELEMENTS: [&str; 31] = [
    "January", "Monday", "Jan", "Mon", "MST", "2006", "-07:00", "-0700", "-07",
    "Z07:00", "Z0700", "Z07", "15", "01", "02", "_2", "03", "04", "05", "06",
    "PM", "pm", "1", "2", "3", "4", "5", ".0", ".9", ",0", ",9",
];

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// A time read so far; a year left out is this one, as Promtail does.
#[derive(Default)]
struct Read {
    year: Option<i64>,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    nanos: i64,
    pm: Option<bool>,
    /// A numeric offset read: it wins over the location.
    offset: Option<i64>,
    abbreviation: Option<String>,
}

/// `text` read with a Go layout (`2006-01-02 15:04:05`), as
/// nanoseconds since the epoch, as Go's ParseInLocation reads it: a
/// time without an offset is in `zone` (UTC without), an abbreviation
/// one the zone uses or else UTC.
pub fn parse_layout(
    layout: &str,
    text: &str,
    zone: Option<&Zone>,
) -> Option<i64> {
    let (mut layout, mut text) = (layout, text);
    let mut read = Read {
        month: 1,
        day: 1,
        ..Read::default()
    };
    while let Some(c) = layout.chars().next() {
        let element = ELEMENTS.iter().find(|e| layout.starts_with(**e));
        let Some(element) = element else {
            text = text.strip_prefix(c)?;
            layout = &layout[c.len_utf8()..];
            continue;
        };
        let fraction = element.starts_with(['.', ',']);
        let width = if fraction {
            1 + layout[1..]
                .bytes()
                .take_while(|b| *b == element.as_bytes()[1])
                .count()
        } else {
            element.len()
        };
        text = read.element(&layout[..width], text)?;
        layout = &layout[width..];
        if *element == "05" && !layout.starts_with(['.', ',']) {
            text = read.fraction(text, 9, true)?;
        }
    }
    if !text.is_empty() {
        return None;
    }
    read.nanos(zone)
}

impl Read {
    /// Reads one element; what follows it.
    fn element<'a>(&mut self, element: &str, text: &'a str) -> Option<&'a str> {
        let (value, rest) = match element {
            "January" | "Jan" => return self.month_name(text, element.len()),
            "Monday" | "Mon" | "MST" => {
                let n = text.bytes().take_while(u8::is_ascii_alphabetic);
                let (name, rest) = text.split_at(n.count());
                if element == "MST" {
                    self.abbreviation = Some(name.to_owned());
                }
                return Some(rest);
            }
            "PM" | "pm" => {
                let (head, rest) = (text.get(..2)?, &text[2..]);
                self.pm = Some(head.eq_ignore_ascii_case("pm"));
                return Some(rest);
            }
            "2006" => digits(text, 4, 4)?,
            "_2" => digits(text.strip_prefix(' ').unwrap_or(text), 1, 2)?,
            "1" | "2" | "3" | "4" | "5" => digits(text, 1, 2)?,
            e if e.starts_with(['-', 'Z']) => return self.zone(e, text),
            e if e.starts_with(['.', ',']) => {
                let optional = e.as_bytes()[1] == b'9';
                return self.fraction(text, e.len() - 1, optional);
            }
            _ => digits(text, 2, 2)?,
        };
        match element {
            "2006" => self.year = Some(value),
            "06" => {
                self.year = Some(value + if value < 69 { 2000 } else { 1900 })
            }
            "01" | "1" => self.month = value,
            "02" | "_2" | "2" => self.day = value,
            "15" | "03" | "3" => self.hour = value,
            "04" | "4" => self.minute = value,
            _ => self.second = value,
        }
        Some(rest)
    }

    fn month_name<'a>(&mut self, text: &'a str, len: usize) -> Option<&'a str> {
        for (index, name) in MONTHS.iter().enumerate() {
            let name = if len == 3 { &name[..3] } else { name };
            if text.get(..name.len())?.eq_ignore_ascii_case(name) {
                self.month = index as i64 + 1;
                return Some(&text[name.len()..]);
            }
        }
        None
    }

    fn zone<'a>(&mut self, element: &str, text: &'a str) -> Option<&'a str> {
        if element.starts_with('Z') {
            if let Some(rest) = text.strip_prefix('Z') {
                self.offset = Some(0);
                return Some(rest);
            }
        }
        let sign = match text.as_bytes().first()? {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        let (hours, mut rest) = digits(&text[1..], 2, 2)?;
        let mut minutes = 0;
        if element.len() > 3 {
            rest = rest
                .strip_prefix(':')
                .filter(|_| element.contains(':'))
                .unwrap_or(rest);
            (minutes, rest) = digits(rest, 2, 2)?;
        }
        self.offset = Some(sign * (hours * 3600 + minutes * 60));
        Some(rest)
    }

    /// `.123`: `width` digits, or with `optional` up to as many, or none.
    fn fraction<'a>(
        &mut self,
        text: &'a str,
        width: usize,
        optional: bool,
    ) -> Option<&'a str> {
        let Some(after) = text.strip_prefix(['.', ',']) else {
            return optional.then_some(text);
        };
        let count = after.bytes().take_while(u8::is_ascii_digit).count();
        if count == 0 || (!optional && count != width) {
            return optional.then_some(text);
        }
        let mut scale = 100_000_000;
        for digit in after[..count].bytes().take(9) {
            self.nanos += i64::from(digit - b'0') * scale;
            scale /= 10;
        }
        Some(&after[count..])
    }

    fn nanos(&self, zone: Option<&Zone>) -> Option<i64> {
        let year = self.year.unwrap_or_else(|| {
            1970 + now_ns().div_euclid(31_556_952_000_000_000)
        });
        let hour = match self.pm {
            Some(true) if self.hour < 12 => self.hour + 12,
            Some(false) if self.hour == 12 => 0,
            _ => self.hour,
        };
        let days = days_from_civil(year, self.month, self.day);
        let wall = days * 86_400 + hour * 3600 + self.minute * 60 + self.second;
        let named = |z: &Zone| z.named(self.abbreviation.as_deref()?);
        let offset = match (self.offset, &self.abbreviation, zone) {
            (Some(offset), ..) => offset,
            (None, Some(_), Some(zone)) => named(zone).unwrap_or(0),
            (None, None, Some(zone)) => zone.offset_of_local(wall),
            _ => 0,
        };
        Some((wall - offset) * 1_000_000_000 + self.nanos)
    }
}

/// A number of `min` to `max` digits at the start of `text`.
fn digits(text: &str, min: usize, max: usize) -> Option<(i64, &str)> {
    let count = text
        .bytes()
        .take(max)
        .take_while(u8::is_ascii_digit)
        .count();
    if count < min {
        return None;
    }
    Some((text[..count].parse().ok()?, &text[count..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_seconds_into_dates() {
        let at = parse_rfc3339("2024-02-29T23:59:58Z").unwrap() / 1_000_000_000;
        assert_eq!(civil(at), [2024, 2, 29, 23, 59, 58]);
        assert_eq!(civil(0), [1970, 1, 1, 0, 0, 0]);
    }

    #[test]
    fn reads_docker_timestamps() {
        let ns = parse_rfc3339("2026-10-25T17:29:39.083219699Z");
        assert_eq!(ns, Some(1_792_949_379_083_219_699));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        let east = parse_rfc3339("1970-01-01T03:00:00.5+03:00");
        assert_eq!(east, Some(500_000_000));
        assert_eq!(parse_rfc3339("not a time"), None);
    }

    #[test]
    fn reads_durations() {
        let secs = |t| parse_duration(t).map(|d| d.as_secs_f64());
        assert_eq!(secs("1h30m"), Some(5400.0));
        assert_eq!(secs("500ms"), Some(0.5));
        assert_eq!(secs("12h"), Some(43_200.0));
        assert_eq!(secs("1x"), None);
        assert_eq!(secs(""), None);
    }

    #[test]
    fn reads_go_layouts() {
        let rfc = named_layout("RFC3339Nano");
        let ns = parse_layout(rfc, "2026-10-25T17:29:39.083219699Z", None);
        assert_eq!(ns, Some(1_792_949_379_083_219_699));
        let east = parse_layout(rfc, "1970-01-01T03:00:00+03:00", None);
        assert_eq!(east, Some(0));
        let ruby = named_layout("RubyDate");
        let ns = parse_layout(ruby, "Thu Jan 01 01:00:01 +0100 1970", None);
        assert_eq!(ns, Some(1_000_000_000));
        let custom = "02/Jan/2006:15:04:05 -0700";
        let ns = parse_layout(custom, "01/Jan/1970:00:00:02.5 +0000", None);
        assert_eq!(ns, Some(2_500_000_000));
        let midnight = parse_layout("3:04PM", "12:00AM", None);
        assert_eq!(midnight.map(|n| n / 1_000_000_000 % 86_400), Some(0));
        assert_eq!(parse_layout("2006-01-02", "1970-01-0x", None), None);
    }
}
