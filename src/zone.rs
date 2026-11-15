//! Time zones from the host's tz database (`/usr/share/zoneinfo`, TZif),
//! for stage.timestamp's `location`: a zone's offsets by transition,
//! and after the last one the POSIX TZ rule of the file's footer, as
//! slim files (zic's default) keep only that for daylight saving time.

use crate::host;
use crate::time::days_from_civil;

pub struct Zone {
    transitions: Vec<(i64, usize)>,
    /// Each local time type: offset east of UTC in seconds, abbreviation.
    types: Vec<(i64, String)>,
    rule: Option<Rule>,
}

/// `CET-1CEST,M3.5.0,M10.5.0/3`: standard and daylight time.
struct Rule {
    std: (i64, String),
    dst: Option<Daylight>,
}

/// Daylight time's offset and abbreviation, and when it starts and ends
/// (the day, the local time of day in seconds).
struct Daylight {
    offset: (i64, String),
    start: (Day, i64),
    end: (Day, i64),
}

/// When daylight time starts or ends: `Jn`, `n` or `Mm.w.d`.
enum Day {
    Julian(i64),
    Zero(i64),
    Month(i64, i64, i64),
}

impl Zone {
    /// `name` from the host's tz database; UTC for "UTC" or "".
    pub fn load(name: &str) -> Result<Zone, String> {
        if ["", "UTC", "Etc/UTC"].contains(&name) {
            return Ok(Zone::utc());
        }
        if name.contains("..") || name.starts_with('/') {
            return Err(format!("location `{name}`"));
        }
        let path = format!("/usr/share/zoneinfo/{name}");
        let data = std::fs::read(host::path(&path))
            .map_err(|e| format!("location `{name}`: {path}: {e}"))?;
        Zone::parse(&data).ok_or(format!("location `{name}`: not TZif"))
    }

    fn utc() -> Zone {
        Zone {
            transitions: Vec::new(),
            types: vec![(0, "UTC".into())],
            rule: None,
        }
    }

    fn parse(data: &[u8]) -> Option<Zone> {
        let (version, mut counts) = header(data)?;
        let (mut rest, mut size) = (&data[44..], 4);
        if version >= b'2' {
            rest = rest.get(block_len(&counts, 4)..)?;
            let (_, wide) = header(rest)?;
            (counts, size, rest) = (wide, 8, &rest[44..]);
        }
        let [_, _, _, times, types, chars] = counts;
        let footer = rest.get(block_len(&counts, size)..);
        let (at, rest) = rest.split_at_checked(times * size)?;
        let (index, rest) = rest.split_at_checked(times)?;
        let (infos, rest) = rest.split_at_checked(types * 6)?;
        let names = rest.get(..chars)?;
        let int = |b: &[u8]| -> i64 {
            b.iter()
                .fold(if b[0] & 0x80 != 0 { -1 } else { 0 }, |n, &x| {
                    (n << 8) | i64::from(x)
                })
        };
        let types: Vec<(i64, String)> = infos
            .chunks(6)
            .map(|t| (int(&t[..4]), abbreviation(names, t[5] as usize)))
            .collect();
        let transitions = at
            .chunks(size)
            .zip(index)
            .map(|(t, &i)| (int(t), i as usize))
            .filter(|(_, i)| *i < types.len())
            .collect();
        let footer = footer.and_then(|f| std::str::from_utf8(f).ok());
        let rule = footer.and_then(|f| Rule::parse(f.trim_matches('\n')));
        Some(Zone {
            transitions,
            types,
            rule,
        })
        .filter(|z| !z.types.is_empty())
    }

    /// The offset east of UTC at `utc`, seconds since the epoch.
    pub fn offset_at(&self, utc: i64) -> i64 {
        let after = self.transitions.partition_point(|(t, _)| *t <= utc);
        if after == self.transitions.len() {
            if let Some(rule) = &self.rule {
                return rule.offset_at(utc);
            }
        }
        match after.checked_sub(1) {
            Some(i) => self.types[self.transitions[i].1].0,
            None => self.types[0].0,
        }
    }

    /// The offset of a local time, `wall` seconds as if it were UTC.
    pub fn offset_of_local(&self, wall: i64) -> i64 {
        let guess = self.offset_at(wall);
        let second = self.offset_at(wall - guess);
        if second == guess { guess } else { second }
    }

    /// The offset of an abbreviation this zone uses, as Go's
    /// ParseInLocation reads `MST`.
    pub fn named(&self, abbreviation: &str) -> Option<i64> {
        let rule = self.rule.iter().flat_map(|r| {
            std::iter::once(&r.std).chain(r.dst.as_ref().map(|d| &d.offset))
        });
        let mut all = self.types.iter().chain(rule);
        all.find(|(_, name)| name == abbreviation).map(|(o, _)| *o)
    }
}

/// TZif's version byte and its six counts.
fn header(data: &[u8]) -> Option<(u8, [usize; 6])> {
    if data.get(..4)? != b"TZif" {
        return None;
    }
    let mut counts = [0; 6];
    for (i, count) in counts.iter_mut().enumerate() {
        let at = 20 + 4 * i;
        let bytes: [u8; 4] = data.get(at..at + 4)?.try_into().ok()?;
        *count = u32::from_be_bytes(bytes) as usize;
    }
    Some((data[4], counts))
}

/// The data block's length after its header, times `size` bytes wide.
fn block_len(counts: &[usize; 6], size: usize) -> usize {
    let [ut, std, leaps, times, types, chars] = *counts;
    times * size + times + types * 6 + chars + leaps * (size + 4) + std + ut
}

fn abbreviation(names: &[u8], at: usize) -> String {
    let name = names.get(at..).unwrap_or_default();
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).into_owned()
}

impl Rule {
    fn parse(text: &str) -> Option<Rule> {
        let (std_name, rest) = name(text)?;
        let (std, rest) = offset(rest)?;
        let std = (-std, std_name);
        if rest.is_empty() {
            return Some(Rule { std, dst: None });
        }
        let (dst_name, rest) = name(rest)?;
        let (dst, rest) = match rest.strip_prefix(',') {
            Some(_) => (std.0 + 3600, rest),
            None => offset(rest).map(|(o, r)| (-o, r))?,
        };
        let mut parts = rest.strip_prefix(',')?.split(',');
        let dst = Daylight {
            offset: (dst, dst_name),
            start: change(parts.next()?)?,
            end: change(parts.next()?)?,
        };
        Some(Rule {
            std,
            dst: Some(dst),
        })
    }

    fn offset_at(&self, utc: i64) -> i64 {
        let Some(daylight) = &self.dst else {
            return self.std.0;
        };
        let dst = daylight.offset.0;
        let ((start, start_at), (end, end_at)) =
            (&daylight.start, &daylight.end);
        let year = crate::time::year_of(utc + self.std.0);
        let begins = start.day(year) * 86_400 + start_at - self.std.0;
        let ends = end.day(year) * 86_400 + end_at - dst;
        let summer = if begins < ends {
            begins <= utc && utc < ends
        } else {
            !(ends <= utc && utc < begins)
        };
        if summer { dst } else { self.std.0 }
    }
}

/// A zone name: letters, or anything between `<` and `>`.
fn name(text: &str) -> Option<(String, &str)> {
    if let Some(quoted) = text.strip_prefix('<') {
        let (name, rest) = quoted.split_once('>')?;
        return Some((name.to_owned(), rest));
    }
    let len = text.bytes().take_while(u8::is_ascii_alphabetic).count();
    (len >= 3).then(|| (text[..len].to_owned(), &text[len..]))
}

/// `[+-]hh[:mm[:ss]]` as seconds; POSIX counts west as positive.
fn offset(text: &str) -> Option<(i64, &str)> {
    let (sign, text) = match text.as_bytes().first()? {
        b'-' => (-1, &text[1..]),
        b'+' => (1, &text[1..]),
        _ => (1, text),
    };
    let len = text
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b':')
        .count();
    let mut seconds = 0;
    for (i, part) in text[..len].split(':').enumerate().take(3) {
        seconds += part.parse::<i64>().ok()? * [3600, 60, 1][i];
    }
    Some((sign * seconds, &text[len..]))
}

/// `M3.5.0/3`: the day and the local time of day, 02:00 by default.
fn change(text: &str) -> Option<(Day, i64)> {
    let (day, at) = match text.split_once('/') {
        Some((day, at)) => (day, offset(at)?.0),
        None => (text, 7200),
    };
    let day = if let Some(julian) = day.strip_prefix('J') {
        Day::Julian(julian.parse().ok()?)
    } else if let Some(m) = day.strip_prefix('M') {
        let mut n = m.split('.').map(|p| p.parse::<i64>().ok());
        Day::Month(n.next()??, n.next()??, n.next()??)
    } else {
        Day::Zero(day.parse().ok()?)
    };
    Some((day, at))
}

impl Day {
    /// The day in `year`, as days since the epoch.
    fn day(&self, year: i64) -> i64 {
        let jan1 = days_from_civil(year, 1, 1);
        let leap = days_from_civil(year + 1, 1, 1) - jan1 == 366;
        match *self {
            Day::Julian(n) => jan1 + n - 1 + i64::from(leap && n >= 60),
            Day::Zero(n) => jan1 + n,
            Day::Month(month, week, weekday) => {
                let first = days_from_civil(year, month, 1);
                let next = match month {
                    12 => days_from_civil(year + 1, 1, 1),
                    _ => days_from_civil(year, month + 1, 1),
                };
                // 1970-01-01 was a Thursday, weekday 4.
                let first_weekday = (first + 4).rem_euclid(7);
                let mut day = first + (weekday - first_weekday).rem_euclid(7);
                day += (week - 1) * 7;
                while day >= next {
                    day -= 7;
                }
                day
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JULY: i64 = 1_782_907_200; // 2026-07-01 12:00 UTC
    const JANUARY: i64 = 1_768_478_400; // 2026-01-15 12:00 UTC

    #[test]
    fn reads_posix_rules() {
        let zone = Zone {
            transitions: Vec::new(),
            types: vec![(3600, "CET".into())],
            rule: Rule::parse("CET-1CEST,M3.5.0,M10.5.0/3"),
        };
        assert_eq!(zone.offset_at(JULY), 7200);
        assert_eq!(zone.offset_at(JANUARY), 3600);
        assert_eq!(zone.named("CEST"), Some(7200));
        // 2026-03-29 01:00 UTC: daylight time starts at 02:00 CET.
        assert_eq!(zone.offset_at(1_774_746_000 - 1), 3600);
        assert_eq!(zone.offset_at(1_774_746_000), 7200);
        let south = Rule::parse("<-03>3").unwrap();
        assert_eq!(south.offset_at(JULY), -3 * 3600);
    }

    #[test]
    fn reads_the_hosts_database() {
        let Ok(zone) = Zone::load("Europe/Berlin") else {
            return;
        };
        assert_eq!(zone.offset_at(JULY), 7200);
        assert_eq!(zone.offset_at(JANUARY), 3600);
        // 1970 had no daylight time in Germany.
        assert_eq!(zone.offset_at(180 * 86_400), 3600);
        assert!(Zone::load("../etc/passwd").is_err());
        let read = |layout, text| {
            crate::time::parse_layout(layout, text, Some(&zone)).unwrap()
        };
        let local = read("2006-01-02 15:04", "2026-07-01 14:00");
        assert_eq!(local, JULY * 1_000_000_000);
        let named = read("2006-01-02 15:04 MST", "2026-01-15 13:00 CET");
        assert_eq!(named, JANUARY * 1_000_000_000);
    }
}
