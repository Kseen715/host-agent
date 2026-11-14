//! Wall-clock time as Prometheus and Loki take it, and Docker's
//! RFC 3339 timestamps read without a date library.

use std::time::{SystemTime, UNIX_EPOCH};

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
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_docker_timestamps() {
        let ns = parse_rfc3339("2026-10-25T17:29:39.083219699Z");
        assert_eq!(ns, Some(1_792_949_379_083_219_699));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        let east = parse_rfc3339("1970-01-01T03:00:00.5+03:00");
        assert_eq!(east, Some(500_000_000));
        assert_eq!(parse_rfc3339("not a time"), None);
    }
}
