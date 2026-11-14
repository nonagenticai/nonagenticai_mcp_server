//! ISO 8601 expiry parsing for licence introspection, without a date-time dependency.
//!
//! The licence authority renders `expires_at` / `token_expires_at` with Python's
//! `datetime.isoformat()`. The reference implementation parses with
//! `datetime.fromisoformat`, requires a timezone (`expiry must be timezone aware`), and treats
//! an explicit `null` as perpetual. This parser covers the same shapes — `T` or space
//! separator, optional seconds and fractional seconds, and `Z` / `±HH`, `±HHMM`, `±HH:MM`
//! offsets — and rejects naive values. Fractional seconds are floored, which can only
//! shorten authority, never extend it.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, floored.
pub(crate) fn unix_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Parse a timezone-aware ISO 8601 timestamp into epoch seconds.
pub(crate) fn parse_iso8601_epoch_seconds(value: &str) -> Option<i64> {
    let mut cursor = Cursor {
        input: value,
        index: 0,
    };
    let year = cursor.number(4)?;
    cursor.expect(b'-')?;
    let month = cursor.number(2)?;
    cursor.expect(b'-')?;
    let day = cursor.number(2)?;
    cursor.expect_one_of(b"T ")?;
    let hour = cursor.number(2)?;
    cursor.expect(b':')?;
    let minute = cursor.number(2)?;
    let second = match cursor.peek() {
        Some(b':') => {
            cursor.index += 1;
            cursor.number(2)?
        }
        _ => 0,
    };
    if let Some(b'.' | b',') = cursor.peek() {
        cursor.index += 1;
        let fraction = cursor.digits()?;
        if fraction.is_empty() {
            return None;
        }
    }
    let offset = match cursor.peek() {
        Some(b'Z' | b'z') => {
            cursor.index += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            cursor.index += 1;
            let hours = cursor.number(2)?;
            let mut minutes = 0;
            let mut seconds = 0;
            if cursor.peek() == Some(b':') {
                cursor.index += 1;
                minutes = cursor.number(2)?;
                if cursor.peek() == Some(b':') {
                    cursor.index += 1;
                    seconds = cursor.number(2)?;
                }
            } else if cursor.peek().is_some_and(|b| b.is_ascii_digit()) {
                minutes = cursor.number(2)?;
                if cursor.peek().is_some_and(|b| b.is_ascii_digit()) {
                    seconds = cursor.number(2)?;
                }
            }
            if hours > 23 || minutes > 59 || seconds > 59 {
                return None;
            }
            let magnitude = hours * 3600 + minutes * 60 + seconds;
            if sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return None,
    };
    if !cursor.rest().is_empty() {
        return None;
    }
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let naive = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(naive - offset)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

struct Cursor<'a> {
    input: &'a str,
    index: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.index).copied()
    }

    fn expect(&mut self, byte: u8) -> Option<()> {
        if self.peek() == Some(byte) {
            self.index += 1;
            Some(())
        } else {
            None
        }
    }

    fn expect_one_of(&mut self, bytes: &[u8]) -> Option<()> {
        match self.peek() {
            Some(found) if bytes.contains(&found) => {
                self.index += 1;
                Some(())
            }
            _ => None,
        }
    }

    fn number(&mut self, digits: usize) -> Option<i64> {
        let end = self.index.checked_add(digits)?;
        let part = self.input.get(self.index..end)?;
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        self.index = end;
        part.parse().ok()
    }

    /// Consume every remaining ASCII digit, returning what was consumed.
    fn digits(&mut self) -> Option<&str> {
        let start = self.index;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.index += 1;
        }
        self.input.get(start..self.index)
    }

    fn rest(&self) -> &str {
        &self.input[self.index..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shapes_datetime_fromisoformat_accepts() {
        assert_eq!(parse_iso8601_epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso8601_epoch_seconds("1970-01-01T00:00:00.123456+00:00"),
            Some(0)
        );
        assert_eq!(
            parse_iso8601_epoch_seconds("1969-12-31T23:59:59Z"),
            Some(-1)
        );
        // Same instant, three offset spellings.
        let utc = parse_iso8601_epoch_seconds("2026-11-14T08:00:00Z").unwrap();
        assert_eq!(
            parse_iso8601_epoch_seconds("2026-11-14T10:00:00+02:00"),
            Some(utc)
        );
        assert_eq!(
            parse_iso8601_epoch_seconds("2026-11-14T10:00:00+0200"),
            Some(utc)
        );
        assert_eq!(
            parse_iso8601_epoch_seconds("2026-11-14T10:00:00+02"),
            Some(utc)
        );
        assert_eq!(
            parse_iso8601_epoch_seconds("2026-11-14 08:00:00Z"),
            Some(utc)
        );
        assert!(parse_iso8601_epoch_seconds("2024-02-29T12:00:00Z").is_some());
    }

    #[test]
    fn rejects_naive_or_malformed_values() {
        assert_eq!(parse_iso8601_epoch_seconds("2026-11-14T08:00:00"), None);
        assert_eq!(parse_iso8601_epoch_seconds("2026-11-14"), None);
        assert_eq!(parse_iso8601_epoch_seconds("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_iso8601_epoch_seconds("2026-02-29T00:00:00Z"), None);
        assert_eq!(parse_iso8601_epoch_seconds("2026-11-14T24:00:00Z"), None);
        assert_eq!(
            parse_iso8601_epoch_seconds("2026-11-14T08:00:00+24:00"),
            None
        );
        assert_eq!(
            parse_iso8601_epoch_seconds("2026-11-14T08:00:00Zjunk"),
            None
        );
        assert_eq!(parse_iso8601_epoch_seconds(""), None);
    }
}
