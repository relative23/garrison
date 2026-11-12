//! Timestamps as every component writes and reads them.
//!
//! Stored and transmitted times are ISO 8601 in UTC with a `+00:00` offset and
//! microseconds unless they are zero, so databases and answers compare as text.

use jiff::fmt::temporal::DateTimeParser;

pub use jiff::{SignedDuration, Timestamp};

pub fn now() -> Timestamp {
    Timestamp::now()
}

/// `2026-10-29T12:34:56.123456+00:00`, or without the fraction at whole seconds.
pub fn isoformat(instant: Timestamp) -> String {
    let micros = instant.subsec_microsecond();
    if micros == 0 {
        instant.strftime("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        format!(
            "{}.{micros:06}+00:00",
            instant.strftime("%Y-%m-%dT%H:%M:%S")
        )
    }
}

/// The time as a mail header writes it: `Thu, 29 Oct 2026 12:34:56 +0000`.
pub fn mail_date(instant: Timestamp) -> String {
    instant.strftime("%a, %d %b %Y %H:%M:%S +0000").to_string()
}

/// The current time in the stored format.
pub fn now_isoformat() -> String {
    isoformat(now())
}

/// The instant of seconds since the epoch with a fraction, as a file's
/// modification time is read. Databases store whole seconds
/// (`Timestamp::as_second`).
///
/// Rounds to microseconds, the fraction half to even.
pub fn from_unix(seconds: f64) -> Option<Timestamp> {
    if !seconds.is_finite() {
        return None;
    }
    let whole = seconds.trunc();
    let micros = ((seconds - whole) * 1_000_000.0).round_ties_even();
    // Both parts are integral and far inside i64 for any representable time.
    #[allow(clippy::cast_possible_truncation)]
    let total = (whole as i64)
        .checked_mul(1_000_000)?
        .checked_add(micros as i64)?;
    Timestamp::from_microsecond(total).ok()
}

/// Seconds since the epoch with a fraction, for arithmetic with ages and
/// spans. Databases store whole seconds (`Timestamp::as_second`).
#[allow(clippy::cast_precision_loss)]
pub fn unix(instant: Timestamp) -> f64 {
    instant.as_microsecond() as f64 / 1_000_000.0
}

/// A date and time that carries its own offset (`Z` or `±HH:MM`); a time
/// without one is ambiguous and yields `None`.
pub fn parse(text: &str) -> Option<Timestamp> {
    static PARSER: DateTimeParser = DateTimeParser::new();
    PARSER.parse_timestamp(text.trim_ascii()).ok()
}

/// A moment together with the UTC offset it was written with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    pub instant: Timestamp,
    /// Seconds east of UTC.
    pub offset: i32,
}

/// Like [`parse`], but keeps the written offset (`Z` is `+00:00`).
pub fn parse_written(text: &str) -> Option<Written> {
    static PARSER: DateTimeParser = DateTimeParser::new();
    let instant = parse(text)?;
    let numeric = text.trim_ascii().replace('Z', "+00:00");
    let civil = PARSER.parse_datetime(&numeric).ok()?;
    let local = civil.to_zoned(jiff::tz::TimeZone::UTC).ok()?.timestamp();
    let offset = i32::try_from(local.as_second() - instant.as_second()).ok()?;
    Some(Written { instant, offset })
}

/// ISO 8601 with the written local time and its offset.
pub fn isoformat_written(written: Written) -> String {
    let local = written
        .instant
        .checked_add(SignedDuration::from_secs(i64::from(written.offset)))
        .unwrap_or(written.instant);
    let text = isoformat(local);
    let base = &text[..text.len() - "+00:00".len()];
    let sign = if written.offset < 0 { '-' } else { '+' };
    let seconds = written.offset.unsigned_abs();
    let (hours, minutes, rest) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    if rest == 0 {
        format!("{base}{sign}{hours:02}:{minutes:02}")
    } else {
        format!("{base}{sign}{hours:02}:{minutes:02}:{rest:02}")
    }
}

/// A date and time without an offset, read as UTC (`2026-10-29 12:34:56` or
/// `2026-10-29T12:34:56`), for sources that write UTC without saying so.
pub fn parse_naive_utc(text: &str) -> Option<Timestamp> {
    static PARSER: DateTimeParser = DateTimeParser::new();
    let civil = PARSER.parse_datetime(text.trim_ascii()).ok()?;
    civil
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()
        .map(|zoned| zoned.timestamp())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn now_is_the_system_clock() {
        let system = || {
            let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            i64::try_from(since.as_secs()).unwrap()
        };
        let before = system();
        let (ours, written) = (now().as_second(), parse(&now_isoformat()).unwrap());
        let after = system();
        assert!((before..=after).contains(&ours), "{ours}");
        assert!((before..=after).contains(&written.as_second()), "{written}");
    }

    #[test]
    fn formats_with_offset_and_microseconds() {
        let whole = Timestamp::from_second(1_793_000_000).unwrap();
        assert_eq!(isoformat(whole), "2026-10-26T07:33:20+00:00");
        let fraction = Timestamp::from_microsecond(1_793_000_000_000_042).unwrap();
        assert_eq!(isoformat(fraction), "2026-10-26T07:33:20.000042+00:00");
        assert_eq!(
            isoformat(from_unix(1_793_000_000.5).unwrap()),
            "2026-10-26T07:33:20.500000+00:00"
        );
    }

    #[test]
    fn parses_times_with_an_offset_only() {
        let expected = Timestamp::from_second(1_793_000_000).unwrap();
        for text in [
            "2026-10-26T07:33:20+00:00",
            "2026-10-26T07:33:20Z",
            "2026-10-26 07:33:20+00:00",
            "2026-10-26T09:33:20+02:00",
            "2026-10-26T07:33:20.000+00:00",
        ] {
            assert_eq!(parse(text), Some(expected), "{text}");
        }
        for text in [
            "2026-10-26T07:33:20",
            "2026-10-26",
            "yesterday",
            "",
            "2026-13-01T00:00:00Z",
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    #[test]
    fn naive_times_are_read_as_utc() {
        let expected = Timestamp::from_second(1_793_000_000).unwrap();
        assert_eq!(parse_naive_utc("2026-10-26 07:33:20"), Some(expected));
        assert_eq!(parse_naive_utc("2026-10-26T07:33:20"), Some(expected));
        assert_eq!(parse_naive_utc("26.10.2026"), None);
    }

    #[test]
    fn written_offsets_are_kept() {
        let written = parse_written("2026-10-28T10:00:00.5+02:00").unwrap();
        assert_eq!(written.offset, 7200);
        assert_eq!(
            isoformat_written(written),
            "2026-10-28T10:00:00.500000+02:00"
        );
        let zulu = parse_written("2026-10-28T10:00:00Z").unwrap();
        assert_eq!(isoformat_written(zulu), "2026-10-28T10:00:00+00:00");
        let west = parse_written("2026-10-28 10:00:00-05:30").unwrap();
        assert_eq!(isoformat_written(west), "2026-10-28T10:00:00-05:30");
        assert_eq!(parse_written("2026-10-28T10:00:00"), None);
    }

    #[test]
    fn unix_seconds_round_trip() {
        let instant = from_unix(1_793_000_000.25).unwrap();
        assert!((unix(instant) - 1_793_000_000.25).abs() < 1e-6);
        assert_eq!(from_unix(f64::NAN), None);
    }
}
