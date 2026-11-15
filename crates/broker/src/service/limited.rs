//! Stalwart's own rate limit, as the broker's journal says it. Where Stalwart
//! answers a check of a user's rights 429, the broker answers 503 as when
//! Stalwart is away; the journal names the limit at once, and then once a
//! minute at most, with how many more were refused, so that a flood of
//! checks does not fill it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// At most one line in this long.
const QUIET: Duration = Duration::from_secs(60);

/// When the journal last named the limit, and what was refused since.
#[derive(Debug, Default)]
pub(super) struct Limited {
    said: Option<Instant>,
    /// The refusals since that line, by whose budget they were.
    since: BTreeMap<String, u64>,
}

impl Limited {
    /// The line for a refusal of `whose` budget at `now`, where one is due.
    pub(super) fn refused(&mut self, whose: &str, now: Instant) -> Option<String> {
        if self
            .said
            .is_some_and(|said| now.saturating_duration_since(said) < QUIET)
        {
            *self.since.entry(whose.to_owned()).or_default() += 1;
            return None;
        }
        self.said = Some(now);
        let since = std::mem::take(&mut self.since);
        let more = if since.is_empty() {
            String::new()
        } else {
            let each: Vec<String> = since
                .iter()
                .map(|(whose, count)| format!("{count} to {whose}"))
                .collect();
            format!(
                "; {} more since the last such line ({})",
                since.values().sum::<u64>(),
                each.join(", ")
            )
        };
        Some(format!(
            "Stalwart refused a check of a user's rights for its rate limit (HTTP 429 to \
             {whose}): rights cannot be checked, and users see \"Authorization is temporarily \
             unavailable\", until Stalwart's minute is over{more}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_said_at_once_and_then_once_a_minute_with_a_count() {
        let mut limited = Limited::default();
        let start = Instant::now();
        let first = limited.refused("the broker's key", start).unwrap();
        assert!(
            first.starts_with(
                "Stalwart refused a check of a user's rights for its rate limit (HTTP 429 to \
                 the broker's key)"
            ),
            "{first}"
        );
        assert!(!first.contains("more since"), "{first}");
        for second in 1..60 {
            let at = start + Duration::from_secs(second);
            assert_eq!(limited.refused("the broker's key", at), None);
        }
        let at = start + Duration::from_secs(59);
        assert_eq!(limited.refused("the user's token", at), None);
        let later = limited
            .refused("the broker's key", start + Duration::from_secs(60))
            .unwrap();
        assert!(
            later.ends_with(
                "; 60 more since the last such line (59 to the broker's key, 1 to the user's \
                 token)"
            ),
            "{later}"
        );
        // A quiet minute leaves nothing to count.
        let quiet = limited
            .refused("the user's token", start + Duration::from_secs(200))
            .unwrap();
        assert!(quiet.contains("HTTP 429 to the user's token"), "{quiet}");
        assert!(!quiet.contains("more since"), "{quiet}");
    }
}
