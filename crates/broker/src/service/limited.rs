//! Stalwart's own rate limit and its outages, as the broker's journal says
//! them. Where Stalwart answers a check of a user's rights 429, or could not
//! be reached or failed on its side, the broker answers 503; the journal
//! names it at once, and then once a minute at most, with how many more
//! there were, so that a flood of checks does not fill it.

use std::time::Instant;

use crate::quiet::Quiet;

/// When the journal last named Stalwart's rate limit, and what it refused
/// since.
#[derive(Debug, Default)]
pub(super) struct Limited(Quiet);

impl Limited {
    /// The line for a refusal of `whose` budget at `now`, where one is due.
    pub(super) fn refused(&mut self, whose: &str, now: Instant) -> Option<String> {
        let more = self.0.due(whose, "to", now)?;
        Some(format!(
            "Stalwart refused a check of a user's rights for its rate limit (HTTP 429 to \
             {whose}): rights cannot be checked, and users see \"Authorization is temporarily \
             unavailable\", until Stalwart's minute is over{more}"
        ))
    }
}

/// When the journal last named a check that Stalwart did not complete, and
/// which failed since.
#[derive(Debug, Default)]
pub(super) struct Failing(Quiet);

impl Failing {
    /// The line for a check that Stalwart did not complete at `now`, where
    /// one is due; `how` names the request and what met it.
    pub(super) fn failed(&mut self, how: &str, now: Instant) -> Option<String> {
        let more = self.0.due(how, "for", now)?;
        Some(format!(
            "Stalwart did not complete a check of a user's rights ({how}): rights cannot be \
             checked, and users see \"Authorization is temporarily unavailable\", until it \
             answers again{more}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

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

    #[test]
    fn a_check_stalwart_did_not_complete_is_said_at_once_and_then_once_a_minute() {
        let mut failing = Failing::default();
        let start = Instant::now();
        let first = failing
            .failed("UserInfo: Stalwart answered HTTP 503", start)
            .unwrap();
        assert_eq!(
            first,
            "Stalwart did not complete a check of a user's rights (UserInfo: Stalwart answered \
             HTTP 503): rights cannot be checked, and users see \"Authorization is temporarily \
             unavailable\", until it answers again"
        );
        let at = start + Duration::from_secs(30);
        assert_eq!(
            failing.failed("UserInfo: Stalwart is unavailable", at),
            None
        );
        let later = failing
            .failed(
                "UserInfo: Stalwart is unavailable",
                start + Duration::from_secs(60),
            )
            .unwrap();
        assert!(
            later.ends_with(
                "until it answers again; 1 more since the last such line (1 for UserInfo: \
                 Stalwart is unavailable)"
            ),
            "{later}"
        );
    }
}
