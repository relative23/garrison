//! Lines the journal gets at once and then at most once a minute, with how
//! many more there were since, so that a flood does not fill it: what the
//! broker says of Stalwart's rate limit and outage, and what the web
//! service's client says of a broker that does not answer.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// At most one line of a kind in this long.
const QUIET: Duration = Duration::from_secs(60);

/// When the journal last got a line of one kind, and what came since, by
/// what each was.
#[derive(Debug, Default)]
pub(crate) struct Quiet {
    said: Option<Instant>,
    since: BTreeMap<String, u64>,
}

impl Quiet {
    pub(crate) const fn new() -> Self {
        Quiet {
            said: None,
            since: BTreeMap::new(),
        }
    }

    /// Whether a line for `what` is due at `now`: then the end of that line,
    /// which says how many more came since the last one, each by what it
    /// was after `word`; `None` while the minute is not over, which counts
    /// this one.
    pub(crate) fn due(&mut self, what: &str, word: &str, now: Instant) -> Option<String> {
        if self
            .said
            .is_some_and(|said| now.saturating_duration_since(said) < QUIET)
        {
            *self.since.entry(what.to_owned()).or_default() += 1;
            return None;
        }
        self.said = Some(now);
        let since = std::mem::take(&mut self.since);
        if since.is_empty() {
            return Some(String::new());
        }
        let each: Vec<String> = since
            .iter()
            .map(|(what, count)| format!("{count} {word} {what}"))
            .collect();
        Some(format!(
            "; {} more since the last such line ({})",
            since.values().sum::<u64>(),
            each.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_due_at_once_and_then_once_a_minute_with_what_came_since() {
        let mut quiet = Quiet::default();
        let start = Instant::now();
        assert_eq!(quiet.due("a", "for", start), Some(String::new()));
        for second in 1..60 {
            let at = start + Duration::from_secs(second);
            assert_eq!(quiet.due("a", "for", at), None);
        }
        assert_eq!(quiet.due("b", "for", start + Duration::from_secs(59)), None);
        assert_eq!(
            quiet.due("a", "for", start + QUIET).as_deref(),
            Some("; 60 more since the last such line (59 for a, 1 for b)")
        );
        // A quiet minute leaves nothing to count.
        let later = start + QUIET * 3;
        assert_eq!(quiet.due("b", "for", later), Some(String::new()));
        // A clock that has not moved on counts as within the minute.
        assert_eq!(quiet.due("b", "for", later), None);
    }
}
