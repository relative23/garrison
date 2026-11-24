//! Whether the services stay up after they started: one that reports ready
//! and falls over at once would otherwise pass as started and restart
//! forever.

use super::files::{Step, run};
use super::{SYSTEMCTL, states};
use crate::state::State;
use crate::units;

const SETTLE: std::time::Duration = std::time::Duration::from_secs(8);
/// The services that must stay up; the macro milter with them where it runs.
const WATCHED: [&str; 3] = [units::WEB, units::INGEST, units::BROKER];

pub(super) fn settle(milter: bool) -> Step {
    std::thread::sleep(SETTLE);
    let watched = WATCHED.into_iter().chain(milter.then_some(units::MILTER));
    for unit in watched {
        let output = run(
            SYSTEMCTL,
            &["show", "-p", "ActiveState", "-p", "NRestarts", unit],
        )?;
        if let Some(unsettled) = unsettled(unit, &String::from_utf8_lossy(&output.stdout)) {
            return Err(unsettled);
        }
    }
    Ok(())
}

/// The value `systemctl show` gave `key` in `shown`; empty where it gave none.
pub(super) fn property<'a>(shown: &'a str, key: &str) -> &'a str {
    shown
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_default()
}

/// Why `systemctl show -p ActiveState -p NRestarts` describes `unit` as one
/// that did not stay up.
pub(super) fn unsettled(unit: &str, properties: &str) -> Option<State> {
    let value = |key: &str| property(properties, key);
    let seconds = SETTLE.as_secs();
    match (value("ActiveState"), value("NRestarts")) {
        ("active", "0") => None,
        ("active", restarts) => Some(states::restarting(unit, restarts, seconds)),
        (state, _) => Some(states::not_active(unit, state, seconds)),
    }
}

#[cfg(test)]
mod tests {
    use super::{states, unsettled};

    #[test]
    fn a_service_must_stay_active_without_restarts() {
        let web = "garrison-web.service";
        assert_eq!(unsettled(web, "NRestarts=0\nActiveState=active\n"), None);
        assert_eq!(
            unsettled(web, "ActiveState=active\nNRestarts=2\n"),
            Some(states::restarting(web, "2", 8))
        );
        assert_eq!(
            unsettled(web, "ActiveState=activating\nNRestarts=1\n"),
            Some(states::not_active(web, "activating", 8))
        );
        assert_eq!(unsettled(web, ""), Some(states::not_active(web, "", 8)));
    }
}
