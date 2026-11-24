//! Whether the services stay up after they started: one that reports ready
//! and falls over at once would otherwise pass as started and restart
//! forever.

use super::SYSTEMCTL;
use super::files::{Step, run};
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
        if let Some(reason) = unsettled(&String::from_utf8_lossy(&output.stdout)) {
            return Err(format!(
                "{unit} {reason} within {} s of starting",
                SETTLE.as_secs()
            ));
        }
    }
    Ok(())
}

/// Why `systemctl show -p ActiveState -p NRestarts` describes a unit that did not stay up.
pub(super) fn unsettled(properties: &str) -> Option<String> {
    let value = |key: &str| {
        properties
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_default()
    };
    match (value("ActiveState"), value("NRestarts")) {
        ("active", "0") => None,
        ("active", restarts) => Some(format!("restarted {restarts} times")),
        (state, _) => Some(format!(
            "is {}",
            if state.is_empty() { "unknown" } else { state }
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::unsettled;

    #[test]
    fn a_service_must_stay_active_without_restarts() {
        assert_eq!(unsettled("NRestarts=0\nActiveState=active\n"), None);
        assert_eq!(
            unsettled("ActiveState=active\nNRestarts=2\n").unwrap(),
            "restarted 2 times"
        );
        assert_eq!(
            unsettled("ActiveState=activating\nNRestarts=1\n").unwrap(),
            "is activating"
        );
        assert_eq!(unsettled("").unwrap(), "is unknown");
    }
}
