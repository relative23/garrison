//! The firewall check where systemctl does not say what it is asked.

use super::*;

/// A systemctl that runs but cannot reach systemd, as while the system bus
/// restarts ("Failed to connect to bus", on its error output), writes no
/// state, or fewer than it was asked for: that is no answer, and the card
/// is Unknown, never a firewall that does not run.
#[test]
fn a_systemctl_without_a_state_for_every_unit_leaves_the_firewall_unknown() {
    let root = tempfile::tempdir().unwrap();
    let provider = provider(root.path(), "\"firewall\"");
    for (code, stdout) in [(1, ""), (3, "inactive\ninactive\n")] {
        let runner = Programs::new(vec![("systemctl is-active", code, stdout)]);
        let card = checked(&provider, &runner, &Remembered::default(), 0);
        assert_eq!(
            (card.state, card.findings),
            (
                State::Unknown,
                vec!["systemctl gave no state for every firewall unit.".to_owned()]
            ),
            "{stdout:?}"
        );
    }
}
