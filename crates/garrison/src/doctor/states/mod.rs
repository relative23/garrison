//! Every state `garrison doctor` reports, its one constructor each, by the
//! check it belongs to: a line's words and what mends it stand here and
//! nowhere else. A check picks the state and its level.

pub(super) mod files;
pub(super) mod host;
pub(super) mod keys;
pub(super) mod milter;
pub(super) mod notify;
pub(super) mod policy;
pub(super) mod public;
pub(super) mod selinux;

use std::fmt::Display;

use crate::loaded::Unloaded;
use crate::state::State;
use crate::unfollowed::Unfollowed;

/// `1 problem`, `2 problems`.
fn counted(number: usize, one: &str, more: &str) -> String {
    format!("{number} {}", if number == 1 { one } else { more })
}

/// Why a question to Stalwart at `url` got no answer.
fn no_answer(url: &str, why: impl Display) -> String {
    format!("Stalwart did not answer at {url} ({why})")
}

pub(super) fn not_root() -> State {
    let text = "Run as root: the checks read files only root may read.";
    State::new("doctor-not-root", text)
}

pub(super) fn in_order(checks: usize) -> State {
    let text = if checks == 1 {
        "The 1 check is in order.".to_owned()
    } else {
        format!("All {} are in order.", counted(checks, "check", "checks"))
    };
    State::new("doctor-summary-in-order", text)
}

pub(super) fn no_problem(warned: usize, unknown: usize, checks: usize) -> State {
    let text = tally(0, warned, unknown, checks);
    State::new("doctor-summary-no-problem", text)
}

pub(super) fn problems(failed: usize, warned: usize, unknown: usize, checks: usize) -> State {
    let text = tally(failed, warned, unknown, checks);
    State::new("doctor-summary-problems", text)
}

/// `1 problem, 2 warnings, 0 unknown, of 30 checks.`
fn tally(failed: usize, warned: usize, unknown: usize, checks: usize) -> String {
    format!(
        "{}, {}, {unknown} unknown, of {}.",
        counted(failed, "problem", "problems"),
        counted(warned, "warning", "warnings"),
        counted(checks, "check", "checks")
    )
}

pub(super) fn placeholder(key: &str, origin: &str) -> State {
    let text = format!("{key} is still the placeholder {origin}");
    State::new("doctor-origin-placeholder", text)
        .with_fix("Set the real address in /etc/garrison/garrison.toml.")
}

/// In check-config's words.
pub(super) fn unfollowed(setting: Unfollowed) -> State {
    State::new("doctor-setting-unfollowed", setting.what).with_fix(setting.fix)
}

/// In check-config's words.
pub(super) fn unloaded(secret: Unloaded) -> State {
    State::new("doctor-secret-unloaded", secret.what).with_fix(secret.fix)
}

/// A list of Spamhaus' Data Query Service written without its key that
/// nothing could ask, in check-config's words.
pub(super) fn dqs_unasked((what, fix): (String, String)) -> State {
    State::new("doctor-dqs-list-unasked", what).with_fix(fix)
}

/// A list that holds its key in garrison.toml, in check-config's words.
pub(super) fn dqs_key_written((what, fix): (String, String)) -> State {
    State::new("doctor-dqs-key-in-config", what).with_fix(fix)
}

#[cfg(test)]
fn rows() -> Vec<(State, &'static str)> {
    let said = |what: &str, fix: &str| (what.to_owned(), fix.to_owned());
    vec![
        (
            not_root(),
            "Run as root: the checks read files only root may read. [doctor-not-root]",
        ),
        (
            in_order(30),
            "All 30 checks are in order. [doctor-summary-in-order]",
        ),
        (
            no_problem(1, 1, 30),
            "0 problems, 1 warning, 1 unknown, of 30 checks. [doctor-summary-no-problem]",
        ),
        (
            problems(2, 0, 0, 30),
            "2 problems, 0 warnings, 0 unknown, of 30 checks. [doctor-summary-problems]",
        ),
        (
            placeholder("issuer", "https://mail.example.org"),
            "issuer is still the placeholder https://mail.example.org [doctor-origin-placeholder]\n      \
             Set the real address in /etc/garrison/garrison.toml.",
        ),
        (
            unfollowed(Unfollowed {
                what: "broker.socket is /run/broker.sock, but garrison-broker.socket listens on \
                       /run/garrison/broker.sock"
                    .into(),
                fix: "Remove the setting.".into(),
            }),
            "broker.socket is /run/broker.sock, but garrison-broker.socket listens on \
             /run/garrison/broker.sock [doctor-setting-unfollowed]\n      Remove the setting.",
        ),
        (
            unloaded(Unloaded {
                setting: "broker.native_key",
                what: "broker.native_key is credential:key, but garrison-broker.service loads \
                       this secret only as credential:broker-native-key"
                    .into(),
                fix: "Write broker.native_key = \"credential:broker-native-key\".".into(),
            }),
            "broker.native_key is credential:key, but garrison-broker.service loads this secret \
             only as credential:broker-native-key [doctor-secret-unloaded]\n      Write \
             broker.native_key = \"credential:broker-native-key\".",
        ),
        (
            dqs_unasked(said(
                "providers[1].lists names zen.dq.spamhaus.net",
                "Set collector.dqs_key.",
            )),
            "providers[1].lists names zen.dq.spamhaus.net [doctor-dqs-list-unasked]\n      \
             Set collector.dqs_key.",
        ),
        (
            dqs_key_written(said(
                "providers[1].lists names ….sbl.dq.spamhaus.net with the key",
                "Write the zone without the key.",
            )),
            "providers[1].lists names ….sbl.dq.spamhaus.net with the key \
             [doctor-dqs-key-in-config]\n      Write the zone without the key.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every state of doctor's, with its whole line as an example.
    fn every() -> Vec<(State, &'static str)> {
        [
            rows(),
            host::rows(),
            files::rows(),
            keys::rows(),
            milter::rows(),
            notify::rows(),
            policy::rows(),
            public::rows(),
            selinux::rows(),
        ]
        .concat()
    }

    /// Every state of doctor's, once, with its whole line: the one place in
    /// doctor's tests where a sentence stands.
    #[test]
    fn every_state_of_doctor_says_its_line() {
        let rows = every();
        crate::state::table(
            &[
                include_str!("mod.rs"),
                include_str!("host.rs"),
                include_str!("files.rs"),
                include_str!("keys.rs"),
                include_str!("milter.rs"),
                include_str!("notify.rs"),
                include_str!("policy.rs"),
                include_str!("public.rs"),
                include_str!("selinux.rs"),
            ],
            &rows,
        );
        // What a state says for other data, where the tests before it held
        // those words: its line is the table's too.
        let entry = |defer: bool| -> crate::doctor::milter::Entry {
            serde_json::from_value(serde_json::json!({"id": "m", "host": "127.0.0.1",
                "port": 8096, "tempFailOnError": defer}))
            .unwrap()
        };
        for (state, line) in [
            (
                in_order(1),
                "The 1 check is in order. [doctor-summary-in-order]",
            ),
            (
                host::collection_recent(-120),
                "the last collection run finished 0 minutes ago [doctor-collection-recent]",
            ),
            (
                milter::stranded(&entry(true)),
                "Stalwart asks a milter at 127.0.0.1:8096 (entry m), where nothing answers: \
                 Stalwart defers all incoming mail [doctor-milter-stranded]\n      Start the \
                 milter that is to answer there. If nothing is to answer there, remove that entry \
                 in the Stalwart WebUI (Settings ▸ MTA ▸ Milters) and reload its settings.",
            ),
        ] {
            assert_eq!(state.to_string(), line);
        }
    }

    /// Each state an acceptance script looks for in doctor's output, by its
    /// name in brackets, is one doctor has: a script cannot tell a name
    /// doctor no longer says from a fault.
    #[test]
    fn every_name_the_scripts_look_for_is_a_state_of_doctors() {
        let rows = every();
        let known: Vec<&str> = rows.iter().map(|(state, _)| state.name).collect();
        let mut looked_for = 0;
        for script in [
            include_str!("../../../../../scripts/acceptance-quickstart.sh"),
            include_str!("../../../../../scripts/acceptance-host.sh"),
            include_str!("../../../../../scripts/soak.sh"),
            include_str!("../../../../../scripts/acceptance.sh"),
            include_str!("../../../../../scripts/acceptance-failures-config.sh"),
            include_str!("../../../../../scripts/acceptance-failures-commands.sh"),
        ] {
            for rest in script.split("[doctor-").skip(1) {
                let name = format!("doctor-{}", rest.split(']').next().unwrap_or_default());
                assert!(
                    known.contains(&name.as_str()),
                    "{name} is no state of doctor's"
                );
                looked_for += 1;
            }
        }
        assert!(looked_for >= 17, "{looked_for}");
    }
}
