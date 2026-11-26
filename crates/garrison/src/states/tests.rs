//! The states of the commands beside the installer, upgrade and setup, each
//! with its whole line: the one place in their tests where their words stand.

use std::path::Path;

use super::{commands, config, services};
use crate::state::State;

mod access;
mod backup_check;

type Rows = Vec<State>;

fn configuration() -> Rows {
    let settings = Path::new("/etc/garrison/garrison.toml");
    vec![
        config::unloadable(settings, "unknown field `nonsense`"),
        config::not_followed("detect", false, Path::new("/root/garrison.toml")),
        config::switch_missing(Path::new("/opt/garrison/current/static/stalwart-switch.js")),
        config::providers_refused("providers[2]: unknown type `nonsense`"),
        config::unloaded("collector.native_key is credential:my-key, but … loads it as …"),
        config::dqs_refused(
            "providers[1].lists names zen.dq.spamhaus.net",
            "Set collector.dqs_key",
        ),
        config::hidden_check("providers[receipt].path is /home/jobs/nightly.json. Keep it."),
        config::valid(3, 1),
        config::placeholder("public_origin", "https://admin.example.test"),
        config::unfollowed(
            "credentials_directory is /etc/garrison/elsewhere",
            "Remove it",
        ),
        config::dqs_warned(
            "providers[1].lists names ….sbl.dq.spamhaus.net",
            "Move the key",
        ),
        config::hidden_check_warned("providers[receipt].path is /home/jobs/nightly.json."),
        config::policy_refused("garrison-broker may not enter /etc/garrison"),
        config::policy_warned("garrison-broker owns the access policy"),
        config::policy_valid(Path::new("/etc/garrison/access-policy.json")),
    ]
}

fn smaller() -> Rows {
    vec![
        commands::backup_io("ingest", "database disk image is malformed"),
        commands::receipt_unwritten(
            Path::new("/srv/receipt.json"),
            "Permission denied (os error 13)",
        ),
        commands::notify_unloaded("notifications.token is credential:t, but …"),
        commands::notify_not_root(),
        commands::no_channel(),
        commands::notify_sent("ntfy"),
        commands::notify_failed("ntfy", "HTTP 403"),
        commands::unknown_module("backup", &["dashboard", "backups"]),
        commands::modules_io("/etc/garrison/garrison.toml", "unknown field `x`"),
        commands::not_offered(Path::new("/etc/garrison/garrison.toml")),
        commands::modules_unasked(),
        commands::modules_unchanged(),
        commands::modules_held(),
        commands::modules_written(Path::new("/etc/garrison/garrison.toml.previous")),
        commands::modules_unapplied(&["garrison-broker.service", "garrison-web.service"]),
        commands::modules_restarted(),
    ]
}

fn services() -> Rows {
    let database = Path::new("/var/lib/garrison/collector/status.sqlite");
    vec![
        services::stopped("ingest", "Address already in use (os error 98)"),
        services::collect_busy(),
        services::watch_unloaded(
            Path::new("/etc/garrison/garrison.toml"),
            "unknown field `nonsense`",
        ),
        services::watch_not_known(database),
        services::watch_never_ran(),
        services::watch_running(),
        services::watch_stopped(),
        services::watch_told_stopped(),
        services::watch_told_running(),
        services::watch_unfinished("database is locked"),
    ]
}

fn wizard() -> Rows {
    let answers = [
        "https://garrison.example.org".to_owned(),
        "https://mail.example.org".to_owned(),
        "http://127.0.0.1:8080".to_owned(),
        "https://mail.example.org/admin/".to_owned(),
    ];
    vec![
        commands::wizard_io("standard input", "Input/output error (os error 5)"),
        commands::wizard_ended(),
        commands::addresses_unwritable(Path::new("/etc/garrison/garrison.toml"), &answers),
        commands::step_failed("Creating the access policy"),
        commands::stalwart_unconnected(),
        commands::start_failed(&State::new("install-busy", "Another install runs.")),
        commands::wizard_not_root(),
        commands::no_terminal(),
        commands::wizard_not_installed(),
    ]
}

#[test]
fn every_state_of_the_commands_says_its_line() {
    let rows = [
        configuration(),
        smaller(),
        services(),
        wizard(),
        access::rows(),
        access::answers(),
        access::roles(),
        access::locks(),
        access::reasons(),
        backup_check::rows(),
        backup_check::copies(),
    ]
    .concat();
    let sources = [
        include_str!("config.rs"),
        include_str!("commands.rs"),
        include_str!("services.rs"),
        include_str!("access.rs"),
        include_str!("roles.rs"),
        include_str!("backup_check.rs"),
    ];
    crate::state::table(&sources, &rows);
}
