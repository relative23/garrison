//! The states of the commands beside the installer, upgrade and setup, each
//! with its whole line: the one place in their tests where their words stand.

use std::path::Path;

use super::{commands, config, services};
use crate::state::State;

mod access;
mod backup_check;

type Rows = Vec<(State, &'static str)>;

fn configuration() -> Rows {
    let settings = Path::new("/etc/garrison/garrison.toml");
    vec![
        (
            config::unloadable(settings, "unknown field `nonsense`"),
            "Cannot load /etc/garrison/garrison.toml: unknown field `nonsense` [config-unloadable]",
        ),
        (
            config::not_followed("detect", false, Path::new("/root/garrison.toml")),
            "garrison detect reads no configuration, so it takes no --config \
             (/root/garrison.toml). [config-not-followed]",
        ),
        (
            config::switch_missing(Path::new("/opt/garrison/current/static/stalwart-switch.js")),
            "/opt/garrison/current/static/stalwart-switch.js is missing; build the interface \
             first. [switch-script-missing]",
        ),
        (
            config::providers_refused("providers[2]: unknown type `nonsense`"),
            "Configuration not usable: providers[2]: unknown type `nonsense` \
             [check-config-providers]",
        ),
        (
            config::unloaded("collector.native_key is credential:my-key, but … loads it as …"),
            "Configuration not usable: collector.native_key is credential:my-key, but … loads it \
             as … [check-config-unloaded]",
        ),
        (
            config::dqs_refused(
                "providers[1].lists names zen.dq.spamhaus.net",
                "Set collector.dqs_key",
            ),
            "Configuration not usable: providers[1].lists names zen.dq.spamhaus.net. Set \
             collector.dqs_key [check-config-dqs-refused]",
        ),
        (
            config::hidden_check("providers[receipt].path is /home/jobs/nightly.json. Keep it."),
            "Configuration not usable: providers[receipt].path is /home/jobs/nightly.json. Keep \
             it. [check-config-hidden-check]",
        ),
        (
            config::valid(3, 1),
            "Configuration valid: 3 providers, 1 actions. [check-config-valid]",
        ),
        (
            config::placeholder("public_origin", "https://admin.example.test"),
            "Warning: deployment.public_origin https://admin.example.test is a placeholder; set \
             the real name. [check-config-placeholder]",
        ),
        (
            config::unfollowed(
                "credentials_directory is /etc/garrison/elsewhere",
                "Remove it",
            ),
            "Warning: credentials_directory is /etc/garrison/elsewhere. Remove it \
             [check-config-unfollowed]",
        ),
        (
            config::dqs_warned(
                "providers[1].lists names ….sbl.dq.spamhaus.net",
                "Move the key",
            ),
            "Warning: providers[1].lists names ….sbl.dq.spamhaus.net. Move the key \
             [check-config-dqs-warned]",
        ),
        (
            config::hidden_check_warned("providers[receipt].path is /home/jobs/nightly.json."),
            "Warning: providers[receipt].path is /home/jobs/nightly.json. \
             [check-config-hidden-check-warned]",
        ),
        (
            config::policy_refused("garrison-broker may not enter /etc/garrison"),
            "Access policy not usable: garrison-broker may not enter /etc/garrison \
             [check-config-policy-refused]",
        ),
        (
            config::policy_warned("garrison-broker owns the access policy"),
            "Warning: garrison-broker owns the access policy [check-config-policy-warned]",
        ),
        (
            config::policy_valid(Path::new("/etc/garrison/access-policy.json")),
            "Access policy valid: /etc/garrison/access-policy.json [check-config-policy-valid]",
        ),
    ]
}

fn smaller() -> Rows {
    vec![
        (
            commands::backup_io("ingest", "database disk image is malformed"),
            "ingest: database disk image is malformed [backup-io]",
        ),
        (
            commands::receipt_unwritten(
                Path::new("/srv/receipt.json"),
                "Permission denied (os error 13)",
            ),
            "Cannot write /srv/receipt.json: Permission denied (os error 13) \
             [self-check-receipt-unwritten]",
        ),
        (
            commands::notify_unloaded("notifications.token is credential:t, but …"),
            "Not tested: notifications.token is credential:t, but … [notify-test-unloaded]",
        ),
        (
            commands::notify_not_root(),
            "Run as root: the channels' secrets are files only root may read. \
             [notify-test-not-root]",
        ),
        (
            commands::no_channel(),
            "No channel is configured: set ntfy_url, webhook_url or the mail settings under \
             [notifications] in garrison.toml. [notify-test-no-channel]",
        ),
        (
            commands::notify_sent("ntfy"),
            "ntfy: the test message is out. [notify-test-sent]",
        ),
        (
            commands::notify_failed("ntfy", "HTTP 403"),
            "ntfy: the test message did not go out: HTTP 403. Check its address and its secret in \
             /etc/garrison/credentials. [notify-test-failed]",
        ),
        (
            commands::unknown_module("backup", &["dashboard", "backups"]),
            "backup is not a module ID; known: dashboard, backups [modules-unknown]",
        ),
        (
            commands::modules_io("/etc/garrison/garrison.toml", "unknown field `x`"),
            "/etc/garrison/garrison.toml: unknown field `x` [modules-io]",
        ),
        (
            commands::not_offered(Path::new("/etc/garrison/garrison.toml")),
            "/etc/garrison/garrison.toml: the edited file does not offer the chosen modules \
             [modules-not-offered]",
        ),
        (
            commands::modules_unasked(),
            "garrison modules asks before it writes, and no terminal is here to answer: add --yes \
             to write it. [modules-unasked]",
        ),
        (
            commands::modules_unchanged(),
            "Nothing was changed. [modules-unchanged]",
        ),
        (
            commands::modules_held(),
            "The configuration offers these modules already; nothing was changed. [modules-held]",
        ),
        (
            commands::modules_written(Path::new("/etc/garrison/garrison.toml.previous")),
            "Written; the previous file is /etc/garrison/garrison.toml.previous. \
             [modules-written]",
        ),
        (
            commands::modules_unapplied(&["garrison-broker.service", "garrison-web.service"]),
            "Restart garrison-broker.service and garrison-web.service to apply it. \
             [modules-unapplied]",
        ),
        (
            commands::modules_restarted(),
            "The broker and the web service were restarted where they ran. [modules-restarted]",
        ),
    ]
}

fn services() -> Rows {
    let database = Path::new("/var/lib/garrison/collector/status.sqlite");
    vec![
        (
            services::stopped("ingest", "Address already in use (os error 98)"),
            "The ingest service stopped: Address already in use (os error 98) [service-stopped]",
        ),
        (
            services::collect_busy(),
            "Another collection run is under way; this one ends without collecting \
             [collect-busy]",
        ),
        (
            services::watch_unloaded(
                Path::new("/etc/garrison/garrison.toml"),
                "unknown field `nonsense`",
            ),
            "/etc/garrison/garrison.toml does not load (unknown field `nonsense`); watching with \
             what the last collection run left [watch-unloaded]",
        ),
        (
            services::watch_not_known(database),
            "Whether the collector runs is not known: the newest snapshot in \
             /var/lib/garrison/collector/status.sqlite is dated at a time that is none \
             [watch-not-known]",
        ),
        (
            services::watch_never_ran(),
            "No collection run has finished yet [watch-never-ran]",
        ),
        (
            services::watch_running(),
            "The collector runs [watch-running]",
        ),
        (
            services::watch_stopped(),
            "The collector has stopped [watch-stopped]",
        ),
        (
            services::watch_told_stopped(),
            "The collector has stopped; the channels were told [watch-told-stopped]",
        ),
        (
            services::watch_told_running(),
            "The collector runs again; the channels were told [watch-told-running]",
        ),
        (
            services::watch_unfinished("database is locked"),
            "The watch over the collector did not finish: database is locked [watch-unfinished]",
        ),
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
        (
            commands::wizard_io("standard input", "Input/output error (os error 5)"),
            "standard input: Input/output error (os error 5) [wizard-io]",
        ),
        (
            commands::wizard_ended(),
            "The setup was ended; run `garrison setup` again to continue. [wizard-ended]",
        ),
        (
            commands::addresses_unwritable(Path::new("/etc/garrison/garrison.toml"), &answers),
            "The addresses cannot be written into /etc/garrison/garrison.toml: its deployment \
             table is not one [deployment] section with a line for each, as dotted keys write it. \
             Write public_origin = \"https://garrison.example.org\", issuer = \
             \"https://mail.example.org\", stalwart_url = \"http://127.0.0.1:8080\" and admin_url \
             = \"https://mail.example.org/admin/\" under [deployment] there, then run `garrison \
             setup` again. [wizard-addresses-unwritable]",
        ),
        (
            commands::step_failed("Creating the access policy"),
            "Creating the access policy did not succeed; fix the cause above and run `garrison \
             setup` again. [wizard-step-failed]",
        ),
        (
            commands::stalwart_unconnected(),
            "Connecting Stalwart did not succeed. [wizard-stalwart-unconnected]",
        ),
        (
            commands::start_failed(&State::new("install-busy", "Another install runs.")),
            "Starting Garrison failed: Another install runs. [install-busy]; run `garrison setup` \
             again. [wizard-start-failed]",
        ),
        (
            commands::wizard_not_root(),
            "Run as root. [wizard-not-root]",
        ),
        (
            commands::no_terminal(),
            "garrison setup asks questions at a terminal; without one, follow \"Unattended \
             installation\" in docs/operator/installation.md. [wizard-no-terminal]",
        ),
        (
            commands::wizard_not_installed(),
            "Install the release first: ./bin/garrison install in the unpacked archive. \
             [wizard-not-installed]",
        ),
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
