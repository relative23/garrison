//! Garrison's own systemd units, as `deploy/systemd` ships them. Every list
//! of units in the operator commands is made of these names.

mod sandbox;

pub(crate) use sandbox::{
    collector_places, hidden_base, hidden_paths, hidden_policy, policy_place,
};

pub(crate) const WEB: &str = "garrison-web.service";
pub(crate) const INGEST: &str = "garrison-ingest.service";
/// systemd starts the broker when its socket is first used.
pub(crate) const BROKER: &str = "garrison-broker.service";
pub(crate) const BROKER_SOCKET: &str = "garrison-broker.socket";
/// One collection run; its timer starts it every minute.
pub(crate) const COLLECT: &str = "garrison-collect.service";
pub(crate) const COLLECT_TIMER: &str = "garrison-collect.timer";
/// One look at whether the collector still runs; its timer starts it every
/// five minutes.
pub(crate) const WATCH: &str = "garrison-watch.service";
pub(crate) const WATCH_TIMER: &str = "garrison-watch.timer";
/// The macro milter; it runs only where the configuration switches it on.
pub(crate) const MILTER: &str = "garrison-milter.service";
/// Where earlier releases noted the ID of the filter's entry in Stalwart,
/// in the credentials directory; setup removes it.
pub(crate) const MILTER_ENTRY: &str = "stalwart-milter-id";

/// What is active on a host where Garrison runs, in the order `detect` and
/// `doctor` name the units.
pub(crate) const RUNNING: [&str; 5] = [WEB, INGEST, BROKER_SOCKET, COLLECT_TIMER, WATCH_TIMER];

/// Where the units keep each service's data: systemd makes
/// `StateDirectory=garrison/<service>` here, and the service may write
/// nowhere else.
pub(crate) const STATE: &str = "/var/lib/garrison";
/// Where the units load every credential from (`LoadCredential=`).
pub(crate) const CREDENTIALS: &str = "/etc/garrison/credentials";
/// The files of the notification channels that the collector and the watch
/// load: the tokens, the mail password and the addresses kept as secrets.
/// systemd starts no unit whose credential is missing, so the installer
/// keeps an empty file for each, which means: none.
pub(crate) const NOTIFICATION_FILES: [&str; 5] = [
    "ntfy-token",
    "notify-webhook-token",
    "notify-mail-password",
    "ntfy-url",
    "notify-webhook-url",
];
/// The collector's own files that may be empty, which means none: Stalwart's
/// metrics exporter's credential, which setup writes only where the exporter
/// is Garrison's, and the key of Spamhaus' Data Query Service, which only
/// its lists need. The installer keeps an empty file for each, as for the
/// notification files.
pub(crate) const COLLECTOR_FILES: [&str; 2] = ["metrics-credential", "spamhaus-dqs-key"];
/// Where `garrison-broker.socket` listens; systemd hands it to the broker.
pub(crate) const BROKER_PATH: &str = "/run/garrison/broker.sock";
/// Each setting that names a secret, the units whose services read it, and
/// the one name those units load it as (`LoadCredential=`): systemd hands a
/// service no other.
pub(crate) const SECRETS: [(&str, &[&str], &str); 10] = [
    ("ingest.signature_key", &[INGEST], "webhook-signature-key"),
    ("collector.native_key", &[COLLECT], "collector-native-key"),
    (
        "collector.metrics_credential",
        &[COLLECT],
        "metrics-credential",
    ),
    ("collector.dqs_key", &[COLLECT], "spamhaus-dqs-key"),
    ("broker.native_key", &[BROKER], "broker-native-key"),
    ("notifications.token", &[COLLECT, WATCH], "ntfy-token"),
    (
        "notifications.webhook_token",
        &[COLLECT, WATCH],
        "notify-webhook-token",
    ),
    (
        "notifications.mail_password",
        &[COLLECT, WATCH],
        "notify-mail-password",
    ),
    ("notifications.ntfy_url", &[COLLECT, WATCH], "ntfy-url"),
    (
        "notifications.webhook_url",
        &[COLLECT, WATCH],
        "notify-webhook-url",
    ),
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const SHIPPED: [(&str, &str); 7] = [
        (
            WEB,
            include_str!("../../../deploy/systemd/garrison-web.service"),
        ),
        (
            INGEST,
            include_str!("../../../deploy/systemd/garrison-ingest.service"),
        ),
        (
            COLLECT,
            include_str!("../../../deploy/systemd/garrison-collect.service"),
        ),
        (
            WATCH,
            include_str!("../../../deploy/systemd/garrison-watch.service"),
        ),
        (
            BROKER,
            include_str!("../../../deploy/systemd/garrison-broker.service"),
        ),
        (
            BROKER_SOCKET,
            include_str!("../../../deploy/systemd/garrison-broker.socket"),
        ),
        (
            MILTER,
            include_str!("../../../deploy/systemd/garrison-milter.service"),
        ),
    ];

    /// The values of `key` in every shipped unit, with the unit's name.
    pub(super) fn values(key: &str) -> Vec<(&'static str, &'static str)> {
        SHIPPED
            .iter()
            .flat_map(|(unit, text)| {
                text.lines()
                    .filter_map(move |line| Some((*unit, line.strip_prefix(key)?)))
            })
            .collect()
    }

    #[test]
    fn the_paths_are_the_ones_the_shipped_units_use() {
        let directories = values("StateDirectory=");
        for (unit, service) in [
            (WEB, "web"),
            (INGEST, "ingest"),
            (COLLECT, "collector"),
            (WATCH, "watch"),
            (BROKER, "broker"),
        ] {
            let wanted = format!("garrison/{service}");
            assert!(directories.contains(&(unit, wanted.as_str())), "{unit}");
        }
        assert_eq!(directories.len(), 5);
        for (unit, paths) in values("ReadOnlyPaths=") {
            for path in paths.split_whitespace() {
                assert!(path.starts_with(&format!("{STATE}/")), "{unit}: {path}");
            }
        }
        let credentials = values("LoadCredential=");
        assert!(credentials.len() >= 8);
        for (unit, credential) in credentials {
            let (name, source) = credential.split_once(':').unwrap();
            assert_eq!(source, format!("{CREDENTIALS}/{name}"), "{unit}");
        }
        assert_eq!(values("ListenStream="), [(BROKER_SOCKET, BROKER_PATH)]);
    }

    /// Under `/proc` the web service, the receiver and the macro filter read
    /// only their own process (the web service its binary's path, to find the
    /// interface), so they see nothing else there. The collector's `host`
    /// check reads the host's figures there (`meminfo`, `loadavg`, `uptime`).
    #[test]
    fn the_services_that_read_only_their_own_process_see_nothing_else_in_proc() {
        for (key, value) in [("ProtectProc=", "invisible"), ("ProcSubset=", "pid")] {
            let set = values(key);
            for unit in [WEB, INGEST, MILTER] {
                assert!(set.contains(&(unit, value)), "{unit} lacks {key}{value}");
            }
        }
        let subsets = values("ProcSubset=");
        assert!(
            subsets.iter().all(|(unit, _)| *unit != COLLECT),
            "{subsets:?}"
        );
    }

    /// check-config refuses a hidden policy only for the file the units
    /// read: their services start with the default configuration.
    #[test]
    fn the_units_start_every_service_with_the_default_configuration() {
        let started = values("ExecStart=");
        assert_eq!(started.len(), 6, "{started:?}");
        for (unit, command) in started {
            assert!(
                command.starts_with("/opt/garrison/current/bin/garrison ")
                    && !command.contains("--config"),
                "{unit}: {command}"
            );
        }
    }

    /// Every credential a unit loads is the secret of one setting, and each
    /// setting's units load it under the name the list gives.
    #[test]
    fn each_secret_is_loaded_by_its_units_under_its_name() {
        let loaded: BTreeSet<(&str, &str)> = values("LoadCredential=")
            .into_iter()
            .map(|(unit, credential)| (unit, credential.split_once(':').unwrap().0))
            .collect();
        let listed: BTreeSet<(&str, &str)> = SECRETS
            .iter()
            .flat_map(|(_, units, name)| units.iter().map(|unit| (*unit, *name)))
            .collect();
        assert_eq!(listed, loaded);
    }

    /// The installer keeps a file for every notification credential the
    /// collector and the watch load, and they load every one it keeps: both
    /// send on the same channels.
    #[test]
    fn the_collector_and_the_watch_load_every_notification_file() {
        let loaded = |unit: &str| -> Vec<&str> {
            values("LoadCredential=")
                .into_iter()
                .filter(|(name, _)| *name == unit)
                .filter_map(|(_, credential)| credential.split_once(':').map(|(name, _)| name))
                .collect()
        };
        for unit in [COLLECT, WATCH] {
            for name in NOTIFICATION_FILES {
                assert!(loaded(unit).contains(&name), "{unit} does not load {name}");
            }
        }
        let watch = loaded(WATCH);
        assert_eq!(watch.len(), NOTIFICATION_FILES.len(), "{watch:?}");
        // The collector's own files that may be empty are its alone.
        for name in COLLECTOR_FILES {
            assert!(
                loaded(COLLECT).contains(&name),
                "{COLLECT} does not load {name}"
            );
            assert!(!watch.contains(&name), "{name}");
        }
    }
}
