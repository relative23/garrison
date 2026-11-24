//! Settings that the shipped units and nginx's include do not follow.
//!
//! systemd makes each service's state directory and lets the service write
//! nowhere else, loads the credentials from one directory and listens for
//! the broker on one path. The settings that name those places stay in the
//! configuration, so that a file that names them keeps loading, but another
//! value is not followed. nginx's include names the web port as the
//! installer last wrote it. `check-config` warns of each.

use std::fs;
use std::path::Path;

use garrison_core::config::{Config, Database};

use crate::{nginx, units};

/// One setting that something does not follow.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Unfollowed {
    /// The setting, and what does not follow it.
    pub(crate) what: String,
    /// What to do.
    pub(crate) fix: String,
}

/// The include as the installer last wrote it, where there is one.
pub(crate) fn installed_include() -> Option<String> {
    let data = garrison_core::files::read_bounded(Path::new(nginx::SNIPPET), 64 * 1024).ok()?;
    String::from_utf8(data).ok()
}

/// Whether two paths name one directory: as written, or once resolved,
/// as where `/var/lib/garrison` is a link to another disk.
fn same(configured: &Path, fixed: &Path) -> bool {
    configured == fixed
        || matches!(
            (fs::canonicalize(configured), fs::canonicalize(fixed)),
            (Ok(one), Ok(other)) if one == other
        )
}

/// A state directory other than the one its writer's unit may write in.
fn state(config: &Config, database: Database) -> Option<Unfollowed> {
    let service = database.writer();
    let path = config.database(database);
    let configured = path.parent()?;
    let fixed = Path::new(units::STATE).join(service);
    let unit = match database {
        Database::Web => units::WEB,
        Database::Events => units::INGEST,
        Database::Status => units::COLLECT,
        Database::Jobs => units::BROKER,
    };
    (!same(configured, &fixed)).then(|| Unfollowed {
        what: format!(
            "{service}.state_directory is {}, but {unit} may write only in {}, the directory \
             systemd makes for it",
            configured.display(),
            fixed.display()
        ),
        fix: format!(
            "Remove the setting. To keep Garrison's data on another disk, mount it at {}.",
            units::STATE
        ),
    })
}

/// The settings of `config` that the units or the installed include
/// (`include`, the text of nginx's include where there is one) do not follow.
pub(crate) fn settings(config: &Config, include: Option<&str>) -> Vec<Unfollowed> {
    let mut found: Vec<Unfollowed> = Database::ALL
        .into_iter()
        .filter_map(|database| state(config, database))
        .collect();
    let credentials = &config.credentials_directory;
    if !same(credentials, Path::new(units::CREDENTIALS)) {
        found.push(Unfollowed {
            what: format!(
                "credentials_directory is {}, but the units load every credential from {}: no \
                 service reads what `garrison stalwart setup` writes into {}",
                credentials.display(),
                units::CREDENTIALS,
                credentials.display()
            ),
            fix: format!(
                "Remove the setting and keep the credentials in {}.",
                units::CREDENTIALS
            ),
        });
    }
    let socket = &config.broker.socket;
    if !same(socket, Path::new(units::BROKER_PATH)) {
        found.push(Unfollowed {
            what: format!(
                "broker.socket is {}, but {} listens on {} and hands that socket to the broker: \
                 the web service would find no broker at {}",
                socket.display(),
                units::BROKER_SOCKET,
                units::BROKER_PATH,
                socket.display()
            ),
            fix: "Remove the setting.".to_owned(),
        });
    }
    let port = config.web.port;
    if let Some(written) = include
        .and_then(nginx::port_of)
        .filter(|written| *written != port)
    {
        found.push(Unfollowed {
            what: format!(
                "web.port is {port}, but nginx's include {} sends Garrison's requests to port \
                 {written}",
                nginx::SNIPPET
            ),
            fix: format!(
                "Run the installer again, which under SELinux also loads the module for the \
                 port; without SELinux, restarting garrison-web and writing the include anew \
                 does as well: sudo systemctl restart garrison-web && sudo sh -c 'garrison \
                 nginx --snippet > {}' && sudo nginx -t && sudo systemctl reload nginx",
                nginx::SNIPPET
            ),
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use garrison_core::config::from_text;

    use super::*;

    const EXAMPLE: &str = include_str!("../../../deploy/config/garrison.example.toml");
    const CREDENTIALS: &str = "credentials_directory = \"/etc/garrison/credentials\"\n";

    /// The example configuration with `from` replaced by `to`.
    fn edited(from: &str, to: &str) -> Config {
        assert!(EXAMPLE.contains(from), "{from}");
        from_text(&EXAMPLE.replacen(from, to, 1)).unwrap()
    }

    /// The example configuration with `line` added to `section`.
    fn with(section: &str, line: &str) -> Config {
        let header = format!("[{section}]\n");
        edited(&header, &format!("{header}{line}\n"))
    }

    fn whats(config: &Config, include: Option<&str>) -> Vec<String> {
        settings(config, include)
            .into_iter()
            .map(|unfollowed| unfollowed.what)
            .collect()
    }

    #[test]
    fn the_example_and_the_defaults_written_out_are_followed() {
        let example = from_text(EXAMPLE).unwrap();
        assert_eq!(whats(&example, None), Vec::<String>::new());
        assert_eq!(
            whats(&example, Some(&nginx::snippet(8091))),
            Vec::<String>::new()
        );
        for config in [
            with("web", "state_directory = \"/var/lib/garrison/web/\""),
            with("ingest", "state_directory = \"/var/lib/garrison//ingest\""),
            with(
                "collector",
                "state_directory = \"/var/lib/garrison/./collector\"",
            ),
            with("broker", "socket = \"/run/garrison/broker.sock\""),
            edited(
                CREDENTIALS,
                "credentials_directory = \"/etc/garrison/credentials/\"\n",
            ),
        ] {
            assert_eq!(whats(&config, None), Vec::<String>::new());
        }
    }

    #[test]
    fn each_setting_the_units_do_not_follow_is_named_with_what_to_do() {
        let moved = with("collector", "state_directory = \"/srv/garrison/collector\"");
        assert_eq!(
            settings(&moved, None),
            [Unfollowed {
                what: "collector.state_directory is /srv/garrison/collector, but \
                       garrison-collect.service may write only in /var/lib/garrison/collector, \
                       the directory systemd makes for it"
                    .to_owned(),
                fix: "Remove the setting. To keep Garrison's data on another disk, mount it at \
                      /var/lib/garrison."
                    .to_owned(),
            }]
        );
        for (config, start) in [
            (
                with("web", "state_directory = \"/srv/web\""),
                "web.state_directory is /srv/web, but garrison-web.service",
            ),
            (
                with("ingest", "state_directory = \"/srv/ingest\""),
                "ingest.state_directory is /srv/ingest, but garrison-ingest.service",
            ),
            (
                with("broker", "state_directory = \"/srv/broker\""),
                "broker.state_directory is /srv/broker, but garrison-broker.service",
            ),
            (
                with("broker", "socket = \"/run/broker.sock\""),
                "broker.socket is /run/broker.sock, but garrison-broker.socket listens on \
                 /run/garrison/broker.sock",
            ),
            (
                edited(
                    CREDENTIALS,
                    "credentials_directory = \"/root/credentials\"\n",
                ),
                "credentials_directory is /root/credentials, but the units load every \
                 credential from /etc/garrison/credentials",
            ),
        ] {
            let found = whats(&config, None);
            assert_eq!(found.len(), 1, "{found:?}");
            assert!(found[0].starts_with(start), "{found:?}");
        }
    }

    #[test]
    fn an_include_written_for_another_port_is_named() {
        let config = edited("port = 8091", "port = 9443");
        assert_eq!(config.web.port, 9443);
        let found = settings(&config, Some(&nginx::snippet(8091)));
        assert_eq!(
            found[0].what,
            "web.port is 9443, but nginx's include /etc/nginx/snippets/garrison.conf sends \
             Garrison's requests to port 8091"
        );
        assert!(
            found[0].fix.contains("garrison nginx --snippet"),
            "{}",
            found[0].fix
        );
        // garrison-web takes web.port when it starts; nginx would send to
        // a port nothing listens on yet.
        assert!(
            found[0]
                .fix
                .contains("sudo systemctl restart garrison-web && sudo sh -c"),
            "{}",
            found[0].fix
        );
        assert_eq!(found.len(), 1);
        // Written for this port, or an include of the operator's own: nothing to say.
        assert_eq!(
            whats(&config, Some(&nginx::snippet(9443))),
            Vec::<String>::new()
        );
        assert_eq!(
            whats(&config, Some("location / { return 404; }")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_directory_named_through_a_link_is_the_same_directory() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        fs::create_dir(&real).unwrap();
        let linked = directory.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(same(&linked, &real));
        assert!(!same(&directory.path().join("other"), &real));
    }
}
