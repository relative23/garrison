//! `garrison uninstall [--purge] [--dry-run]`: take Garrison off the host.
//!
//! By default the program and its system integration go and the data stays:
//! configuration and credentials, the databases, the installer's backups and
//! the service users, so that installing again continues where it stopped.
//! `--purge` removes those too, but never backups the operator wrote with
//! `garrison backup --to`. Nothing changes until nginx is known to stay valid
//! without Garrison's snippets, and `--dry-run` only lists what would go.

use std::fs;
use std::path::{Path, PathBuf};

use super::files::{Step, announce, io, lock, must, run};
use super::{BACKUPS, BASE, CONFIG, LOCK, SYSTEMCTL, UNITS, command, preflight};

const USERS: [&str; 5] = [
    "garrison-milter",
    "garrison-ingest",
    "garrison-collector",
    "garrison-broker",
    "garrison",
];
const SEMODULE: &str = "/usr/sbin/semodule";
const NGINX: &str = "/usr/sbin/nginx";

/// Something the uninstallation removes.
#[derive(Debug, PartialEq, Eq)]
enum Item {
    /// Stop and disable the units before their files go.
    Units,
    Path(PathBuf),
    /// The SELinux module that lets nginx reach Garrison.
    Module,
    /// The service users and their group.
    Users,
}

impl Item {
    fn describe(&self) -> String {
        match self {
            Self::Units => "the services (stopped and disabled)".into(),
            Self::Path(path) => path.display().to_string(),
            Self::Module => "the SELinux module garrison".into(),
            Self::Users => format!("the users {} and the group garrison", USERS.join(", ")),
        }
    }
}

/// What goes, below `root` (`/` outside tests), in the order of removal.
fn plan(root: &Path, purge: bool, module: bool) -> Vec<Item> {
    let at = |path: &str| root.join(path.trim_start_matches('/'));
    let mut items = vec![Item::Units];
    for unit in UNITS {
        items.push(Item::Path(at("/etc/systemd/system").join(unit)));
    }
    items.push(Item::Path(at("/etc/polkit-1/rules.d/50-garrison.rules")));
    items.extend(snippets(root).into_iter().map(Item::Path));
    if module {
        items.push(Item::Module);
    }
    // The command's link, unless something else took that name.
    let link = at(command::LINK);
    if command::ours(&link) {
        items.push(Item::Path(link));
    }
    items.push(Item::Path(at(BASE)));
    if purge {
        items.push(Item::Path(at(CONFIG)));
        items.push(Item::Path(at("/var/lib/garrison")));
        items.extend(installer_backups(&at(BACKUPS)).into_iter().map(Item::Path));
        items.push(Item::Users);
        items.push(Item::Path(at("/etc/sysusers.d/garrison.conf")));
    }
    items.retain(|item| match item {
        Item::Path(path) => fs::symlink_metadata(path).is_ok(),
        _ => true,
    });
    items
}

fn snippets(root: &Path) -> Vec<PathBuf> {
    let folder = root.join("etc/nginx/snippets");
    // nginx reads `.conf` exactly; other cases are not snippets.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    let ours = |name: &str| name.starts_with("garrison") && name.ends_with(".conf");
    let mut found: Vec<PathBuf> = fs::read_dir(&folder)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(ours)
        })
        .collect();
    found.sort();
    found
}

/// The installer's own backups and the link to the one a rollback restores.
fn installer_backups(backups: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(backups)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name == super::LAST
                        || name.starts_with("pre-upgrade-")
                        || name.starts_with("pre-reinstall-")
                })
        })
        .collect();
    found.sort();
    found
}

fn module_loaded() -> bool {
    Path::new(SEMODULE).exists()
        && run(SEMODULE, &["-l"]).is_ok_and(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.split_whitespace().next() == Some("garrison"))
        })
}

/// nginx must accept its configuration without Garrison's snippets, or an
/// include left in a server block would keep nginx from starting. The files
/// move aside for the test and come back whatever it says.
fn nginx_stays_valid(snippets: &[PathBuf]) -> Step {
    if snippets.is_empty() || !Path::new(NGINX).exists() {
        return Ok(());
    }
    let aside: Vec<(PathBuf, PathBuf)> = snippets
        .iter()
        .map(|path| (path.clone(), path.with_extension("conf.garrison-uninstall")))
        .collect();
    for (path, moved) in &aside {
        io(fs::rename(path, moved), path)?;
    }
    let test = run(NGINX, &["-t"]);
    for (path, moved) in &aside {
        io(fs::rename(moved, path), path)?;
    }
    let test = test?;
    if test.status.success() {
        return Ok(());
    }
    Err(format!(
        "nginx would not start without Garrison's snippets; nothing was changed. Remove the \
         `include /etc/nginx/snippets/garrison…` lines from your server blocks first:\n{}",
        String::from_utf8_lossy(&test.stderr).trim()
    ))
}

fn remove(item: &Item) -> Step {
    match item {
        Item::Units => {
            let mut disable = vec!["disable", "--now"];
            disable.extend(UNITS);
            let _ = run(SYSTEMCTL, &disable);
            Ok(())
        }
        Item::Path(path) => {
            let kind = io(fs::symlink_metadata(path), path)?;
            if kind.is_dir() {
                io(fs::remove_dir_all(path), path)
            } else {
                io(fs::remove_file(path), path)
            }
        }
        Item::Module => must(SEMODULE, &["-r", "garrison"]),
        Item::Users => {
            for user in USERS {
                let _ = run("/usr/sbin/userdel", &[user]);
            }
            let _ = run("/usr/sbin/groupdel", &["garrison"]);
            Ok(())
        }
    }
}

fn uninstall(purge: bool, dry_run: bool) -> Step {
    preflight()?;
    let _held = lock(Path::new(LOCK))?;
    let root = Path::new("/");
    let items = plan(root, purge, module_loaded());
    super::milter::forgotten(Path::new(CONFIG))?;
    nginx_stays_valid(&snippets(root))?;
    if dry_run {
        for item in &items {
            announce(&format!("Would remove {}", item.describe()));
        }
        return Ok(());
    }
    for item in &items {
        announce(&format!("Removing {}", item.describe()));
        remove(item)?;
    }
    must(SYSTEMCTL, &["daemon-reload"])?;
    if run(SYSTEMCTL, &["is-active", "--quiet", "nginx"])
        .is_ok_and(|output| output.status.success())
    {
        must(SYSTEMCTL, &["reload", "nginx"])?;
    }
    if !purge {
        announce(&format!(
            "Kept for a later installation: {CONFIG}, /var/lib/garrison, {BACKUPS} and the \
             service users. `garrison uninstall --purge` from a release archive removes them."
        ));
    }
    announce(
        "Garrison's webhook, API keys and sign-in client in Stalwart stay; remove them in the \
         Stalwart WebUI if you no longer need them.",
    );
    Ok(())
}

pub(crate) fn run_uninstall(purge: bool, dry_run: bool) -> u8 {
    match uninstall(purge, dry_run) {
        Ok(()) => 0,
        Err(error) => {
            crate::complain(&error);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        for folder in [
            "etc/systemd/system",
            "etc/polkit-1/rules.d",
            "etc/nginx/snippets",
            "etc/garrison/credentials",
            "etc/sysusers.d",
            "usr/bin",
            "opt/garrison/releases/0.1.0",
            "var/lib/garrison/web",
            "var/backups/garrison/pre-upgrade-20261030T132151",
            "var/backups/garrison/latest",
        ] {
            fs::create_dir_all(root.join(folder)).unwrap();
        }
        for file in [
            "etc/systemd/system/garrison-web.service",
            "etc/polkit-1/rules.d/50-garrison.rules",
            "etc/nginx/snippets/garrison.conf",
            "etc/nginx/snippets/garrison-stalwart-server.conf",
            "etc/nginx/snippets/other.conf",
            "etc/sysusers.d/garrison.conf",
        ] {
            fs::write(root.join(file), "").unwrap();
        }
        std::os::unix::fs::symlink(
            "/opt/garrison/current/bin/garrison",
            root.join("usr/bin/garrison"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "pre-upgrade-20261030T132151",
            root.join("var/backups/garrison/last-pre-upgrade"),
        )
        .unwrap();
        directory
    }

    fn paths(items: &[Item], root: &Path) -> Vec<String> {
        items
            .iter()
            .filter_map(|item| match item {
                Item::Path(path) => Some(path.strip_prefix(root).unwrap().display().to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn by_default_the_program_goes_and_the_data_stays() {
        let directory = host();
        let root = directory.path();
        let items = plan(root, false, true);
        assert_eq!(items[0], Item::Units);
        assert!(items.contains(&Item::Module));
        assert!(!items.contains(&Item::Users));
        assert_eq!(
            paths(&items, root),
            [
                "etc/systemd/system/garrison-web.service",
                "etc/polkit-1/rules.d/50-garrison.rules",
                "etc/nginx/snippets/garrison-stalwart-server.conf",
                "etc/nginx/snippets/garrison.conf",
                "usr/bin/garrison",
                "opt/garrison",
            ]
        );
    }

    #[test]
    fn another_program_of_the_commands_name_stays() {
        let directory = host();
        let root = directory.path();
        fs::remove_file(root.join("usr/bin/garrison")).unwrap();
        fs::write(root.join("usr/bin/garrison"), "another program").unwrap();
        let paths = paths(&plan(root, true, false), root);
        assert!(!paths.contains(&"usr/bin/garrison".to_owned()), "{paths:?}");
    }

    #[test]
    fn a_purge_also_takes_data_users_and_the_installers_backups_only() {
        let directory = host();
        let root = directory.path();
        let items = plan(root, true, false);
        assert!(!items.contains(&Item::Module));
        assert!(items.contains(&Item::Users));
        let paths = paths(&items, root);
        for gone in [
            "etc/garrison",
            "var/lib/garrison",
            "var/backups/garrison/last-pre-upgrade",
            "var/backups/garrison/pre-upgrade-20261030T132151",
            "etc/sysusers.d/garrison.conf",
        ] {
            assert!(paths.contains(&gone.to_owned()), "{gone}");
        }
        assert!(
            !paths
                .iter()
                .any(|path| path.ends_with("latest") || path.ends_with("other.conf"))
        );
    }
}
