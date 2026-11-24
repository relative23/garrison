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
use super::requirements::root_with_systemctl;
use super::{BACKUPS, BASE, CONFIG, LOCK, SYSTEMCTL, UNITS, command};

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

/// What goes, below `root` (`/` outside tests), in the order of removal;
/// `policy` is the access policy as the configuration names it.
fn plan(root: &Path, purge: bool, module: bool, policy: &Path) -> Vec<Item> {
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
        // A policy the configuration keeps elsewhere goes as well.
        if !policy.starts_with(CONFIG) {
            let policy = root.join(policy.strip_prefix("/").unwrap_or(policy));
            items.extend(policy_files(&policy).into_iter().map(Item::Path));
        }
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

/// The policy at `policy` and what `garrison access` keeps beside it: its
/// lock and its backups. Files only: the broker reads nothing else, and a
/// folder or a link of such a name is not Garrison's.
fn policy_files(policy: &Path) -> Vec<PathBuf> {
    let (Some(folder), Some(name)) = (policy.parent(), policy.file_name()) else {
        return Vec::new();
    };
    let name = name.to_string_lossy();
    // `garrison access` writes `.bak` exactly; other cases are no backups of it.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    let ours = |entry: &str| {
        entry == name
            || entry == format!("{name}.lock")
            || (entry.starts_with(&format!("{name}.")) && entry.ends_with(".bak"))
    };
    let mut found: Vec<PathBuf> = fs::read_dir(folder)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter(|entry| ours(&entry.file_name().to_string_lossy()))
        .map(|entry| entry.path())
        .collect();
    found.sort();
    found
}

/// Where `settings` is there and does not load, a purge cannot tell where
/// it keeps the access policy: one kept outside CONFIG is left, and this
/// says so.
fn policy_unknown(settings: &Path) -> Option<String> {
    if !settings.exists() {
        return None;
    }
    let error = garrison_core::config::load(settings).err()?;
    Some(format!(
        "{} does not load, so an access policy it names outside {CONFIG} is not removed \
         ({error}); remove it yourself if there is one.",
        settings.display()
    ))
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
                        || name.starts_with("pre-restore-")
                        || name.starts_with("pre-switch-back-")
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
    root_with_systemctl()?;
    let _held = lock(Path::new(LOCK))?;
    let root = Path::new("/");
    let items = plan(root, purge, module_loaded(), &super::policy());
    let unknown = policy_unknown(&Path::new(CONFIG).join("garrison.toml")).filter(|_| purge);
    super::milter::forgotten(Path::new(CONFIG))?;
    nginx_stays_valid(&snippets(root))?;
    if dry_run {
        for item in &items {
            announce(&format!("Would remove {}", item.describe()));
        }
        if let Some(unknown) = &unknown {
            announce(unknown);
        }
        return Ok(());
    }
    for item in &items {
        announce(&format!("Removing {}", item.describe()));
        remove(item)?;
    }
    if let Some(unknown) = &unknown {
        announce(unknown);
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
mod tests;
