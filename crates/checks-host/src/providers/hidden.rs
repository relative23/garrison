//! How the collector sees a place of the host. Its sandbox puts an
//! inaccessible folder over `/home`, `/root` and `/run/user`
//! (`ProtectHome=true`) and an empty folder of its own over `/tmp` and
//! `/var/tmp` (`PrivateTmp=true`), and a drop-in may show it a folder of the
//! host at another place (`BindReadOnlyPaths=`), as `/proc/self/mountinfo`
//! shows; root, which check-config runs as, sees the host's places there.

use std::path::{Component, Path, PathBuf};

/// The places that `ProtectHome=true` makes inaccessible to the collector's
/// unit. Outside the unit they are the host's homes, which a card never
/// asks to open to every user.
pub(crate) const HOMES: [&str; 3] = ["/home", "/root", "/run/user"];

/// How this process sees a place of the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seen {
    /// As the host's own.
    Host,
    /// Not at all: systemd's sandbox mounted a folder of its own over this
    /// place.
    Hidden(PathBuf),
    /// Through a mount at `point` of the host's folder `source`.
    Bound { point: PathBuf, source: PathBuf },
}

impl Seen {
    /// Where `path`, seen so, lies on the host, where a mount shows it at
    /// another place.
    pub(crate) fn on_host(&self, path: &Path) -> Option<PathBuf> {
        match self {
            Seen::Bound { point, source } => path
                .strip_prefix(point)
                .ok()
                .map(|rest| below(source, rest)),
            Seen::Host | Seen::Hidden(_) => None,
        }
    }
}

/// `rest` below `folder`, which is `folder` itself where `rest` is empty.
fn below(folder: &Path, rest: &Path) -> PathBuf {
    if rest.as_os_str().is_empty() {
        folder.to_path_buf()
    } else {
        folder.join(rest)
    }
}

/// How this process sees `path`; as the host's where its mounts cannot be
/// read.
pub(crate) fn seen(path: &Path) -> Seen {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map_or(Seen::Host, |mounts| seen_in(&mounts, path))
}

/// Where a look at a path stops: the path as the links on the way lead, the
/// deepest folder of it that can be looked at, and the first link on the
/// way with where it leads, if there is one.
pub(crate) struct Stop {
    pub(crate) path: PathBuf,
    pub(crate) folder: PathBuf,
    pub(crate) link: Option<(PathBuf, PathBuf)>,
}

/// [`Stop`] for `path`, following up to eight links on the way.
pub(crate) fn stop(path: &Path) -> Stop {
    let mut path = path.to_path_buf();
    let mut link = None;
    for _ in 0..8 {
        let folder = path
            .ancestors()
            .skip(1)
            .find(|folder| std::fs::symlink_metadata(folder).is_ok())
            .unwrap_or(&path)
            .to_path_buf();
        let Ok(target) = std::fs::read_link(&folder) else {
            return Stop { path, folder, link };
        };
        // A link that names no root leads from the folder that holds it.
        let target = normal(&folder.parent().unwrap_or(Path::new("/")).join(target));
        let rest = path
            .strip_prefix(&folder)
            .map(Path::to_path_buf)
            .unwrap_or_default();
        link.get_or_insert_with(|| (folder, target.clone()));
        path = target.join(rest);
    }
    let folder = path.clone();
    Stop { path, folder, link }
}

/// `path` without its `.` and `..`, as far as the names alone tell.
fn normal(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                normal.pop();
            }
            Component::CurDir => {}
            part => normal.push(part),
        }
    }
    normal
}

impl Stop {
    /// How the path is seen, `seen` being how the path asked for is: where a
    /// link led elsewhere, that place is what is seen.
    pub(crate) fn seen(&self, seen: &Seen) -> Seen {
        match &self.link {
            Some(_) => self::seen(&self.path),
            None => seen.clone(),
        }
    }

    /// The place under which the collector's unit hides the path, seen as
    /// `seen`: the one its sandbox mounted a folder of its own over, or,
    /// where the look was `denied`, the home it stopped at, which the unit
    /// hides and which is opened to no user.
    pub(crate) fn hidden_under(&self, seen: &Seen, denied: bool) -> Option<PathBuf> {
        match seen {
            Seen::Hidden(place) => Some(place.clone()),
            Seen::Host | Seen::Bound { .. } => {
                let home = denied && HOMES.iter().any(|home| self.folder == Path::new(home));
                home.then(|| self.folder.clone())
            }
        }
    }
}

/// One line of mountinfo: the file system, the folder of it that the mount
/// shows, and where.
struct Mount<'a> {
    device: &'a str,
    root: &'a Path,
    point: &'a Path,
}

/// [`seen`] for the mounts that `mountinfo` lists, in the order they were
/// mounted. The last of them that holds `path` is the one it is seen
/// through, as a folder mounted later covers what was mounted below it.
/// Where that mount shows systemd's inaccessible folder or a unit's own
/// temporary one, the sandbox hides the host's place; where another mount
/// of the same file system shows a folder that holds the one it shows, as
/// `/` shows `/@` and a bind mount `/@/root` on btrfs, it shows that
/// folder's place of the host. A subvolume or a file system of its own,
/// whose root no other mount holds, is the host's.
fn seen_in(mountinfo: &str, path: &Path) -> Seen {
    let mounts: Vec<Mount<'_>> = mountinfo
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let device = fields.nth(2)?;
            let root = Path::new(fields.next()?);
            let point = Path::new(fields.next()?);
            Some(Mount {
                device,
                root,
                point,
            })
        })
        .collect();
    let Some(last) = mounts.iter().rfind(|mount| path.starts_with(mount.point)) else {
        return Seen::Host;
    };
    let root = last.root.to_string_lossy();
    if root.ends_with("/systemd/inaccessible/dir") || root.contains("/systemd-private-") {
        return Seen::Hidden(last.point.to_path_buf());
    }
    // The first of those that holds it most nearly.
    let mut holder: Option<&Mount<'_>> = None;
    for mount in &mounts {
        let holds = mount.device == last.device
            && mount.point != last.point
            && last.root.starts_with(mount.root);
        let nearer = holder
            .is_none_or(|known| mount.root.components().count() > known.root.components().count());
        if holds && nearer {
            holder = Some(mount);
        }
    }
    holder
        .and_then(|mount| {
            let rest = last.root.strip_prefix(mount.root).ok()?;
            Some(Seen::Bound {
                point: last.point.to_path_buf(),
                source: below(mount.point, rest),
            })
        })
        .unwrap_or(Seen::Host)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mounts that a unit with the collector's `ProtectHome=true` and
    /// `PrivateTmp=true` sees, as a user unit of systemd 262 showed them
    /// (2026-11-24), without the lines of other places.
    const SANDBOX: &str = include_str!("hidden/sandbox-mountinfo.txt");

    /// The same with two folders of the host shown at other places, as
    /// docs/operator/checks.md has an operator do it:
    /// `BindReadOnlyPaths=/root:/dev/shm/hostchk-3/shown` and
    /// `/etc:/dev/shm/hostchk-3/etc-shown`, measured so (2026-11-24) on a
    /// btrfs root whose `/`, `/home` and `/var/log` are subvolumes.
    const BOUND: &str = include_str!("hidden/bind-mountinfo.txt");

    #[test]
    fn the_places_the_sandbox_mounts_over_are_hidden() {
        let cases = [
            ("/root/backup/last.json", Some("/root")),
            ("/home/webmail/bulwark", Some("/home")),
            // Mounted before /run/user was covered, so no longer seen.
            ("/run/user/1000/last.json", Some("/run/user")),
            ("/tmp/backup/last.json", Some("/tmp")),
            ("/var/tmp/last.json", Some("/var/tmp")),
            ("/var/lib/backup/last.json", None),
            ("/homeless/last.json", None),
            ("/run/last.json", None),
        ];
        for (path, hidden) in cases {
            let found = seen_in(SANDBOX, Path::new(path));
            let expected = hidden.map_or(Seen::Host, |place| Seen::Hidden(PathBuf::from(place)));
            assert_eq!(found, expected, "{path}");
        }
        // The host's own mounts, as root sees them, hide nothing.
        let host: Vec<&str> = SANDBOX
            .lines()
            .filter(|line| !line.contains("/systemd"))
            .collect();
        for (path, _) in cases {
            assert_eq!(
                seen_in(&host.join("\n"), Path::new(path)),
                Seen::Host,
                "{path}"
            );
        }
        assert_eq!(seen(Path::new("/proc/self")), Seen::Host);
    }

    /// A folder of the host that a mount shows at another place is named by
    /// its place on the host; a subvolume and a file system of its own are
    /// the host's, and the sandbox's places stay hidden beside the mounts.
    #[test]
    fn a_folder_that_a_mount_shows_at_another_place_is_the_hosts() {
        let bound = |point: &str, source: &str| Seen::Bound {
            point: PathBuf::from(point),
            source: PathBuf::from(source),
        };
        let cases = [
            (
                "/dev/shm/hostchk-3/shown/last.json",
                bound("/dev/shm/hostchk-3/shown", "/root"),
            ),
            (
                "/dev/shm/hostchk-3/etc-shown/.pwd.lock",
                bound("/dev/shm/hostchk-3/etc-shown", "/etc"),
            ),
            ("/dev/shm/hostchk-3/last.json", Seen::Host),
            ("/var/log/backup.json", Seen::Host),
            ("/var/lib/backup/last.json", Seen::Host),
            ("/root/last.json", Seen::Hidden(PathBuf::from("/root"))),
            ("/tmp/last.json", Seen::Hidden(PathBuf::from("/tmp"))),
        ];
        for (path, expected) in cases {
            assert_eq!(seen_in(BOUND, Path::new(path)), expected, "{path}");
        }
        let shown = bound("/dev/shm/hostchk-3/etc-shown", "/etc");
        assert_eq!(
            shown.on_host(Path::new("/dev/shm/hostchk-3/etc-shown/.pwd.lock")),
            Some(PathBuf::from("/etc/.pwd.lock"))
        );
        assert_eq!(
            shown.on_host(Path::new("/dev/shm/hostchk-3/etc-shown")),
            Some(PathBuf::from("/etc"))
        );
        assert_eq!(shown.on_host(Path::new("/dev/shm/hostchk-3")), None);
    }

    /// The homes are what the collector's unit hides with `ProtectHome=true`.
    #[test]
    fn the_homes_are_what_the_collectors_unit_hides() {
        let unit = include_str!("../../../../deploy/systemd/garrison-collect.service");
        assert!(unit.lines().any(|line| line == "ProtectHome=true"));
        for home in HOMES {
            assert_eq!(
                seen_in(SANDBOX, &Path::new(home).join("x")),
                Seen::Hidden(PathBuf::from(home))
            );
        }
    }
}
