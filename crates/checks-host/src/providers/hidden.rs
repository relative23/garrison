//! The places the collector's sandbox hides from it. Its unit puts an
//! inaccessible folder over `/home`, `/root` and `/run/user`
//! (`ProtectHome=true`) and an empty folder of its own over `/tmp` and
//! `/var/tmp` (`PrivateTmp=true`), as `/proc/self/mountinfo` shows; root,
//! which check-config runs as, sees the host's places there.

use std::path::{Path, PathBuf};

/// The places that `ProtectHome=true` makes inaccessible to the collector's
/// unit. Outside the unit they are the host's homes, which a card never
/// asks to open to every user.
pub(crate) const HOMES: [&str; 3] = ["/home", "/root", "/run/user"];

/// The place over which systemd's sandbox mounted one of its own, among
/// those that hold `path`, as this process sees them; `None` where it sees
/// the host's.
pub(crate) fn place(path: &Path) -> Option<PathBuf> {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    place_in(&mounts, path)
}

/// [`place`] for the mounts that `mountinfo` lists, in the order they were
/// mounted. The last of them that holds `path` is the one it is seen
/// through, as a folder mounted later covers what was mounted below it.
/// Where that mount shows systemd's inaccessible folder or a unit's own
/// temporary one, the sandbox hides the host's place.
fn place_in(mountinfo: &str, path: &Path) -> Option<PathBuf> {
    let (point, root) = mountinfo
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let root = fields.nth(3)?;
            Some((Path::new(fields.next()?), root))
        })
        .rfind(|(point, _)| path.starts_with(point))?;
    (root.ends_with("/systemd/inaccessible/dir") || root.contains("/systemd-private-"))
        .then(|| point.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mounts that a unit with the collector's `ProtectHome=true` and
    /// `PrivateTmp=true` sees, as a user unit of systemd 262 showed them
    /// (2026-11-24), without the lines of other places.
    const SANDBOX: &str = include_str!("hidden/sandbox-mountinfo.txt");

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
            let found = place_in(SANDBOX, Path::new(path));
            assert_eq!(found, hidden.map(PathBuf::from), "{path}");
        }
        // The host's own mounts, as root sees them, hide nothing.
        let host: Vec<&str> = SANDBOX
            .lines()
            .filter(|line| !line.contains("/systemd"))
            .collect();
        for (path, _) in cases {
            assert_eq!(place_in(&host.join("\n"), Path::new(path)), None, "{path}");
        }
        assert_eq!(place(Path::new("/proc/self")), None);
    }

    /// The homes are what the collector's unit hides with `ProtectHome=true`.
    #[test]
    fn the_homes_are_what_the_collectors_unit_hides() {
        let unit = include_str!("../../../../deploy/systemd/garrison-collect.service");
        assert!(unit.lines().any(|line| line == "ProtectHome=true"));
        for home in HOMES {
            assert_eq!(
                place_in(SANDBOX, &Path::new(home).join("x")),
                Some(PathBuf::from(home))
            );
        }
    }
}
