//! The rows of `garrison backup-check`'s states.

use std::path::Path;

use super::Rows;
use crate::states::backup_check::*;

pub(super) fn rows() -> Rows {
    let report = Path::new("/var/lib/garrison/backup-check/restic.json");
    let lock = Path::new("/var/lib/garrison/backup-check/restic.json.lock");
    let absent = std::io::Error::from_raw_os_error(2);
    vec![
        unknown_tool(),
        lock_taken(lock, &absent),
        lock_other(lock),
        waits(report),
        listed("restic", 2, Some("2026-11-16T02:00:04+00:00")),
        unlisted("borg", "Repository /srv/repo does not exist."),
        verified("no errors were found"),
        verify_failed("pack 5e1f0c3a: not referenced"),
        restored("/etc/hosts: 1 files, 220 bytes"),
        restore_failed("/etc/hosts was not in the newest snapshot: nothing was restored"),
    ]
}

pub(super) fn copies() -> Rows {
    let report = Path::new("/var/lib/garrison/backup-check/restic.json");
    let copy = Path::new("/var/tmp/garrison-restore-00000000000000c1");
    let stuck = not_removed(copy, &std::io::Error::from_raw_os_error(16));
    vec![
        stuck.clone(),
        leftover_removed(copy),
        leftover_kept(&stuck),
        copy_kept(&stuck),
        report_foreign(Path::new("/srv/reports/restic.json")),
        report_unread(report, 64),
        report_unplaced(report),
        report_unlisted(report, "restic"),
        report_unidentified(report, "restic"),
        report_anonymous(report),
        report_other(
            report,
            ("restic", "/srv/repo", "5e1f"),
            ("borg", "/srv/borg", "77aa"),
        ),
        report_copy(
            report,
            ("restic", "/srv/repo", "5e1f"),
            ("restic", "/srv/copy", "5e1f"),
        ),
        unwritten(report, "Read-only file system (os error 30)"),
        written(report),
    ]
}
