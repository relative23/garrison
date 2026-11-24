//! The rows of `garrison backup-check`'s states.

use std::path::Path;

use super::Rows;
use crate::states::backup_check::*;

pub(super) fn rows() -> Rows {
    let report = Path::new("/var/lib/garrison/backup-check/restic.json");
    let lock = Path::new("/var/lib/garrison/backup-check/restic.json.lock");
    let absent = std::io::Error::from_raw_os_error(2);
    vec![
        (
            unknown_tool(),
            "The backup tool is restic or borg. [backup-check-unknown-tool]",
        ),
        (
            lock_taken(lock, &absent),
            "The report's lock /var/lib/garrison/backup-check/restic.json.lock cannot be taken: No \
             such file or directory (os error 2). [backup-check-io]",
        ),
        (
            lock_other(lock),
            "/var/lib/garrison/backup-check/restic.json.lock is no lock of `garrison \
             backup-check`'s, but a link, another user's file or no file: remove it, then run the \
             command again. [backup-check-lock-other]",
        ),
        (
            waits(report),
            "Another `garrison backup-check` writes /var/lib/garrison/backup-check/restic.json; \
             this run waits until it has ended. [backup-check-waits]",
        ),
        (
            listed("restic", 2, Some("2026-11-16T02:00:04+00:00")),
            "restic: 2 snapshots, the newest of 2026-11-16T02:00:04+00:00. [backup-check-listed]",
        ),
        (
            unlisted("borg", "Repository /srv/repo does not exist."),
            "borg did not list its snapshots: Repository /srv/repo does not exist. \
             [backup-check-unlisted]",
        ),
        (
            verified("no errors were found"),
            "Integrity check: passed (no errors were found) [backup-check-verified]",
        ),
        (
            verify_failed("pack 5e1f0c3a: not referenced"),
            "Integrity check: FAILED (pack 5e1f0c3a: not referenced) [backup-check-verify-failed]",
        ),
        (
            restored("/etc/hosts: 1 files, 220 bytes"),
            "Restore test: passed (/etc/hosts: 1 files, 220 bytes) [backup-check-restored]",
        ),
        (
            restore_failed("/etc/hosts was not in the newest snapshot: nothing was restored"),
            "Restore test: FAILED (/etc/hosts was not in the newest snapshot: nothing was \
             restored) [backup-check-restore-failed]",
        ),
    ]
}

pub(super) fn copies() -> Rows {
    let report = Path::new("/var/lib/garrison/backup-check/restic.json");
    let copy = Path::new("/var/tmp/garrison-restore-00000000000000c1");
    let stuck = not_removed(copy, &std::io::Error::from_raw_os_error(16));
    vec![
        (
            stuck.clone(),
            "/var/tmp/garrison-restore-00000000000000c1 could not be removed (Device or resource \
             busy (os error 16)); it holds a copy of what the backup holds: remove it as root with \
             rm -r /var/tmp/garrison-restore-00000000000000c1 [backup-check-not-removed]",
        ),
        (
            leftover_removed(copy),
            "Removed /var/tmp/garrison-restore-00000000000000c1, a copy of restored data that an \
             interrupted test restore left. [backup-check-leftover-removed]",
        ),
        (
            leftover_kept(&stuck),
            "A copy that an interrupted test restore left: \
             /var/tmp/garrison-restore-00000000000000c1 could not be removed (Device or resource \
             busy (os error 16)); it holds a copy of what the backup holds: remove it as root with \
             rm -r /var/tmp/garrison-restore-00000000000000c1 [backup-check-not-removed] \
             [backup-check-leftover-kept]",
        ),
        (
            copy_kept(&stuck),
            "This test restore's copy: /var/tmp/garrison-restore-00000000000000c1 could not be \
             removed (Device or resource busy (os error 16)); it holds a copy of what the backup \
             holds: remove it as root with rm -r /var/tmp/garrison-restore-00000000000000c1 \
             [backup-check-not-removed] [backup-check-copy-kept]",
        ),
        (
            report_foreign(Path::new("/srv/reports/restic.json")),
            "The last report, /srv/reports/restic.json, can be changed by users other than root: \
             its last integrity check and test restore are not kept. [backup-check-report-foreign]",
        ),
        (
            report_unread(report, 64),
            "The last report, /var/lib/garrison/backup-check/restic.json, cannot be read: it must \
             be a file, not a link, of at most 64 KiB of valid JSON. Its last integrity check and \
             test restore are not kept. [backup-check-report-unread]",
        ),
        (
            report_unplaced(report),
            "The last report, /var/lib/garrison/backup-check/restic.json, is not known to be of \
             this repository, since the command is not told where this one is: its last \
             integrity check and test restore are not kept. [backup-check-report-unplaced]",
        ),
        (
            report_unlisted(report, "restic"),
            "The last report, /var/lib/garrison/backup-check/restic.json, is not known to be of \
             this repository, since restic could not list it: its last integrity check and test \
             restore are not kept. [backup-check-report-unlisted]",
        ),
        (
            report_unidentified(report, "restic"),
            "The last report, /var/lib/garrison/backup-check/restic.json, is not known to be of \
             this repository, since restic gave no ID for it: its last integrity check and test \
             restore are not kept. [backup-check-report-unidentified]",
        ),
        (
            report_anonymous(report),
            "The last report, /var/lib/garrison/backup-check/restic.json, holds no repository ID: \
             its last integrity check and test restore are not kept. \
             [backup-check-report-anonymous]",
        ),
        (
            report_other(
                report,
                ("restic", "/srv/repo", "5e1f"),
                ("borg", "/srv/borg", "77aa"),
            ),
            "The last report, /var/lib/garrison/backup-check/restic.json, is of the restic \
             repository /srv/repo (ID 5e1f), and this run asks the borg repository /srv/borg (ID \
             77aa): its last integrity check and test restore are not kept. \
             [backup-check-report-other]",
        ),
        (
            report_copy(
                report,
                ("restic", "/srv/repo", "5e1f"),
                ("restic", "/srv/copy", "5e1f"),
            ),
            "The last report, /var/lib/garrison/backup-check/restic.json, is of the restic \
             repository /srv/repo (ID 5e1f), and this run asks the restic repository /srv/copy (ID \
             5e1f): its last integrity check and test restore are not kept. The same ID at \
             another place is a copy, which needs a --report of its own; name one repository \
             alike in every run. [backup-check-report-copy]",
        ),
        (
            unwritten(report, "Read-only file system (os error 30)"),
            "The report could not be written to /var/lib/garrison/backup-check/restic.json: \
             Read-only file system (os error 30) [backup-check-unwritten]",
        ),
        (
            written(report),
            "Report written to /var/lib/garrison/backup-check/restic.json. [backup-check-written]",
        ),
    ]
}
