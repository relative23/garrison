//! A report the collector cannot see or get an answer about: in a place its
//! unit hides, or on a file system that does not answer.

use std::path::PathBuf;
use std::time::Instant;

use super::*;
use crate::providers::hidden::Seen;
use crate::providers::ran::patience;
use crate::testing::table;

fn provider(path: &str) -> BackupCheck {
    BackupCheck::new(&table(&format!(
        "type = \"backup-check\"\npath = \"{path}\""
    )))
    .unwrap()
}

/// Where the collector's unit hides the place that holds the report, as it
/// hides `/root` and `/tmp`, running `garrison backup-check` again writes
/// the report where it was and mends nothing: the card says where the
/// report belongs. Seen as the host's, a home this user may not search gets
/// the same words, and `/tmp` those of a report that is not there.
#[test]
fn a_report_in_a_place_the_collectors_unit_hides_says_so() {
    for (path, place) in [
        ("/root/garrison-test-hidden/restic.json", "/root"),
        ("/tmp/garrison-test-hidden/restic.json", "/tmp"),
    ] {
        let hides = format!(
            "the report at {path} lies under {place}, which the collector's unit hides from \
             it: let `garrison backup-check restic --report FILE` write it where the collector \
             sees it, as under /var/lib/garrison/backup-check, and set `path` to that file \
             (docs/operator/checks.md, \"Paths the collector cannot see\")"
        );
        let check = provider(path);
        let hidden = Seen::Hidden(PathBuf::from(place));
        assert_eq!(check.read(patience(), &hidden).unwrap_err(), hides);
        let kept_out = fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied);
        let seen = check.read(patience(), &Seen::Host).unwrap_err();
        let absent = format!("no report at {path}; `garrison backup-check restic` writes it");
        assert_eq!(seen, if kept_out { hides } else { absent }, "{path}");
    }
}

/// A report whose file system gives no answer in the check's time, as one
/// on a hard NFS mount whose server is gone, leaves the card Unknown with
/// that said: here the time is past before the report is asked for.
#[test]
fn a_report_whose_file_system_does_not_answer_says_so() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restic.json");
    fs::write(&path, "{}").unwrap();
    let check = provider(&path.display().to_string());
    assert_eq!(
        check.read(Instant::now(), &Seen::Host).unwrap_err(),
        format!(
            "the report at {} could not be read: its file system did not answer within 8 seconds",
            path.display()
        )
    );
}
