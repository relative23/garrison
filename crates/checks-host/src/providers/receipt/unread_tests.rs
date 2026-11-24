//! Why a receipt that the card cannot read is not read, and what mends it.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rustix::fs::{CWD, Mode, OFlags, RenameFlags};

use super::*;
use crate::testing::{Canned, config, context, table};

/// A receipt only this user can change, whatever the umask.
fn write(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// A receipt the card cannot read says why, and what mends it: none there;
/// a folder on the way that the collector's user may not search; a file it
/// may not open, as one a job writes under umask 027 or 077 (both shown
/// without root, by mode 000); a link or no plain file; and a file too large
/// or no JSON object or list. Each is Unknown.
#[test]
fn an_unreadable_receipt_says_why_and_what_mends_it() {
    let directory = tempfile::tempdir().unwrap();
    let folder = directory.path().join("jobs");
    std::fs::create_dir(&folder).unwrap();
    let path = folder.join("receipt.json");
    let (shown, there) = (path.display().to_string(), folder.display().to_string());
    let receipt = Receipt::new(&table(&format!(
        "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{shown}\"\nmodules = [\"backups\"]"
    )))
    .unwrap();
    let (config, runner) = (config(directory.path()), Canned(String::new()));
    let card = || {
        let observation = receipt
            .collect(&context(&config, &runner))
            .unwrap()
            .observations
            .remove(0);
        assert_eq!(
            observation.state,
            State::Unknown,
            "{:?}",
            observation.findings
        );
        observation.findings
    };
    assert_eq!(
        card(),
        [format!(
            "No receipt at {shown}: the job that writes it has written none there."
        )]
    );
    let large = format!("{{\"log\": \"{}\"}}", "x".repeat(1024 * 1024));
    for written in ["", "not json", "\"a text\"", large.as_str()] {
        write(&path, written);
        assert_eq!(
            card(),
            [format!(
                "The receipt at {shown} cannot be read: it must be at most 1024 KiB of JSON, \
                 an object or a list."
            )],
            "{written:.20}"
        );
    }
    write(&path, r#"{"date": "2026-10-29T11:00:00Z"}"#);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&path).is_err() {
        assert_eq!(
            card(),
            [format!(
                "The receipt at {shown} is there, but the collector's user may not open it: \
                 let the job write it with mode 0644 (chmod 0644 {shown})."
            )]
        );
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::symlink_metadata(&path).is_err() {
        assert_eq!(
            card(),
            [format!(
                "The receipt at {shown} cannot be looked for: the collector's user may not \
                 search the folder {there}; let every user search it (chmod o+x {there})."
            )]
        );
    }
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(directory.path().join("elsewhere.json"), &path).unwrap();
    assert_eq!(
        card(),
        [format!(
            "The receipt at {shown} is a link, which is not followed: let the job write the \
             file there itself."
        )]
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(
        card(),
        [format!(
            "The receipt at {shown} is no plain file: let the job write it there as one."
        )]
    );
}

/// A user who may write the receipt's folder can put a FIFO in its place at
/// any moment, also between two looks of the card at it: no collect waits
/// for a writer, which would hold up every check after it until systemd
/// ends the run. One thread swaps the receipt, which holds no JSON, with a
/// FIFO as fast as it can while another collects.
#[test]
fn a_fifo_swapped_in_for_the_receipt_never_holds_up_a_collect() {
    const COLLECTS: usize = 2000;
    let directory = tempfile::tempdir().unwrap();
    let (path, fifo) = (
        directory.path().join("receipt.json"),
        directory.path().join("fifo"),
    );
    write(&path, "the job's log, which is no JSON");
    rustix::fs::mkfifoat(CWD, &fifo, Mode::from_raw_mode(0o644)).unwrap();
    let receipt = Receipt::new(&table(&format!(
        "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{}\"\nmodules = [\"backups\"]",
        path.display()
    )))
    .unwrap();
    let (config, runner) = (config(directory.path()), Canned(String::new()));
    let (stop, done) = (AtomicBool::new(false), AtomicUsize::new(0));
    let held_up = std::thread::scope(|scope| {
        let swapper = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                rustix::fs::renameat_with(CWD, &path, CWD, &fifo, RenameFlags::EXCHANGE).unwrap();
            }
        });
        scope.spawn(|| {
            for _ in 0..COLLECTS {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                receipt.collect(&context(&config, &runner)).unwrap();
                done.fetch_add(1, Ordering::Relaxed);
            }
        });
        let mut seen = (0, Instant::now());
        let held_up = loop {
            std::thread::sleep(Duration::from_millis(10));
            let count = done.load(Ordering::Relaxed);
            if count == COLLECTS {
                break None;
            }
            if count != seen.0 {
                seen = (count, Instant::now());
            } else if seen.1.elapsed() > Duration::from_secs(5) {
                break Some(count + 1);
            }
        };
        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();
        // A collect that waits goes on once the FIFO, at one of the two
        // names now, has a writer, so that the threads end.
        for name in [&path, &fifo] {
            let _ = rustix::fs::open(name, OFlags::WRONLY | OFlags::NONBLOCK, Mode::empty());
        }
        held_up
    });
    assert_eq!(held_up, None, "the collect that waited for a writer");
}

/// Where the collector's sandbox hides the place that holds the receipt,
/// as the collector's unit hides `/root` and `/tmp`, neither a mode nor the
/// job mends it: the card says so where the place can be neither searched
/// nor looked in. Seen as the host's, `/tmp` gets the words for the host,
/// while a home folder that this user may not search, as `/root`, is never
/// to be opened to every user: the card says that the unit hides it too.
#[test]
fn a_receipt_in_a_place_the_sandbox_hides_says_so() {
    for (path, place) in [
        ("/root/garrison-test-hidden/last.json", "/root"),
        ("/tmp/garrison-test-hidden/last.json", "/tmp"),
    ] {
        let receipt = Receipt::new(&table(&format!(
            "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{path}\"\nmodules = [\"backups\"]"
        )))
        .unwrap();
        let hides = format!(
            "The receipt at {path} lies under {place}, which the collector's unit hides from \
             it: let the job write it where the collector sees it, as under /var/lib \
             (docs/operator/checks.md, \"Paths the collector cannot see\")."
        );
        assert_eq!(receipt.unread(Some(Path::new(place)), patience()), hides);
        let kept_out = std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let seen = receipt.unread(None, patience());
        assert_eq!(seen == hides, kept_out, "{path}: {seen}");
        assert!(!seen.contains("chmod"), "{path}: {seen}");
    }
}

/// A receipt whose file system gives no answer by the check's time, as one
/// on a hard NFS mount whose server is gone, is Unknown and says so, and
/// the looks at why it could not be read say the same: here the time is
/// past before the card begins.
#[test]
fn a_receipt_whose_file_system_does_not_answer_says_so() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("last.json");
    write(&path, r#"{"date": "2026-10-29T11:00:00Z"}"#);
    let receipt = Receipt::new(&table(&format!(
        "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{}\"\nmodules = [\"backups\"]",
        path.display()
    )))
    .unwrap();
    let (config, runner) = (config(directory.path()), Canned(String::new()));
    let silent = format!(
        "The receipt at {} could not be read: its file system did not answer within 8 seconds.",
        path.display()
    );
    let card = receipt
        .card(&context(&config, &runner), Instant::now())
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(
        (card.state, card.findings),
        (State::Unknown, vec![silent.clone()])
    );
    assert_eq!(receipt.unread(None, Instant::now()), silent);
}
