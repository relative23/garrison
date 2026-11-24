use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::json;

use super::*;

/// Replace the file, so a read-only mode from an earlier step does not block it.
fn write(path: &Path, data: &str, mode: u32) {
    fs::remove_file(path).ok();
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

const SECRET: &str = "0123456789abcdef-secret";

#[test]
fn bounded_reads_refuse_links_directories_fifos_and_large_files() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("data.json");
    write(&file, r#"{"a": 1}"#, 0o644);
    assert_eq!(read_bounded(&file, 8).unwrap(), br#"{"a": 1}"#);
    assert!(read_bounded(&file, 7).is_err());

    let link = directory.path().join("link.json");
    symlink(&file, &link).unwrap();
    assert!(read_bounded(&link, 1024).is_err());
    assert!(read_bounded(directory.path(), 1024).is_err());

    let fifo = directory.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    // Without O_NONBLOCK this open would wait for a writer forever; on a
    // thread of its own it fails the test instead of hanging it.
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || sender.send(read_bounded(&fifo, 1024).is_err()));
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)), Ok(true));
}

#[test]
fn optional_json_is_none_when_unusable() {
    let directory = tempfile::tempdir().unwrap();
    let good = directory.path().join("good.json");
    write(&good, r#"{"ok": true}"#, 0o644);
    assert_eq!(read_json(&good, 1024), Some(json!({"ok": true})));
    let duplicate = directory.path().join("duplicate.json");
    write(&duplicate, r#"{"a": 1, "a": 2}"#, 0o644);
    assert_eq!(read_json(&duplicate, 1024), None);
    assert_eq!(
        read_json(&directory.path().join("missing.json"), 1024),
        None
    );
    assert_eq!(read_json(&good, 4), None);
}

#[test]
fn private_files_must_not_be_readable_by_others() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    write(&key, &format!("{SECRET}\n"), 0o600);
    assert_eq!(read_secret(&key, Privacy::Owned).unwrap(), SECRET);

    write(&key, SECRET, 0o640);
    let error = read_secret(&key, Privacy::Owned).unwrap_err();
    assert!(
        matches!(error, ProtectedFileError::NotPrivate(_)),
        "{error}"
    );
    // A systemd credential may carry a group ACL, but never access for others.
    assert_eq!(
        read_secret(&key, Privacy::SystemdCredential).unwrap(),
        SECRET
    );
    write(&key, SECRET, 0o604);
    assert!(read_secret(&key, Privacy::SystemdCredential).is_err());

    let link = directory.path().join("link");
    write(&key, SECRET, 0o600);
    symlink(&key, &link).unwrap();
    assert!(matches!(
        read_secret(&link, Privacy::Owned),
        Err(ProtectedFileError::Unavailable(_))
    ));
}

#[test]
fn secrets_are_one_printable_line_of_sane_length() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    for invalid in [
        "short",
        "has a space inside it",
        "tab\tinside-the-secret",
        "ünïcode-secret-value",
    ] {
        write(&key, invalid, 0o600);
        let error = read_secret(&key, Privacy::Owned).unwrap_err();
        assert!(
            matches!(error, ProtectedFileError::InvalidSecret(_)),
            "{invalid}: {error}"
        );
    }
    write(&key, &"x".repeat(16385), 0o600);
    assert!(matches!(
        read_secret(&key, Privacy::Owned),
        Err(ProtectedFileError::TooLarge(_))
    ));
    // A key is never optional: an empty file holds none, as a missing one.
    for empty in ["", "\n", "  \r\n"] {
        write(&key, empty, 0o600);
        let error = read_secret(&key, Privacy::Owned).unwrap_err();
        assert!(
            matches!(error, ProtectedFileError::Empty(_)),
            "{empty:?}: {error}"
        );
        assert_eq!(
            error.to_string(),
            format!("Protected file is empty: {}", key.display())
        );
    }
}

/// What a secret's file holds, as the readers read it, for setup and
/// doctor: an empty file and one of a line end hold nothing, one that holds
/// another form or too much holds something else, and a link or a folder
/// is no file to read.
#[test]
fn a_file_holds_a_secret_only_where_a_reader_would_take_it() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    for (data, held) in [
        ("", Holds::Nothing),
        ("\n", Holds::Nothing),
        (" \r\n", Holds::Nothing),
        ("short\n", Holds::Other),
        ("has a space inside it", Holds::Other),
        (SECRET, Holds::Secret),
        (&format!("{SECRET}\n"), Holds::Secret),
        (&"x".repeat(16385), Holds::Other),
    ] {
        // Whoever may read it: setup asks before it writes the file anew.
        write(&key, data, 0o644);
        assert_eq!(holds(&key, Form::Token).unwrap(), held, "{data:?}");
    }
    write(&key, "pass word 1\n", 0o600);
    assert_eq!(holds(&key, Form::Password).unwrap(), Holds::Secret);
    assert_eq!(holds(&key, Form::Token).unwrap(), Holds::Other);
    let link = directory.path().join("link");
    symlink(&key, &link).unwrap();
    assert!(holds(&link, Form::Token).is_err());
    assert!(holds(directory.path(), Form::Token).is_err());
    assert!(holds(&directory.path().join("missing"), Form::Token).is_err());
}

#[test]
fn an_empty_file_holds_no_secret_and_a_password_may_hold_spaces() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("secret");
    let read = |form| read_optional_secret(&file, Privacy::Owned, form);
    for empty in ["", "\n", "  \r\n"] {
        write(&file, empty, 0o600);
        for form in [Form::Token, Form::Password, Form::Address] {
            assert_eq!(read(form).unwrap(), None, "{empty:?}");
        }
    }
    write(&file, "pass word 1\n", 0o600);
    assert_eq!(
        read(Form::Password).unwrap().as_deref(),
        Some("pass word 1")
    );
    write(&file, "pässwört", 0o600);
    assert_eq!(read(Form::Password).unwrap().as_deref(), Some("pässwört"));
    // A token keeps the stricter form of a key.
    for (text, password) in [
        ("pass word 1", true),
        ("short", true),
        ("pass\tword", false),
        ("pass\0word", false),
        ("two\nlines", false),
    ] {
        write(&file, text, 0o600);
        assert!(
            matches!(read(Form::Token), Err(ProtectedFileError::InvalidSecret(_))),
            "{text:?}"
        );
        assert_eq!(read(Form::Password).is_ok(), password, "{text:?}");
    }
    write(&file, &"x".repeat(8193), 0o600);
    assert!(read(Form::Password).is_err());
    write(&file, SECRET, 0o600);
    assert_eq!(read(Form::Token).unwrap().as_deref(), Some(SECRET));
    // An empty file is no excuse for one that others can read.
    write(&file, "", 0o644);
    assert!(matches!(
        read(Form::Password),
        Err(ProtectedFileError::NotPrivate(_))
    ));
}

#[test]
fn an_address_is_one_line_without_spaces_however_short() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("address");
    let read = || read_optional_secret(&file, Privacy::Owned, Form::Address);
    for text in ["https://n.sh/t\n", "https://ntfy.example.org/a-b_c?x=1"] {
        write(&file, text, 0o600);
        assert_eq!(read().unwrap().as_deref(), Some(text.trim()), "{text:?}");
    }
    for text in [
        "https://host/a b",
        "https://host/ä",
        "two\nlines",
        "tab\there",
    ] {
        write(&file, text, 0o600);
        assert!(
            matches!(read(), Err(ProtectedFileError::InvalidSecret(_))),
            "{text:?}"
        );
    }
    write(&file, &format!("https://host/{}", "x".repeat(8192)), 0o600);
    assert!(read().is_err());
}

#[test]
fn protected_files_must_not_be_writable_or_world_readable() {
    let directory = tempfile::tempdir().unwrap();
    let policy = directory.path().join("policy.json");
    for mode in [0o400, 0o600, 0o640] {
        write(&policy, r#"{"schemaVersion": 1}"#, mode);
        assert_eq!(
            read_protected(&policy, 1024).unwrap(),
            json!({"schemaVersion": 1})
        );
    }
    for mode in [0o620, 0o644, 0o602] {
        write(&policy, "{}", mode);
        let error = read_protected(&policy, 1024).unwrap_err();
        assert!(
            matches!(error, ProtectedFileError::TooOpen(_)),
            "{mode:o}: {error}"
        );
    }
    write(&policy, r#"{"a": 1, "a": 2}"#, 0o600);
    assert!(matches!(
        read_protected(&policy, 1024),
        Err(ProtectedFileError::InvalidJson(_))
    ));
    write(&policy, "{not json}", 0o600);
    assert_eq!(
        read_protected(&policy, 1024).unwrap_err().to_string(),
        format!("Protected file is not valid JSON: {}", policy.display())
    );
    // Too large is its own reason, also when the file is valid JSON.
    write(&policy, r#"{"a": 1}"#, 0o600);
    assert!(matches!(
        read_protected(&policy, 4),
        Err(ProtectedFileError::TooLarge(_))
    ));
    assert_eq!(
        read_protected(&policy, 4).unwrap_err().to_string(),
        format!("Protected file is too large: {}", policy.display())
    );
    // The limit is exact, even when the first `limit` bytes are valid JSON.
    write(&policy, r#"{"a":1}"#, 0o600);
    assert_eq!(read_protected(&policy, 7).unwrap(), json!({"a": 1}));
    write(&policy, "{} ", 0o600);
    assert_eq!(read_protected(&policy, 3).unwrap(), json!({}));
    assert!(matches!(
        read_protected(&policy, 2),
        Err(ProtectedFileError::TooLarge(_))
    ));
}

#[test]
fn atomic_writes_replace_the_file_with_the_requested_mode() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("nested/out.json");
    atomic_write(&target, b"first", 0o640).unwrap();
    atomic_write(&target, b"second", 0o600).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"second");
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let leftovers: Vec<_> = fs::read_dir(target.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".pending-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn only_root_or_this_user_may_be_able_to_change_trusted_json() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("receipt.json");
    let trusted = |mode| {
        write(&path, r#"{"result": "passed"}"#, mode);
        let (value, metadata) = read_json_with_metadata(&path, 1024).unwrap();
        assert_eq!(value, json!({"result": "passed"}));
        changed_only_by_trusted(&metadata)
    };
    assert!(trusted(0o644));
    assert!(trusted(0o600));
    // Group write access is trusted only for the root group.
    let group_is_root = fs::metadata(&path).unwrap().gid() == 0;
    assert_eq!(trusted(0o664), group_is_root);
    assert!(!trusted(0o646));
    // Links are not followed, as for every bounded read.
    let link = directory.path().join("link.json");
    symlink(&path, &link).unwrap();
    assert!(read_json_with_metadata(&link, 1024).is_none());
    assert!(read_json_with_metadata(&path, 4).is_none());
}

/// A call that answers in time gives its answer. One on a file system that
/// does not answer, here the open of a named pipe that has no writer, is
/// given up by its time: the caller goes on, and the call is left to end by
/// itself, as it does once the pipe has a writer.
#[test]
fn a_call_on_a_file_system_is_waited_for_until_its_time() {
    let soon = Instant::now() + Duration::from_secs(5);
    assert_eq!(answered_by(soon, || 42).unwrap(), 42);
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("fifo");
    rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::from_raw_mode(0o600)).unwrap();
    let (opened, ended) = mpsc::channel();
    let waiting = fifo.clone();
    let started = Instant::now();
    let error = answered_by(started + Duration::from_millis(200), move || {
        let open = File::open(&waiting).map(drop);
        let _ = opened.send(());
        open
    })
    .unwrap_err();
    let took = started.elapsed();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(took < Duration::from_secs(2), "{took:?}");
    let until = Instant::now() + Duration::from_secs(5);
    let _writer = loop {
        match rustix::fs::open(&fifo, OFlags::WRONLY | OFlags::NONBLOCK, Mode::empty()) {
            Ok(writer) => break writer,
            Err(error) => assert!(Instant::now() < until, "{error}"),
        }
        thread::sleep(Duration::from_millis(10));
    };
    ended.recv_timeout(Duration::from_secs(5)).unwrap();
}

/// Nothing is asked once the time is past.
#[test]
fn nothing_is_asked_once_its_time_is_past() {
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&asked);
    let past = Instant::now();
    let error = answered_by(past, move || {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    thread::sleep(Duration::from_millis(50));
    assert!(!asked.load(std::sync::atomic::Ordering::SeqCst));
}
