//! What the collector's journal says of its API key for Stalwart: where it
//! has none, why, with the file and what makes one, once for each reason
//! and not in every run; and once that it has the key again.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, Once, PoisonError};
use std::thread::{self, ThreadId};

use super::*;
use crate::testing::{Canned, now};

/// The lines the collection runs of this test binary write about the key,
/// by the thread that wrote them, since tests run side by side.
struct Journal(Mutex<Vec<(ThreadId, String)>>);

impl log::Log for Journal {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let line = format!("{} {}", record.level(), record.args());
        if record.target() == "garrison_collector::run" && line.contains("API key") {
            let mut lines = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            lines.push((thread::current().id(), line));
        }
    }

    fn flush(&self) {}
}

static JOURNAL: Journal = Journal(Mutex::new(Vec::new()));
static KEPT: Once = Once::new();

/// The lines this thread's runs wrote about the key since the last call.
fn said() -> Vec<String> {
    KEPT.call_once(|| {
        log::set_logger(&JOURNAL).unwrap();
        log::set_max_level(log::LevelFilter::Info);
    });
    let me = thread::current().id();
    let mut lines = JOURNAL.0.lock().unwrap_or_else(PoisonError::into_inner);
    let (mine, others): (Vec<_>, Vec<_>) = lines.drain(..).partition(|(thread, _)| *thread == me);
    *lines = others;
    mine.into_iter().map(|(_, line)| line).collect()
}

fn private(path: &Path, data: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Missing, then empty, then there: the journal says each reason once, with
/// the file and what makes a key, and not again in the runs after; then
/// that the key is there again. Only the cards that need the key go
/// without it, and they say so themselves.
#[test]
fn the_journal_says_once_for_each_reason_why_the_collector_has_no_key() {
    said();
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let providers: Vec<Box<dyn Provider>> = Vec::new();
    let runner = Canned(String::new());
    let run = || {
        collect_from(&providers, &config, &credentials, &runner, now()).unwrap();
        said()
    };
    let key = credentials.path(&config.collector.native_key);
    let no_key = |why: &str| {
        vec![format!(
            "WARN The collector has no API key for Stalwart: {why}: {}; run `garrison stalwart \
             setup`, which makes it. Every card that needs it says so until then.",
            key.display()
        )]
    };
    assert_eq!(run(), no_key("Protected file is unavailable"));
    assert_eq!(run(), Vec::<String>::new());
    private(&key, "");
    assert_eq!(run(), no_key("Protected file is empty"));
    private(&key, "\n");
    assert_eq!(run(), Vec::<String>::new());
    private(&key, "collector-key-0123456789\n");
    assert_eq!(
        run(),
        [format!(
            "INFO The collector has an API key for Stalwart again, from {}",
            key.display()
        )]
    );
    assert_eq!(run(), Vec::<String>::new());
    private(&key, "short\n");
    assert_eq!(run(), no_key("Protected secret has an invalid format"));
}
