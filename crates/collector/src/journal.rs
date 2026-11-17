//! What the collector's journal said, for the tests: one logger for the
//! whole test binary, since a process has only one, that keeps every line
//! with the thread that wrote it, as tests run side by side.

use std::sync::{Mutex, Once, PoisonError};
use std::thread::{self, ThreadId};

/// One line as the journal would get it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Line {
    /// The module that wrote it, such as `garrison_collector::run`.
    pub(crate) target: String,
    pub(crate) level: log::Level,
    /// The level and the text, as `WARN The collector has no API key …`.
    pub(crate) text: String,
}

/// The lines the code under test wrote, by the thread that wrote them.
struct Journal(Mutex<Vec<(ThreadId, Line)>>);

impl log::Log for Journal {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let line = Line {
            target: record.target().to_owned(),
            level: record.level(),
            text: format!("{} {}", record.level(), record.args()),
        };
        let mut lines = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        lines.push((thread::current().id(), line));
    }

    fn flush(&self) {}
}

static JOURNAL: Journal = Journal(Mutex::new(Vec::new()));
static KEPT: Once = Once::new();

/// The lines this thread wrote since the last call.
pub(crate) fn lines() -> Vec<Line> {
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
