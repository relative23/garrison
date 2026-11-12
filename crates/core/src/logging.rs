//! Log lines for the journal: `LEVEL component: message`.
//!
//! systemd adds timestamps. Messages never contain secrets or message content.
//! Third-party crates log only warnings and errors unless `verbose` is set.

use std::io::Write;

use log::{Level, LevelFilter, Log, Metadata, Record};

struct Journal {
    verbose: bool,
    /// Prefix each line with `<N>` so journald files it under its priority.
    priorities: bool,
}

const OWN: &str = "garrison";

impl Log for Journal {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        let own = metadata.target().starts_with(OWN);
        match (own, self.verbose) {
            (_, true) => true,
            (true, false) => metadata.level() <= Level::Info,
            (false, false) => metadata.level() <= Level::Warn,
        }
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let prefix = if self.priorities {
            format!("<{}>", priority(record.level()))
        } else {
            String::new()
        };
        let line = format!(
            "{prefix}{} {}: {}\n",
            level_name(record.level()),
            component(record.target()),
            record.args()
        );
        // A failed write to the journal cannot be reported anywhere else.
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }

    fn flush(&self) {
        let _ = std::io::stderr().lock().flush();
    }
}

/// Level names as the journal shows them.
fn level_name(level: Level) -> &'static str {
    match level {
        Level::Error => "ERROR",
        Level::Warn => "WARNING",
        Level::Info => "INFO",
        Level::Debug | Level::Trace => "DEBUG",
    }
}

/// The syslog priority journald reads from a `<N>` prefix.
fn priority(level: Level) -> u8 {
    match level {
        Level::Error => 3,
        Level::Warn => 4,
        Level::Info => 6,
        Level::Debug | Level::Trace => 7,
    }
}

/// Whether `stream` (`$JOURNAL_STREAM`, "device:inode") names this stderr.
fn is_journal(stream: &str, device: u64, inode: u64) -> bool {
    stream
        .split_once(':')
        .is_some_and(|(stream_device, stream_inode)| {
            stream_device.parse() == Ok(device) && stream_inode.parse() == Ok(inode)
        })
}

/// systemd sets `$JOURNAL_STREAM` for a service whose output it records.
fn stderr_is_journal() -> bool {
    let Some(stream) = std::env::var_os("JOURNAL_STREAM") else {
        return false;
    };
    let Ok(stat) = rustix::fs::fstat(std::io::stderr()) else {
        return false;
    };
    stream
        .to_str()
        .is_some_and(|stream| is_journal(stream, stat.st_dev, stat.st_ino))
}

/// `garrison_ingest::app` becomes `garrison.ingest.app`.
fn component(target: &str) -> String {
    match target.strip_prefix("garrison_") {
        Some(rest) => format!("{OWN}.{}", rest.replace("::", ".")),
        None => target.replace("::", "."),
    }
}

/// Install the logger once per process; later calls change nothing.
pub fn init(verbose: bool) {
    let filter = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let journal = Journal {
        verbose,
        priorities: stderr_is_journal(),
    };
    if log::set_boxed_logger(Box::new(journal)).is_ok() {
        log::set_max_level(filter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_are_dotted_paths() {
        assert_eq!(component("garrison_ingest::app"), "garrison.ingest.app");
        assert_eq!(component("garrison_core"), "garrison.core");
        assert_eq!(component("ureq::unversioned"), "ureq.unversioned");
        assert_eq!(level_name(Level::Warn), "WARNING");
    }

    #[test]
    fn priorities_reach_journald_only_through_its_own_stream() {
        assert_eq!(priority(Level::Error), 3);
        assert_eq!(priority(Level::Warn), 4);
        assert_eq!(priority(Level::Info), 6);
        assert_eq!(priority(Level::Trace), 7);
        assert!(is_journal("64768:12345", 64768, 12345));
        assert!(!is_journal("64768:12345", 64768, 12346));
        assert!(!is_journal("64768", 64768, 12345));
        assert!(!is_journal("", 0, 0));
    }

    #[test]
    fn libraries_are_quiet_unless_verbose() {
        let quiet = Journal {
            verbose: false,
            priorities: false,
        };
        let metadata =
            |target: &'static str, level| Metadata::builder().target(target).level(level).build();
        assert!(quiet.enabled(&metadata("garrison_broker", Level::Info)));
        assert!(!quiet.enabled(&metadata("garrison_broker", Level::Debug)));
        assert!(!quiet.enabled(&metadata("ureq", Level::Info)));
        assert!(quiet.enabled(&metadata("ureq", Level::Warn)));
        let verbose = Journal {
            verbose: true,
            priorities: false,
        };
        assert!(verbose.enabled(&metadata("ureq", Level::Debug)));
    }
}
