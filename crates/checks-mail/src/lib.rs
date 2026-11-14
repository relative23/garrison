//! Checks of the mail flow: the recorded events in numbers, accounts that send
//! unusually much, test messages through the server and the antivirus scanner.

pub mod providers;

// The base modules, under the names the checks were written against.
pub(crate) use garrison_checks::{context, options};

/// The checks' test helpers, with the workspace's test configuration.
#[cfg(test)]
mod testing {
    pub(crate) use garrison_checks::testing::*;
    use garrison_core::config::Config;

    pub(crate) fn config(directory: &std::path::Path) -> Config {
        garrison_testing::config(directory, "http://127.0.0.1:9")
    }

    /// What the event receiver recorded about itself in a history a test
    /// made: how many seconds before `now` it last reported, and the windows
    /// in which events were lost, as seconds before `now`.
    #[derive(Debug, Default)]
    pub(crate) struct Receiver {
        pub(crate) quiet_for: i64,
        pub(crate) lost: Vec<(i64, i64)>,
    }

    impl Receiver {
        /// Write the receiver's own tables into `db`.
        pub(crate) fn record(&self, db: &rusqlite::Connection, now: i64) {
            use garrison_core::recording::{
                self, GAPS_TABLE, HEARTBEAT_AT, METADATA_TABLE, OFFLINE,
            };
            db.execute_batch(&format!("{GAPS_TABLE};{METADATA_TABLE};"))
                .unwrap();
            recording::set(db, HEARTBEAT_AT, now - self.quiet_for).unwrap();
            for (start, end) in &self.lost {
                db.execute(
                    "INSERT INTO gaps(start_at,end_at,reason) VALUES(?,?,?)",
                    (now - start, now - end, OFFLINE),
                )
                .unwrap();
            }
        }
    }
}
