//! Garrison's own systemd units, as `deploy/systemd` ships them. Every list
//! of units in the operator commands is made of these names.

pub(crate) const WEB: &str = "garrison-web.service";
pub(crate) const INGEST: &str = "garrison-ingest.service";
/// systemd starts the broker when its socket is first used.
pub(crate) const BROKER: &str = "garrison-broker.service";
pub(crate) const BROKER_SOCKET: &str = "garrison-broker.socket";
/// One collection run; its timer starts it every minute.
pub(crate) const COLLECT: &str = "garrison-collect.service";
pub(crate) const COLLECT_TIMER: &str = "garrison-collect.timer";
/// One look at whether the collector still runs; its timer starts it every
/// five minutes.
pub(crate) const WATCH: &str = "garrison-watch.service";
pub(crate) const WATCH_TIMER: &str = "garrison-watch.timer";
/// The macro milter; it runs only where the configuration switches it on.
pub(crate) const MILTER: &str = "garrison-milter.service";
/// Where setup notes the ID of the filter's entry in Stalwart, in the
/// credentials directory. While the note is there, Stalwart asks the filter.
pub(crate) const MILTER_ENTRY: &str = "stalwart-milter-id";

/// What is active on a host where Garrison runs, in the order `detect` and
/// `doctor` name the units.
pub(crate) const RUNNING: [&str; 5] = [WEB, INGEST, BROKER_SOCKET, COLLECT_TIMER, WATCH_TIMER];
