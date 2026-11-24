//! The disk forecast across a change of what it measures.

use super::*;

/// The disk forecast of the file system at `disk_path`.
fn forecast(disk_path: &Path) -> HostCare {
    HostCare::new(&table(&format!(
        "type = \"host-care\"\ndisk_path = \"{}\"\nchecks = [\"disk\"]",
        disk_path.display()
    )))
    .unwrap()
}

/// Two days of readings of one file system say nothing of another: where
/// `disk_path` changes, the forecast begins anew with the readings of the
/// file system it names now, and needs a day of them again.
#[test]
fn the_readings_of_another_file_system_are_not_carried_forward() {
    let disk = tempfile::tempdir().unwrap();
    let nothing = Programs::new(Vec::new());
    let memory = Remembered::default();
    for hour in -48..=0 {
        checked(&forecast(disk.path()), &nothing, &memory, hour * 3600);
    }
    let measured = checked(&forecast(disk.path()), &nothing, &memory, 3600);
    assert_ne!(
        measured.findings,
        ["A forecast needs a day of readings."],
        "two days were read"
    );
    let elsewhere = Path::new(env!("CARGO_MANIFEST_DIR"));
    let other = checked(&forecast(elsewhere), &nothing, &memory, 7200);
    assert_eq!(
        (other.state, other.findings),
        (
            State::Unknown,
            vec!["A forecast needs a day of readings.".to_owned()]
        )
    );
}

/// A file system that gives no size, as /proc, a file system of the
/// kernel's, does not (statfs, measured 2026-11-24), has no free space to
/// carry forward: the forecast is Unknown and says so, however many days
/// of readings it has, never in order.
#[test]
fn a_file_system_without_a_size_has_no_forecast() {
    let nothing = Programs::new(Vec::new());
    let memory = Remembered::default();
    let proc = forecast(Path::new("/proc"));
    for hour in -48..=0 {
        checked(&proc, &nothing, &memory, hour * 3600);
    }
    let card = checked(&proc, &nothing, &memory, 3600);
    assert_eq!(
        (card.state, card.findings),
        (
            State::Unknown,
            vec!["The file system gives no size.".to_owned()]
        )
    );
}
