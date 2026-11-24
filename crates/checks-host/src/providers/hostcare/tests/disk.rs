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
/// file system it names now, and needs a day of them again. `/proc`, whose
/// free space is none, would otherwise be full at once.
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
    let other = checked(&forecast(Path::new("/proc")), &nothing, &memory, 7200);
    assert_eq!(
        (other.state, other.findings),
        (
            State::Unknown,
            vec!["A forecast needs a day of readings.".to_owned()]
        )
    );
}
