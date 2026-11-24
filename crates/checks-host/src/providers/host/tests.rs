use super::*;
use crate::testing::{Canned, config, context, table};

fn disk(free: u64, total: u64) -> Disk {
    Disk {
        total,
        free,
        inodes_free: 0,
        inodes_total: 0,
    }
}

#[test]
fn less_than_15_percent_disk_or_10_percent_memory_is_short() {
    let judged = |available: u64, total: u64| {
        let read = BTreeMap::from([
            ("MemAvailable".to_owned(), available),
            ("MemTotal".to_owned(), total),
        ]);
        let (total, available) = memory(&read);
        memory_short(total, available)
    };
    assert_eq!(
        (disk_short(&disk(15, 100)), judged(10, 100)),
        (false, Some(false))
    );
    assert_eq!(
        (disk_short(&disk(14, 100)), judged(9, 100)),
        (true, Some(true))
    );
    // Memory of none is not judged; a disk of no size is not read as
    // one (`a_count_the_file_system_does_not_keep_is_unknown`).
    assert_eq!(judged(0, 0), None);
    let counted = |inodes_free, inodes_total| Disk {
        inodes_free,
        inodes_total,
        ..disk(15, 100)
    };
    assert_eq!(inodes_free(&counted(250, 1000)), Some(25.0));
    assert_eq!(inodes_free(&counted(0, 0)), None);
}

#[test]
fn readings_come_from_proc_and_the_configured_disk() {
    let directory = tempfile::tempdir().unwrap();
    let proc = directory.path();
    fs::write(
        proc.join("meminfo"),
        "MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n",
    )
    .unwrap();
    fs::write(proc.join("loadavg"), "0.50 0.40 0.30 1/100 1234\n").unwrap();
    fs::write(proc.join("uptime"), "3600.9 100.0\n").unwrap();
    let raw = format!("proc = \"{0}\"\ndisk_path = \"{0}\"", proc.display());
    let host = Host::new(&table(&raw)).unwrap();
    let (config, runner) = (config(proc), Canned(String::new()));
    let report = host.collect(&context(&config, &runner)).unwrap();
    let field = |label: &str| {
        let field = report.observations[0]
            .fields
            .iter()
            .find(|field| field.label == label);
        field.unwrap().value.clone()
    };
    let cores = std::thread::available_parallelism().unwrap().get();
    assert_eq!(field("CPU cores"), serde_json::json!(cores));
    assert_eq!(field("Load (1 / 5 / 15 min)"), "0.50 / 0.40 / 0.30");
    assert_eq!(field("Uptime"), 3600);
    let disk = rustix::fs::statvfs(proc).unwrap();
    let inodes: f64 = field("Free inodes")
        .as_str()
        .unwrap()
        .trim_end_matches('%')
        .parse()
        .unwrap();
    let expected = 100.0 * ratio(disk.f_favail, disk.f_files.max(1));
    assert!((inodes - expected).abs() < 0.2, "{inodes} {expected}");
    #[allow(clippy::cast_precision_loss)]
    let free = (disk.f_bavail * disk.f_frsize) as f64 / GIB;
    assert!((report.gauges["disk_free_gib"] - free).abs() < 0.01);
    assert!((report.gauges["ram_used_gib"] - 0.5).abs() < f64::EPSILON);
    assert!((report.gauges["load_1m"] - 0.5).abs() < f64::EPSILON);
}

/// A count that a file system does not keep is unknown, never 0: btrfs
/// gives no inode count, and /proc, a file system of the kernel's, no
/// size either (statfs, measured 2026-11-24), so the card shows no
/// share of free inodes there and neither judges nor shows the disk of
/// /proc. Where this test's own folder lies on btrfs, as on the host it
/// was written on, its card shows no share of free inodes.
#[test]
fn a_count_the_file_system_does_not_keep_is_unknown() {
    let card = |disk_path: &std::path::Path| {
        let directory = tempfile::tempdir().unwrap();
        let proc = directory.path();
        fs::write(
            proc.join("meminfo"),
            "MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n",
        )
        .unwrap();
        fs::write(proc.join("loadavg"), "0.50 0.40 0.30 1/100 1234\n").unwrap();
        fs::write(proc.join("uptime"), "3600.9 100.0\n").unwrap();
        let raw = format!(
            "proc = \"{}\"\ndisk_path = \"{}\"",
            proc.display(),
            disk_path.display()
        );
        let host = Host::new(&table(&raw)).unwrap();
        let (config, runner) = (config(proc), Canned(String::new()));
        host.collect(&context(&config, &runner)).unwrap()
    };
    let report = card(std::path::Path::new("/proc"));
    let proc = &report.observations[0];
    assert_eq!(
        (proc.state, proc.findings.as_slice()),
        (
            State::Partial,
            &["The file system at /proc gives no size.".to_owned()][..]
        )
    );
    let field = |card: &Observation, label: &str| {
        let field = card.fields.iter().find(|field| field.label == label);
        field.unwrap().value.clone()
    };
    for label in ["Disk total", "Disk free", "Free inodes"] {
        assert_eq!(field(proc, label), serde_json::Value::Null, "{label}");
    }
    assert!(!report.gauges.contains_key("disk_free_gib"));
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let counted = rustix::fs::statvfs(here).unwrap().f_files > 0;
    let own = card(here);
    let inodes = field(&own.observations[0], "Free inodes");
    assert_eq!(inodes.is_string(), counted, "{inodes}");
}

/// A `disk_path` that cannot be measured, as one that is not there,
/// costs the card its disk alone: the memory, the load and the uptime
/// stay, and the finding names the path and why.
#[test]
fn a_disk_that_cannot_be_measured_leaves_the_other_readings() {
    let directory = tempfile::tempdir().unwrap();
    let proc = directory.path();
    fs::write(
        proc.join("meminfo"),
        "MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n",
    )
    .unwrap();
    fs::write(proc.join("loadavg"), "0.50 0.40 0.30 1/100 1234\n").unwrap();
    fs::write(proc.join("uptime"), "3600.9 100.0\n").unwrap();
    let gone = proc.join("gone");
    let raw = format!(
        "proc = \"{}\"\ndisk_path = \"{}\"",
        proc.display(),
        gone.display()
    );
    let host = Host::new(&table(&raw)).unwrap();
    let (config, runner) = (config(proc), Canned(String::new()));
    let report = host.collect(&context(&config, &runner)).unwrap();
    let card = &report.observations[0];
    assert_eq!(
        (card.state, card.findings.as_slice()),
        (
            State::Partial,
            &[format!(
                "The file system at {} could not be measured: No such file or directory \
                 (os error 2).",
                gone.display()
            )][..]
        )
    );
    let field = |label: &str| {
        let field = card.fields.iter().find(|field| field.label == label);
        field.unwrap().value.clone()
    };
    assert_eq!(field("Memory total"), serde_json::json!(1_073_741_824));
    assert_eq!(field("Load (1 / 5 / 15 min)"), "0.50 / 0.40 / 0.30");
    assert_eq!(field("Uptime"), 3600);
    for label in ["Disk total", "Disk free", "Free inodes"] {
        assert_eq!(field(label), serde_json::Value::Null, "{label}");
    }
    let gauges: Vec<&str> = report.gauges.keys().map(String::as_str).collect();
    assert_eq!(gauges, ["load_1m", "ram_used_gib"]);
}

/// A meminfo without `MemTotal` or `MemAvailable`, as a `proc` that is not
/// the kernel's may hold, leaves the memory unknown: no 0 B, no warning
/// and no gauge, and the card says why it does not judge the memory.
#[test]
fn a_meminfo_without_its_totals_leaves_the_memory_unknown() {
    for (meminfo, missing, label) in [
        ("MemAvailable: 524288 kB\n", "MemTotal", "Memory total"),
        ("MemTotal: 1048576 kB\n", "MemAvailable", "Memory available"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let proc = directory.path();
        fs::write(proc.join("meminfo"), meminfo).unwrap();
        fs::write(proc.join("loadavg"), "0.50 0.40 0.30 1/100 1234\n").unwrap();
        fs::write(proc.join("uptime"), "3600.9 100.0\n").unwrap();
        let raw = format!("proc = \"{0}\"\ndisk_path = \"{0}\"", proc.display());
        let host = Host::new(&table(&raw)).unwrap();
        let (config, runner) = (config(proc), Canned(String::new()));
        let report = host.collect(&context(&config, &runner)).unwrap();
        let card = &report.observations[0];
        let field = card.fields.iter().find(|field| field.label == label);
        assert_eq!(field.unwrap().value, serde_json::Value::Null, "{missing}");
        let said = format!("meminfo gives no {missing}, so the memory is not judged.");
        assert!(card.findings.contains(&said), "{:?}", card.findings);
        assert!(
            !card
                .findings
                .iter()
                .any(|finding| finding.contains("memory is available")),
            "{:?}",
            card.findings
        );
        assert_ne!(card.state, State::Ok);
        assert!(!report.gauges.contains_key("ram_used_gib"), "{missing}");
    }
}

/// A file system that gives no answer by the check's time, as a hard NFS
/// mount whose server is gone, costs the card its disk alone. Here the time
/// is past before the card begins, as it is once such a mount has held the
/// look at `disk_path` for eight seconds.
#[test]
fn a_disk_that_does_not_answer_costs_the_card_its_disk_alone() {
    let directory = tempfile::tempdir().unwrap();
    let proc = directory.path();
    fs::write(
        proc.join("meminfo"),
        "MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n",
    )
    .unwrap();
    fs::write(proc.join("loadavg"), "0.50 0.40 0.30 1/100 1234\n").unwrap();
    fs::write(proc.join("uptime"), "3600.9 100.0\n").unwrap();
    let raw = format!("proc = \"{0}\"\ndisk_path = \"{0}\"", proc.display());
    let host = Host::new(&table(&raw)).unwrap();
    let (config, runner) = (config(proc), Canned(String::new()));
    let report = host
        .card(&context(&config, &runner), Instant::now())
        .unwrap();
    let card = &report.observations[0];
    assert_eq!(
        (card.state, card.findings.as_slice()),
        (
            State::Partial,
            &[format!(
                "The file system at {} did not answer within 8 seconds.",
                proc.display()
            )][..]
        )
    );
    let field = |label: &str| {
        let field = card.fields.iter().find(|field| field.label == label);
        field.unwrap().value.clone()
    };
    assert_eq!(field("Memory total"), serde_json::json!(1_073_741_824));
    assert_eq!(field("Disk total"), serde_json::Value::Null);
    let gauges: Vec<&str> = report.gauges.keys().map(String::as_str).collect();
    assert_eq!(gauges, ["load_1m", "ram_used_gib"]);
}
