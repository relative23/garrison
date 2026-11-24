//! Host resources from /proc and the filesystem.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::{fs, io};

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, Required, State};

use crate::context::{Collected, Context, HostPath, Provider, Report, Use};
use crate::options::{Checked, Options};

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

#[derive(Debug)]
pub struct Host {
    disk_path: PathBuf,
    proc: PathBuf,
    modules: BTreeSet<ModuleId>,
}

/// What one source gave, or what the card says of why it gave nothing.
type Read<T> = Result<T, String>;

/// Each source of the card on its own, so that one that cannot be read
/// costs only its own values.
struct Reading {
    memory: Read<BTreeMap<String, u64>>,
    load: Read<[f64; 3]>,
    uptime: Read<u64>,
    disk: Read<Disk>,
}

/// The file system at `disk_path`, as statvfs gives it.
struct Disk {
    total: u64,
    free: u64,
    inodes_free: u64,
    inodes_total: u64,
}

/// meminfo's values in bytes, by their keys; a line without a number is
/// left out.
fn meminfo(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let kib: u64 = value.split_whitespace().next()?.parse().ok()?;
            Some((key.to_owned(), kib.checked_mul(1024)?))
        })
        .collect()
}

/// The three load averages that loadavg begins with.
fn loadavg(text: &str) -> Option<[f64; 3]> {
    let mut parts = text.split_whitespace();
    let mut load = [0.0; 3];
    for slot in &mut load {
        *slot = parts.next()?.parse().ok()?;
    }
    Some(load)
}

/// The whole seconds since the host started, which uptime begins with.
fn uptime(text: &str) -> Option<u64> {
    let seconds: f64 = text.split_whitespace().next()?.parse().ok()?;
    // Whole seconds, truncated.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(seconds.max(0.0) as u64)
}

impl Host {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["disk_path", "proc", "modules"])?;
        Ok(Host {
            disk_path: options.path("disk_path", Some("/"))?,
            proc: options.path("proc", Some("/proc"))?,
            modules: options.modules(&["dashboard", "services"])?,
        })
    }

    fn read(&self) -> Reading {
        let text = |name: &str| {
            fs::read_to_string(self.proc.join(name))
                .map_err(|error| format!("{name} could not be read: {error}."))
        };
        let parsed = |name: &str| format!("{name} holds no value this check reads.");
        let disk = rustix::fs::statvfs(&self.disk_path).map_err(|error| {
            format!(
                "The file system at {} could not be measured: {}.",
                self.disk_path.display(),
                io::Error::from(error)
            )
        });
        Reading {
            memory: text("meminfo").map(|text| meminfo(&text)),
            load: text("loadavg").and_then(|text| loadavg(&text).ok_or_else(|| parsed("loadavg"))),
            uptime: text("uptime").and_then(|text| uptime(&text).ok_or_else(|| parsed("uptime"))),
            disk: disk.map(|stats| Disk {
                total: stats.f_blocks.saturating_mul(stats.f_frsize),
                free: stats.f_bavail.saturating_mul(stats.f_frsize),
                inodes_free: stats.f_favail,
                inodes_total: stats.f_files,
            }),
        }
    }
}

/// Logical CPUs this process may use.
fn cpu_count() -> Option<usize> {
    std::thread::available_parallelism().ok().map(usize::from)
}

#[allow(clippy::cast_precision_loss)]
fn ratio(part: u64, whole: u64) -> f64 {
    part as f64 / whole as f64
}

/// The memory there is and the memory available, as meminfo gives them;
/// a total of none is no total.
fn memory(memory: &BTreeMap<String, u64>) -> (Option<u64>, Option<u64>) {
    let total = memory.get("MemTotal").copied();
    let available = memory.get("MemAvailable").copied();
    (total.filter(|total| *total > 0), available)
}

/// Whether the disk (also one of unknown size) runs short.
fn disk_short(disk: &Disk) -> bool {
    disk.total == 0 || ratio(disk.free, disk.total) < 0.15
}

/// Whether the memory runs short, where meminfo gives both its total and
/// what is available.
fn memory_short(total: Option<u64>, available: Option<u64>) -> Option<bool> {
    Some(ratio(available?, total?) < 0.1)
}

/// The card's state and findings: why a source could not be read, first,
/// in the order of the sources, and then what runs short. A source that
/// could not be read, or memory that is not judged, leaves the card Partial
/// where it would be in order, and Unknown where no source could be read.
fn judged(reading: &Reading) -> (State, Vec<String>) {
    let mut findings: Vec<String> = [
        reading.memory.as_ref().err(),
        reading.load.as_ref().err(),
        reading.uptime.as_ref().err(),
        reading.disk.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect();
    let none_read = findings.len() == 4;
    let (total, available) = reading.memory.as_ref().map_or((None, None), memory);
    let short_disk = reading.disk.as_ref().is_ok_and(disk_short);
    let short_memory = memory_short(total, available);
    if short_disk {
        findings.push("Less than 15% of the disk is free.".to_owned());
    }
    if short_memory == Some(true) {
        findings.push("Less than 10% of the memory is available.".to_owned());
    } else if short_memory.is_none() && reading.memory.is_ok() {
        let missing = if total.is_none() {
            "MemTotal"
        } else {
            "MemAvailable"
        };
        findings.push(format!(
            "meminfo gives no {missing}, so the memory is not judged."
        ));
    }
    let state = if short_disk || short_memory == Some(true) {
        State::Warning
    } else if none_read {
        State::Unknown
    } else if findings.is_empty() {
        State::Ok
    } else {
        State::Partial
    };
    (state, findings)
}

impl Provider for Host {
    fn name(&self) -> &'static str {
        "host"
    }

    fn ids(&self) -> Vec<String> {
        vec!["host.resources".to_owned()]
    }

    fn paths(&self) -> Vec<HostPath<'_>> {
        vec![
            HostPath {
                option: "disk_path",
                path: &self.disk_path,
                used: Use::Measures,
            },
            HostPath {
                option: "proc",
                path: &self.proc,
                used: Use::Reads,
            },
        ]
    }

    #[allow(clippy::cast_precision_loss)]
    fn collect(&self, context: &Context<'_>) -> Collected {
        let reading = self.read();
        let (state, findings) = judged(&reading);
        let (total, available) = reading.memory.as_ref().map_or((None, None), memory);
        let disk = reading.disk.as_ref().ok();
        let load = reading.load.as_ref().ok().map(|load| {
            load.iter()
                .map(|value| format!("{value:.2}"))
                .collect::<Vec<_>>()
                .join(" / ")
        });
        let inodes = disk.map(|disk| {
            let free = 100.0 * ratio(disk.inodes_free, disk.inodes_total.max(1));
            format!("{free:.1}%")
        });
        let source = format!(
            "{proc}/meminfo, loadavg, uptime; statvfs({disk})",
            proc = self.proc.display(),
            disk = self.disk_path.display()
        );
        let observation = Observation::new(Required {
            id: "host.resources",
            provider: self.name(),
            title: "Host resources",
            modules: self.modules.iter().copied(),
            evidence: Evidence::Metric,
            state,
            checked_at: &context.checked_at(),
            source: &source,
        })?
        .with_fields(vec![
            Field::text("Architecture", std::env::consts::ARCH),
            Field::new("CPU cores", cpu_count(), Format::Number),
            Field::text("Load (1 / 5 / 15 min)", load),
            Field::new("Memory total", total, Format::Bytes),
            Field::new("Memory available", available, Format::Bytes),
            Field::new(
                "Swap total",
                reading
                    .memory
                    .as_ref()
                    .ok()
                    .and_then(|memory| memory.get("SwapTotal").copied()),
                Format::Bytes,
            ),
            Field::new("Disk total", disk.map(|disk| disk.total), Format::Bytes),
            Field::new("Disk free", disk.map(|disk| disk.free), Format::Bytes),
            Field::text("Free inodes", inodes),
            Field::new(
                "Uptime",
                reading.uptime.as_ref().ok().copied(),
                Format::Duration,
            ),
        ])
        .with_findings(findings)
        .with_max_age(180);
        let mut report = Report::of(observation);
        if let Some(disk) = disk {
            report = report.gauge("disk_free_gib", disk.free as f64 / GIB);
        }
        if let Ok(load) = &reading.load {
            report = report.gauge("load_1m", load[0]);
        }
        if let (Some(total), Some(available)) = (total, available) {
            let used = total.saturating_sub(available);
            report = report.gauge("ram_used_gib", used as f64 / GIB);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
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
        // A disk of unknown size is a warning; memory of none is not judged.
        assert_eq!((disk_short(&disk(0, 0)), judged(0, 0)), (true, None));
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
}
