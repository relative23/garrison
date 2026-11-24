//! Host resources from /proc and the filesystem.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

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

struct Reading {
    memory: BTreeMap<String, u64>,
    load: [f64; 3],
    uptime: u64,
    disk_total: u64,
    disk_free: u64,
    inodes_free: u64,
    inodes_total: u64,
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

    fn read(&self) -> Option<Reading> {
        let text = |name: &str| fs::read_to_string(self.proc.join(name)).ok();
        let mut memory = BTreeMap::new();
        for line in text("meminfo")?.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let kib: u64 = value.split_whitespace().next()?.parse().ok()?;
                memory.insert(key.to_owned(), kib.checked_mul(1024)?);
            }
        }
        let loadavg = text("loadavg")?;
        let mut load = [0.0; 3];
        let mut parts = loadavg.split_whitespace();
        for slot in &mut load {
            *slot = parts.next()?.parse().ok()?;
        }
        let uptime: f64 = text("uptime")?.split_whitespace().next()?.parse().ok()?;
        let stats = statvfs(&self.disk_path)?;
        Some(Reading {
            memory,
            load,
            // Whole seconds, truncated.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            uptime: uptime.max(0.0) as u64,
            disk_total: stats.f_blocks.saturating_mul(stats.f_frsize),
            disk_free: stats.f_bavail.saturating_mul(stats.f_frsize),
            inodes_free: stats.f_favail,
            inodes_total: stats.f_files,
        })
    }
}

fn statvfs(path: &Path) -> Option<rustix::fs::StatVfs> {
    rustix::fs::statvfs(path).ok()
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
fn memory(reading: &Reading) -> (Option<u64>, Option<u64>) {
    let total = reading.memory.get("MemTotal").copied();
    let available = reading.memory.get("MemAvailable").copied();
    (total.filter(|total| *total > 0), available)
}

/// Whether the disk (also one of unknown size) runs short, and whether the
/// memory does, where meminfo gives both its total and what is available.
fn shortages(reading: &Reading) -> (bool, Option<bool>) {
    let disk = reading.disk_total == 0 || ratio(reading.disk_free, reading.disk_total) < 0.15;
    let memory = match memory(reading) {
        (Some(total), Some(available)) => Some(ratio(available, total) < 0.1),
        _ => None,
    };
    (disk, memory)
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
        let base = |state, source: String| {
            Observation::new(Required {
                id: "host.resources",
                provider: self.name(),
                title: "Host resources",
                modules: self.modules.iter().copied(),
                evidence: Evidence::Metric,
                state,
                checked_at: &context.checked_at(),
                source: &source,
            })
        };
        let Some(reading) = self.read() else {
            let unknown = base(State::Unknown, self.proc.display().to_string())?
                .with_scope("Host resource files could not be read.");
            return Ok(Report::of(unknown));
        };
        let (total, available) = memory(&reading);
        let (disk_short, memory_short) = shortages(&reading);
        let mut findings = Vec::new();
        if disk_short {
            findings.push("Less than 15% of the disk is free.".to_owned());
        }
        match memory_short {
            Some(true) => findings.push("Less than 10% of the memory is available.".to_owned()),
            Some(false) => {}
            None => findings.push(format!(
                "meminfo gives no {}, so the memory is not judged.",
                if total.is_none() {
                    "MemTotal"
                } else {
                    "MemAvailable"
                }
            )),
        }
        let state = match (disk_short, memory_short) {
            (true, _) | (_, Some(true)) => State::Warning,
            (false, None) => State::Partial,
            (false, Some(false)) => State::Ok,
        };
        let load: Vec<String> = reading
            .load
            .iter()
            .map(|value| format!("{value:.2}"))
            .collect();
        let inodes = 100.0 * ratio(reading.inodes_free, reading.inodes_total.max(1));
        let source = format!(
            "{proc}/meminfo, loadavg, uptime; statvfs({disk})",
            proc = self.proc.display(),
            disk = self.disk_path.display()
        );
        let observation = base(state, source)?
            .with_fields(vec![
                Field::text("Architecture", std::env::consts::ARCH),
                Field::new("CPU cores", cpu_count(), Format::Number),
                Field::text("Load (1 / 5 / 15 min)", load.join(" / ")),
                Field::new("Memory total", total, Format::Bytes),
                Field::new("Memory available", available, Format::Bytes),
                Field::new(
                    "Swap total",
                    reading.memory.get("SwapTotal").copied(),
                    Format::Bytes,
                ),
                Field::new("Disk total", reading.disk_total, Format::Bytes),
                Field::new("Disk free", reading.disk_free, Format::Bytes),
                Field::text("Free inodes", format!("{inodes:.1}%")),
                Field::new("Uptime", reading.uptime, Format::Duration),
            ])
            .with_findings(findings)
            .with_max_age(180);
        let mut report = Report::of(observation)
            .gauge("disk_free_gib", reading.disk_free as f64 / GIB)
            .gauge("load_1m", reading.load[0]);
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

    fn reading(disk_free: u64, disk_total: u64, available: u64, total: u64) -> Reading {
        Reading {
            memory: BTreeMap::from([
                ("MemAvailable".to_owned(), available),
                ("MemTotal".to_owned(), total),
            ]),
            load: [0.0; 3],
            uptime: 0,
            disk_total,
            disk_free,
            inodes_free: 0,
            inodes_total: 0,
        }
    }

    #[test]
    fn less_than_15_percent_disk_or_10_percent_memory_is_short() {
        assert_eq!(shortages(&reading(15, 100, 10, 100)), (false, Some(false)));
        assert_eq!(shortages(&reading(14, 100, 9, 100)), (true, Some(true)));
        // A disk of unknown size is a warning; memory of none is not judged.
        assert_eq!(shortages(&reading(0, 0, 0, 0)), (true, None));
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
