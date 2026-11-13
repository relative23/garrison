//! Host resources from /proc and the filesystem.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};

use crate::context::{Collected, Context, Provider, Report};
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

/// Whether the disk (also one of unknown size) and the memory run short.
fn shortages(reading: &Reading) -> (bool, bool) {
    let total = reading.memory.get("MemTotal").copied().unwrap_or(0);
    let available = reading.memory.get("MemAvailable").copied().unwrap_or(0);
    let disk = reading.disk_total == 0 || ratio(reading.disk_free, reading.disk_total) < 0.15;
    let memory = total > 0 && ratio(available, total) < 0.1;
    (disk, memory)
}

impl Provider for Host {
    fn name(&self) -> &'static str {
        "host"
    }

    #[allow(clippy::cast_precision_loss)]
    fn collect(&self, context: &Context<'_>) -> Collected {
        let base = |state, source: String| {
            Observation::new(
                "host.resources",
                self.name(),
                "Host resources",
                self.modules.iter().copied(),
                Evidence::Metric,
                state,
                context.checked_at(),
                source,
            )
        };
        let Some(reading) = self.read() else {
            let unknown = base(State::Unknown, self.proc.display().to_string())?
                .with_scope("Host resource files could not be read.");
            return Ok(Report::of(unknown));
        };
        let total = reading.memory.get("MemTotal").copied().unwrap_or(0);
        let available = reading.memory.get("MemAvailable").copied().unwrap_or(0);
        let (disk_short, memory_short) = shortages(&reading);
        let mut findings = Vec::new();
        if disk_short {
            findings.push("Less than 15% of the disk is free.".to_owned());
        }
        if memory_short {
            findings.push("Less than 10% of the memory is available.".to_owned());
        }
        let state = if disk_short || memory_short {
            State::Warning
        } else {
            State::Ok
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
        let used = total.saturating_sub(available);
        Ok(Report::of(observation)
            .gauge("ram_used_gib", used as f64 / GIB)
            .gauge("disk_free_gib", reading.disk_free as f64 / GIB)
            .gauge("load_1m", reading.load[0]))
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
        assert_eq!(shortages(&reading(15, 100, 10, 100)), (false, false));
        assert_eq!(shortages(&reading(14, 100, 9, 100)), (true, true));
        // A disk of unknown size is a warning; unknown memory is not.
        assert_eq!(shortages(&reading(0, 0, 0, 0)), (true, false));
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
}
