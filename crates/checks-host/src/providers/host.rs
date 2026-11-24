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
        let at = self.disk_path.display();
        let disk = rustix::fs::statvfs(&self.disk_path)
            .map_err(|error| {
                let error = io::Error::from(error);
                format!("The file system at {at} could not be measured: {error}.")
            })
            // A file system of the kernel's, such as /proc, keeps no size.
            .and_then(|stats| match stats.f_blocks {
                0 => Err(format!("The file system at {at} gives no size.")),
                _ => Ok(stats),
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

/// Whether the disk, of a size that is known, runs short.
fn disk_short(disk: &Disk) -> bool {
    ratio(disk.free, disk.total) < 0.15
}

/// The share of free inodes, where the file system counts them: btrfs,
/// which makes them as it needs them, gives no count.
fn inodes_free(disk: &Disk) -> Option<f64> {
    (disk.inodes_total > 0).then(|| 100.0 * ratio(disk.inodes_free, disk.inodes_total))
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
        let inodes = disk.and_then(inodes_free).map(|free| format!("{free:.1}%"));
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
mod tests;
