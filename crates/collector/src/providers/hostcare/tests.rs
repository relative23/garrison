use std::fs;
use std::io;
use std::path::Path;

use serde_json::json;

use super::*;
use crate::command::{Output, Runner};
use crate::context::Memory;
use crate::testing::{Remembered, config, now, table};

/// Answers each program with its own output and exit code; a program that
/// is not listed cannot be run.
struct Programs(
    Vec<(&'static str, i32, &'static str)>,
    std::cell::RefCell<Vec<String>>,
);

impl Programs {
    fn new(answers: Vec<(&'static str, i32, &'static str)>) -> Self {
        Programs(answers, std::cell::RefCell::default())
    }

    /// How often a program was run.
    fn runs(&self, program: &str) -> usize {
        self.1
            .borrow()
            .iter()
            .filter(|run| run.starts_with(program))
            .count()
    }
}

impl Runner for Programs {
    fn run(&self, arguments: &[&str]) -> io::Result<Output> {
        let line = arguments.join(" ");
        self.1.borrow_mut().push(line.clone());
        self.0
            .iter()
            .find(|(start, ..)| line.starts_with(start))
            .map(|(_, code, stdout)| Output {
                code: Some(*code),
                stdout: (*stdout).to_owned(),
            })
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}

/// A host below `root` with the given files, each empty unless it has text.
fn host(root: &Path, files: &[(&str, &str)]) {
    for (path, text) in files {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
}

fn provider(root: &Path, checks: &str) -> HostCare {
    HostCare::new(&table(&format!(
        "type = \"host-care\"\nroot = \"{}\"\nchecks = [{checks}]",
        root.display()
    )))
    .unwrap()
}

/// The one observation of a provider with a single check, `at` seconds
/// after the tests' clock.
fn checked(provider: &HostCare, runner: &dyn Runner, memory: &Remembered, at: i64) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + at).unwrap(),
        memory,
        ..crate::testing::context(&config, runner)
    };
    let mut observations = provider.collect(&context).unwrap().observations;
    assert_eq!(observations.len(), 1);
    observations.remove(0)
}

fn field<'a>(observation: &'a Observation, label: &str) -> &'a serde_json::Value {
    &observation
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
}

const APT: &str = "Inst zlib1g [1.3] (1.3+deb13u1 Debian-Security:13/stable-security [amd64])\n\
    Inst curl [8.14] (8.14+b1 Debian:13.2/stable [amd64])\n";

#[test]
fn pending_security_updates_are_a_warning_and_asked_for_every_six_hours() {
    let root = tempfile::tempdir().unwrap();
    host(root.path(), &[("usr/bin/apt-get", "")]);
    let runner = Programs::new(vec![(
        "apt-get -s -o Debug::NoLocking=true upgrade",
        0,
        APT,
    )]);
    let provider = provider(root.path(), "\"updates\"");
    let memory = Remembered::default();
    let first = checked(&provider, &runner, &memory, 0);
    assert_eq!(first.id, "host.updates");
    assert_eq!(first.state, State::Warning);
    assert_eq!(first.findings, ["1 security update is pending."]);
    assert_eq!(field(&first, "Security updates"), &json!(1));
    assert_eq!(field(&first, "Other updates"), &json!(1));
    assert_eq!(first.source, "apt-get -s upgrade");
    // A minute and nearly six hours later the answer is the kept one.
    for later in [60, ASK_EVERY - 1] {
        assert_eq!(
            checked(&provider, &runner, &memory, later).state,
            State::Warning
        );
    }
    assert_eq!(runner.runs("apt-get"), 1);
    checked(&provider, &runner, &memory, ASK_EVERY);
    assert_eq!(runner.runs("apt-get"), 2);
}

#[test]
fn dnf_is_read_from_its_cache_and_updates_without_security_are_in_order() {
    let root = tempfile::tempdir().unwrap();
    host(root.path(), &[("usr/bin/dnf", "")]);
    let quiet = Programs::new(vec![
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp updateinfo list --security --updates",
            0,
            "",
        ),
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp check-update",
            100,
            "\ncurl.x86_64  8.12  baseos\n",
        ),
    ]);
    let provider = provider(root.path(), "\"updates\"");
    let observation = checked(&provider, &quiet, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Ok);
    assert_eq!(observation.findings, Vec::<String>::new());
    assert_eq!(field(&observation, "Other updates"), &json!(1));

    let pending = Programs::new(vec![
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp updateinfo",
            0,
            "ALSA-2026:1 Important/Sec. curl-8.12.1-4.el10.x86_64\nALSA-2026:1 Important/Sec. libcurl-8.12.1-4.el10.x86_64\n",
        ),
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp check-update",
            100,
            "\ncurl.x86_64  8.12  baseos\nlibcurl.x86_64  8.12  baseos\nbash.x86_64  5.2  baseos\n",
        ),
    ]);
    let observation = checked(&provider, &pending, &Remembered::default(), 0);
    assert_eq!(observation.findings, ["2 security updates are pending."]);
    assert_eq!(field(&observation, "Other updates"), &json!(1));
}

#[test]
fn updates_that_cannot_be_read_are_unknown_and_asked_for_again_within_the_hour() {
    for (files, answers, problem) in [
        (
            vec![],
            vec![],
            "no package manager this check reads was found (apt, dnf 4)",
        ),
        (
            vec![("usr/bin/dnf", ""), ("usr/bin/dnf5", "")],
            vec![],
            "this check does not read dnf 5 yet",
        ),
        (
            vec![("usr/bin/apt-get", "")],
            vec![],
            "apt-get did not run: entity not found",
        ),
        (
            vec![("usr/bin/apt-get", "")],
            vec![("apt-get", 100, "")],
            "apt-get could not work out the upgrade",
        ),
        (
            vec![("usr/bin/dnf", "")],
            vec![("dnf", 1, "")],
            "dnf could not list the security updates",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        host(root.path(), &files);
        let runner = Programs::new(answers);
        let provider = provider(root.path(), "\"updates\"");
        let memory = Remembered::default();
        let observation = checked(&provider, &runner, &memory, 0);
        assert_eq!(observation.state, State::Unknown, "{problem}");
        assert_eq!(
            observation.findings,
            [format!("The pending updates are not known: {problem}.")]
        );
        let before = runner.1.borrow().len();
        checked(&provider, &runner, &memory, ASK_AGAIN - 1);
        assert_eq!(runner.1.borrow().len(), before, "{problem}");
    }
}

#[test]
fn a_marker_or_a_newer_kernel_says_that_a_restart_is_due() {
    let nothing = Programs::new(Vec::new());
    let look = |files: &[(&str, &str)]| {
        let root = tempfile::tempdir().unwrap();
        host(root.path(), files);
        checked(
            &provider(root.path(), "\"restart\""),
            &nothing,
            &Remembered::default(),
            0,
        )
    };
    let current = look(&[
        (
            "proc/sys/kernel/osrelease",
            "6.12.0-55.12.1.el10_0.x86_64\n",
        ),
        ("lib/modules/6.12.0-55.12.1.el10_0.x86_64/modules.dep", ""),
        ("lib/modules/6.12.0-55.9.1.el10_0.x86_64/modules.dep", ""),
        // What a removed kernel leaves behind is no kernel.
        ("lib/modules/6.12.0-99.el10_0.x86_64/extra/note", ""),
    ]);
    assert_eq!((current.state, current.findings.len()), (State::Ok, 0));
    assert_eq!(
        field(&current, "Newest installed kernel"),
        &json!("6.12.0-55.12.1.el10_0.x86_64")
    );

    let behind = look(&[
        ("proc/sys/kernel/osrelease", "6.12.0-55.9.1.el10_0.x86_64\n"),
        ("lib/modules/6.12.0-55.12.1.el10_0.x86_64/modules.dep", ""),
        ("lib/modules/6.12.0-55.9.1.el10_0.x86_64/modules.dep", ""),
    ]);
    assert_eq!(behind.state, State::Warning);
    assert_eq!(
        behind.findings,
        [
            "Kernel 6.12.0-55.12.1.el10_0.x86_64 is installed and 6.12.0-55.9.1.el10_0.x86_64 runs: a restart of the host is due."
        ]
    );

    let marked = look(&[
        ("proc/sys/kernel/osrelease", "6.12.57+deb13-amd64\n"),
        ("run/reboot-required", "*** System restart required ***\n"),
        (
            "run/reboot-required.pkgs",
            "libc6\nlinux-image-amd64\nlibc6\n",
        ),
    ]);
    assert_eq!(marked.state, State::Warning);
    assert_eq!(
        marked.findings,
        ["Installed updates need a restart of the host (libc6, linux-image-amd64)."]
    );

    // In a container the kernel is the host's own: nothing is installed here.
    let container = look(&[("proc/sys/kernel/osrelease", "6.12.57\n")]);
    assert_eq!(container.state, State::Ok);
    assert_eq!(look(&[]).state, State::Unknown);
}

#[test]
fn the_clock_is_what_timedatectl_says() {
    let root = tempfile::tempdir().unwrap();
    let provider = provider(root.path(), "\"clock\"");
    for (answers, state) in [
        (vec![("timedatectl show", 0, "yes\n")], State::Ok),
        (vec![("timedatectl show", 0, "no\n")], State::Warning),
        (vec![("timedatectl show", 1, "")], State::Unknown),
        (vec![], State::Unknown),
    ] {
        let observation = checked(
            &provider,
            &Programs::new(answers),
            &Remembered::default(),
            0,
        );
        assert_eq!(observation.state, state);
        assert_eq!(observation.findings.is_empty(), state == State::Ok);
    }
}

#[test]
fn a_firewall_service_that_runs_is_named_and_none_is_a_warning() {
    let root = tempfile::tempdir().unwrap();
    let provider = provider(root.path(), "\"firewall\"");
    let look = |answers| {
        checked(
            &provider,
            &Programs::new(answers),
            &Remembered::default(),
            0,
        )
    };
    let one = look(vec![(
        "systemctl is-active firewalld.service nftables.service ufw.service",
        3,
        "inactive\nactive\ninactive\n",
    )]);
    assert_eq!(one.state, State::Ok);
    assert_eq!(field(&one, "Active"), &json!("nftables"));
    let none = look(vec![(
        "systemctl is-active",
        3,
        "inactive\ninactive\ninactive\n",
    )]);
    assert_eq!(none.state, State::Warning);
    assert!(none.findings[0].starts_with("No firewall service is active"));
    assert!(none.findings[0].ends_with("name that unit in firewall_units."));
    assert_eq!(look(vec![]).state, State::Unknown);
}

#[test]
fn units_of_the_hosts_own_take_the_place_of_the_known_firewall_services() {
    // A host whose own unit loads its nftables rules, like the reference host.
    let provider = HostCare::new(&table(
        "type = \"host-care\"\nchecks = [\"firewall\"]\n\
         firewall_units = [\"mailstack-firewall.service\", \"edge-filter.service\"]",
    ))
    .unwrap();
    let look = |code, stdout| {
        checked(
            &provider,
            &Programs::new(vec![(
                "systemctl is-active mailstack-firewall.service edge-filter.service",
                code,
                stdout,
            )]),
            &Remembered::default(),
            0,
        )
    };
    let running = look(3, "active\ninactive\n");
    assert_eq!(running.state, State::Ok);
    assert_eq!(field(&running, "Active"), &json!("mailstack-firewall"));
    let stopped = look(3, "failed\ninactive\n");
    assert_eq!(stopped.state, State::Warning);
    assert_eq!(
        stopped.findings,
        ["None of the firewall units is active (mailstack-firewall, edge-filter)."]
    );
}

#[test]
fn the_disk_forecast_needs_a_day_and_warns_of_a_disk_that_fills_up() {
    let root = tempfile::tempdir().unwrap();
    let provider = HostCare::new(&table(&format!(
        "type = \"host-care\"\ndisk_path = \"{}\"\nchecks = [\"disk\"]",
        root.path().display()
    )))
    .unwrap();
    let nothing = Programs::new(Vec::new());
    let memory = Remembered::default();
    let first = checked(&provider, &nothing, &memory, 0);
    assert_eq!(first.id, "host.disk-forecast");
    assert_eq!(first.state, State::Unknown);
    assert_eq!(first.findings, ["A forecast needs a day of readings."]);
    let free = field(&first, "Free now").as_u64().unwrap();
    assert!(free > 0);
    // The readings so far say the disk loses a tenth of what is free each day.
    let start = now().as_second() - 2 * 86_400;
    let falling: Vec<Sample> = (0..48)
        .map(|hour: i64| Sample {
            at: start + hour * 3600,
            free: free + (free / 240) * u64::try_from(48 - hour).unwrap(),
        })
        .collect();
    memory.keep(DISK, &serde_json::to_string(&falling).unwrap());
    let soon_full = checked(&provider, &nothing, &memory, 0);
    assert_eq!(soon_full.state, State::Warning, "{:?}", soon_full.fields);
    assert!(soon_full.findings[0].starts_with("At the rate of the last days the disk is full in "));
    // A disk that gains space, or loses it slowly, is in order.
    let steady: Vec<Sample> = (0..48)
        .map(|hour: i64| Sample {
            at: start + hour * 3600,
            free,
        })
        .collect();
    memory.keep(DISK, &serde_json::to_string(&steady).unwrap());
    assert_eq!(checked(&provider, &nothing, &memory, 0).state, State::Ok);
}

#[test]
fn options_are_checked_and_every_check_runs_by_default() {
    let root = tempfile::tempdir().unwrap();
    let all = HostCare::new(&table("type = \"host-care\"")).unwrap();
    assert_eq!(all.checks.len(), 5);
    assert_eq!(all.firewall_units, None);
    let own = HostCare::new(&table(
        "type = \"host-care\"\nfirewall_units = [\"mailstack-firewall.service\"]",
    ))
    .unwrap();
    assert_eq!(
        own.firewall_units,
        Some(vec!["mailstack-firewall.service".to_owned()])
    );
    for wrong in [
        "checks = []",
        "checks = [\"updates\", \"updates\"]",
        "checks = [\"weather\"]",
        "checks = \"clock\"",
        "firewall_units = []",
        "firewall_units = [\"nft -f /etc/nftables.conf\"]",
        "firewall_units = [\"a.service\", \"a.service\"]",
        "firewall_units = \"a.service\"",
        // The units would never be asked for without the firewall check.
        "checks = [\"updates\"]\nfirewall_units = [\"a.service\"]",
        "other = 1",
    ] {
        assert!(
            HostCare::new(&table(&format!("type = \"host-care\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
    drop(root);
}
