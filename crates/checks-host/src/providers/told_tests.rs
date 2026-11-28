//! The rule of a card that is told. A notification carries a card's title,
//! its state and its first finding, so a card that is a warning or failed
//! says first what made it so. Held over every card the checks of this crate
//! report: each way a card is told, beside what else it says; a card that
//! is never told is named with why. A card of these checks that is in
//! neither list fails here.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use garrison_core::observations::{Observation, State};
use garrison_testing::http::{answer, serve};
use serde_json::json;

use super::kinds_tests::{Answers, Missing, cards, file};
use super::*;
use crate::context::{Context, Memory, Provider};
use crate::testing::{Canned, Remembered, config, context, now, table};

/// A way of a card to be told: the card, and the words its first finding
/// holds where it names what made the card's state. A card with no words
/// here is told by its title and state alone, and has no finding at all.
struct Told {
    what: &'static str,
    card: Observation,
    cause: &'static str,
}

fn only(mut cards: Vec<Observation>) -> Observation {
    assert_eq!(cards.len(), 1);
    cards.remove(0)
}

/// A moment `ago` seconds before the tests' clock, as a report writes it.
fn at(ago: i64) -> String {
    let then = garrison_core::time::Timestamp::from_second(now().as_second() - ago).unwrap();
    garrison_core::time::isoformat(then)
}

/// The resources card where a twentieth of the memory is available and the
/// load is not there to read. The disk of the machine the tests run on may
/// be short as well: either says what runs short.
fn resources() -> Vec<Told> {
    let directory = tempfile::tempdir().unwrap();
    let proc = directory.path();
    fs::write(
        proc.join("meminfo"),
        "MemTotal: 1048576 kB\nMemAvailable: 52428 kB\n",
    )
    .unwrap();
    fs::write(proc.join("uptime"), "3600.9 100.0\n").unwrap();
    let raw = format!("proc = \"{0}\"\ndisk_path = \"{0}\"", proc.display());
    let host = Host::new(&table(&raw)).unwrap();
    vec![Told {
        what: "memory that runs short, where the load could not be read",
        card: only(cards(&host, &Canned(String::new()))),
        cause: "Less than 1",
    }]
}

/// The five cards of host care, each with what makes it a warning.
fn care() -> Vec<Told> {
    let root = tempfile::tempdir().unwrap();
    let below = |path: &str| root.path().join(path);
    let of = |folder: &str, check: &str| {
        let disk = if check == "disk" {
            format!("disk_path = \"{}\"\n", root.path().display())
        } else {
            String::new()
        };
        HostCare::new(&table(&format!(
            "type = \"host-care\"\nroot = \"{}\"\n{disk}checks = [\"{check}\"]",
            below(folder).display()
        )))
        .unwrap()
    };
    fs::create_dir_all(below("plain")).unwrap();
    // apt lists no update, from lists it last fetched eight days ago.
    file(&below("apt/usr/bin/apt-get"), "");
    file(
        &below("apt/var/lib/apt/lists/a_main_binary-amd64_Packages"),
        "",
    );
    let partial = below("apt/var/lib/apt/lists/partial");
    fs::create_dir_all(&partial).unwrap();
    let seconds = u64::try_from(now().as_second() - 8 * 86_400).unwrap();
    fs::File::open(&partial)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
    let nothing = Answers(vec![(
        "apt-get -s -o Debug::NoLocking=true dist-upgrade",
        "",
    )]);
    // The distribution's marker of a restart that is due.
    file(&below("marked/run/reboot-required"), "");
    file(
        &below("marked/proc/sys/kernel/osrelease"),
        "6.12.57+deb13-amd64\n",
    );
    // Two days of readings in which the disk loses a tenth of what is free
    // each day.
    let disk = rustix::fs::statvfs(root.path()).unwrap();
    let free = disk.f_bavail.saturating_mul(disk.f_frsize);
    let start = now().as_second() - 2 * 86_400;
    let falling: Vec<serde_json::Value> = (0..48)
        .map(|hour: i64| {
            let more = (free / 240) * u64::try_from(48 - hour).unwrap();
            json!({"at": start + hour * 3600, "free": free + more})
        })
        .collect();
    let memory = Remembered::default();
    memory.keep("hostcare.disk", &json!(falling).to_string());
    let folder = tempfile::tempdir().unwrap();
    let settings = config(folder.path());
    let remembering = Context {
        memory: &memory,
        ..context(&settings, &Missing)
    };
    let forecast = of("plain", "disk").collect(&remembering).unwrap();
    let inactive = Canned("inactive\ninactive\ninactive\n".to_owned());
    vec![
        Told {
            what: "package lists that apt has not fetched for eight days",
            card: only(cards(&of("apt", "updates"), &nothing)),
            cause: "apt has not fetched its package lists for 8 days",
        },
        Told {
            what: "installed updates that need a restart",
            card: only(cards(&of("marked", "restart"), &Missing)),
            cause: "Installed updates need a restart of the host",
        },
        Told {
            what: "a clock that no time server sets",
            card: only(cards(&of("plain", "clock"), &Canned("no\n".to_owned()))),
            cause: "The clock is not synchronised with a time server.",
        },
        Told {
            what: "a disk that fills up within days",
            card: only(forecast.observations),
            cause: "At the rate of the last days the disk is full in ",
        },
        Told {
            what: "no firewall unit that is active",
            card: only(cards(&of("plain", "firewall"), &inactive)),
            cause: "No firewall service is active",
        },
    ]
}

/// A receipt that is two hours too old and whose result is a failure: the
/// failure makes the card failed, where the age alone would make it a
/// warning.
fn receipt() -> Vec<Told> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restore.json");
    let document = json!({"date": at(32 * 3600), "result": "failed"});
    file(&path, &document.to_string());
    let receipt = Receipt::new(&table(&format!(
        "type = \"receipt\"\nid = \"restore\"\ntitle = \"Restore\"\npath = \"{}\"\n\
         modules = [\"backups\"]\nmax_age_hours = 30\n\
         ok_when = {{ key = \"result\", equals = [\"passed\"] }}",
        path.display()
    )))
    .unwrap();
    vec![Told {
        what: "a receipt of a failure that is also too old",
        card: only(cards(&receipt, &Missing)),
        cause: "The recorded result is not a success.",
    }]
}

/// A repository whose newest snapshot is too old and whose integrity check
/// failed: the failed check makes the card failed, where the snapshot's age
/// alone would make it a warning.
fn backup() -> Vec<Told> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restic.json");
    let day = 86_400;
    let report = json!({
        "tool": "restic", "repository": "/srv/restic", "repositoryId": "477c", "problem": null,
        "snapshots": {"at": at(3600), "count": 14, "newest": at(3 * day), "sizeBytes": 52_428_800},
        "verify": {"at": at(3600), "ok": false, "detail": "pack 1a2b is damaged"},
        "restore": {"at": at(3 * day), "ok": true, "detail": "/var/vmail/a: 12 files, 4096 bytes"},
    });
    file(&path, &report.to_string());
    let check = BackupCheck::new(&table(&format!(
        "type = \"backup-check\"\npath = \"{}\"\nverify_days = 7",
        path.display()
    )))
    .unwrap();
    vec![Told {
        what: "a failed integrity check beside a newest snapshot that is too old",
        card: only(cards(&check, &Missing)),
        cause: "The last integrity check failed: pack 1a2b is damaged.",
    }]
}

/// A unit that failed, which its card tells by its state alone, and a job
/// whose last run is three days old where one a day is expected.
fn units() -> Vec<Told> {
    let failed = Systemd::new(&table(
        "units = [{ unit = \"a.service\", label = \"A\", modules = [\"services\"] }]",
    ))
    .unwrap();
    let job = Systemd::new(&table(
        "units = [{ unit = \"job.service\", label = \"Job\", modules = [\"services\"], \
         expect = \"idle\", max_age_hours = 24 }]",
    ))
    .unwrap();
    let shown = |unit: &str, active: &str, result: &str| {
        Canned(format!(
            "Id={unit}\nNames={unit}\nLoadState=loaded\nActiveState={active}\nSubState=dead\n\
             Result={result}\nExecMainStartTimestamp=Mon 2026-10-26 02:00:00 UTC\n\
             ExecMainExitTimestamp=Mon 2026-10-26 02:00:05 UTC\nExecMainStatus=0\n"
        ))
    };
    vec![
        Told {
            what: "a unit that failed",
            card: only(cards(&failed, &shown("a.service", "failed", "exit-code"))),
            cause: "",
        },
        Told {
            what: "a job whose last run is three days old",
            card: only(cards(&job, &shown("job.service", "inactive", "success"))),
            cause: "The last run is older than 24 hours.",
        },
    ]
}

/// An endpoint that answers with another status than the one expected.
fn endpoint() -> Vec<Told> {
    let server = serve(vec![answer(500, "")]);
    let http = Http::new(&table(&format!(
        "id = \"x\"\ntitle = \"X\"\nurl = \"{}/\"",
        server.url
    )))
    .unwrap();
    let card = only(cards(&http, &Missing));
    server.requests();
    vec![Told {
        what: "an endpoint that answers 500",
        card,
        cause: "Answered HTTP 500, expected 200.",
    }]
}

/// A plugin's bundle that is not the one its registry records.
fn plugins() -> Vec<Told> {
    let directory = tempfile::tempdir().unwrap();
    let folder = directory.path().join("plugins");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("spam.js"), "changed").unwrap();
    let plugin = json!({"id": "spam", "version": "1.2.3", "enabled": true,
                        "bundleHash": "0".repeat(64)});
    let registry = json!({"plugins": [plugin]});
    fs::write(folder.join("registry.json"), registry.to_string()).unwrap();
    let bulwark = Bulwark::new(&table(&format!(
        "admin_directory = \"{}\"\nplugins = [\"spam\"]",
        directory.path().display()
    )))
    .unwrap();
    vec![Told {
        what: "a plugin bundle that is not the recorded one",
        card: only(cards(&bulwark, &Missing)),
        cause: "spam",
    }]
}

/// The cards that are never told, each with why.
const NEVER_TOLD: [(&str, &str); 1] = [(
    "version.c",
    "shows a version and judges none: OK or Unknown",
)];

fn ids_of(provider: &dyn Provider) -> Vec<String> {
    provider.ids()
}

#[test]
fn every_card_that_is_told_says_first_what_made_it_so() {
    let mut broken = Vec::new();
    let mut covered: BTreeSet<String> = NEVER_TOLD.iter().map(|(id, _)| (*id).to_owned()).collect();
    let ways = [
        resources(),
        care(),
        receipt(),
        backup(),
        units(),
        endpoint(),
        plugins(),
    ];
    for way in ways.into_iter().flatten() {
        covered.insert(way.card.id.clone());
        let told = matches!(way.card.state, State::Warning | State::Failed);
        let first = way.card.findings.first().map_or("", String::as_str);
        let says = if way.cause.is_empty() {
            way.card.findings.is_empty()
        } else {
            first.contains(way.cause)
        };
        if !told || !says {
            broken.push(format!(
                "{}: {:?} {:?}",
                way.what, way.card.state, way.card.findings
            ));
        }
    }
    assert_eq!(broken, Vec::<String>::new());
    // Every card of the checks is in one list or the other.
    let root = Path::new("/");
    let care = HostCare::new(&table(&format!(
        "type = \"host-care\"\nroot = \"{}\"",
        root.display()
    )))
    .unwrap();
    let version = VersionCommand::new(&table(
        "component = \"C\"\ncommand = [\"/usr/bin/c\", \"--version\"]",
    ))
    .unwrap();
    let ids: BTreeSet<String> = [
        ids_of(&Host::new(&table("")).unwrap()),
        ids_of(&care),
        vec![
            "receipt.restore".to_owned(),
            "backup-check.restic".to_owned(),
            "systemd.a.service".to_owned(),
            "systemd.job.service".to_owned(),
            "http.x".to_owned(),
            "bulwark.plugins".to_owned(),
        ],
        ids_of(&version),
    ]
    .concat()
    .into_iter()
    .collect();
    assert_eq!(covered, ids);
}
