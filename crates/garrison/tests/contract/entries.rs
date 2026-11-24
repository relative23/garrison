//! The macro filter's entries in every state setup meets: whether
//! garrison.toml has `[milter]`, which entries Stalwart holds and under which
//! name of this host they ask, and wherever a run stops. No run that ends in
//! success leaves Stalwart asking where no milter answers, a run that
//! refuses sends Stalwart no change and names each entry asked in vain, and
//! no run changes another program's entry. Stalwart keeps each name of this
//! host as it is written and asks it (measured here with mail), and it asks
//! its entries as it read them last. Setup runs here as a user, which cannot
//! see where a running filter listens: the states are those it tells by
//! garrison.toml and by what answers.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::Duration;

use garrison_testing::config_text;
use garrison_testing::lab::Lab;
use serde_json::{Value, json};

use super::stopper::{Stop, Stopper};
use super::{Setup, forget, lab, text};

/// The name setup writes.
pub(super) const LOOPBACK: &str = "127.0.0.1";
/// Other names of this host that Stalwart's form takes.
pub(super) const NAMES: [&str; 8] = [
    "localhost",
    "::1",
    "[::1]",
    "127.0.0.2",
    "127.1",
    "0.0.0.0",
    "LOCALHOST",
    "localhost.",
];

/// A port of this host where a milter answers, for as long as the test runs.
fn filter() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        garrison_milter::server::serve(
            &listener,
            garrison_milter::Settings {
                max_bytes: 1024,
                ..Default::default()
            },
        );
    });
    port
}

/// A port of this host where nothing listens.
fn silent() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A port of this host that another program holds, which is no milter.
fn held() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut client in listener.incoming().flatten() {
            let _ = client.write_all(b"220 no milter here\r\n");
        }
    });
    port
}

/// An entry as setup writes it, asking `host` at `port`.
pub(super) fn written(host: &str, port: u16) -> Value {
    json!({"host": host, "port": port, "enable": {"match": {}, "else": "true"},
        "stages": {"data": true}, "tempFailOnError": true})
}

/// The ports of this test.
pub(super) struct Ports {
    /// Where the macro filter answers.
    pub(super) filter: u16,
    /// Where another program's milter answers.
    pub(super) other: u16,
    /// The filter's port before it moved, where nothing answers now.
    pub(super) old: u16,
    /// Where another program's milter answered once.
    pub(super) gone: u16,
    /// Where another program answers that is no milter.
    pub(super) taken: u16,
}

impl Ports {
    fn all(&self) -> [u16; 5] {
        [self.filter, self.other, self.old, self.gone, self.taken]
    }

    /// Whether a milter answers at `host` and `port` from this host: the
    /// test's own milters are what listens at its ports, but at `taken`.
    fn answers(&self, host: &str, port: u64) -> bool {
        let Ok(port) = u16::try_from(port) else {
            return false;
        };
        port != self.taken
            && format!("{host}:{port}")
                .to_socket_addrs()
                .is_ok_and(|mut all| {
                    all.any(|address| {
                        TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok()
                    })
                })
    }
}

/// Stalwart's entries that ask this test's ports, under any name, by ID.
pub(super) fn milters(lab: &Lab, ports: &Ports) -> BTreeMap<String, Value> {
    lab.call("x:MtaMilter/get", &json!({"ids": null}))["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            ports
                .all()
                .iter()
                .any(|port| entry["port"] == u64::from(*port))
        })
        .map(|entry| (entry["id"].as_str().unwrap().to_owned(), entry.clone()))
        .collect()
}

/// Every entry of this test out of Stalwart.
fn clear(lab: &Lab, ports: &Ports) {
    let ids: Vec<String> = milters(lab, ports).into_keys().collect();
    if !ids.is_empty() {
        lab.call("x:MtaMilter/set", &json!({ "destroy": ids }));
    }
}

pub(super) fn reload(lab: &Lab) {
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
}

/// Where an entry asks, as Stalwart holds it and setup names it.
fn address(entry: &Value) -> String {
    format!(
        "{}:{}",
        entry["host"].as_str().unwrap_or("?"),
        entry["port"]
    )
}

/// The IDs of the entries of `held` that Stalwart asks in vain: switched
/// on, where no milter answers.
fn vain_ids<'a>(held: &'a BTreeMap<String, Value>, ports: &Ports) -> Vec<&'a String> {
    held.iter()
        .filter(|(_, entry)| {
            entry["enable"]["else"] != "false"
                && !ports.answers(
                    entry["host"].as_str().unwrap_or_default(),
                    entry["port"].as_u64().unwrap_or_default(),
                )
        })
        .map(|(id, _)| id)
        .collect()
}

/// Where the entries of `held` ask that Stalwart asks in vain.
pub(super) fn in_vain(held: &BTreeMap<String, Value>, ports: &Ports) -> Vec<String> {
    vain_ids(held, ports)
        .into_iter()
        .map(|id| address(&held[id]))
        .collect()
}

/// One state: garrison.toml with the filter or without, and Stalwart's
/// entries by name, the name of the host they ask and their port: `g`
/// Garrison's, `d` a second one for the filter, `o` another program's.
pub(super) struct State<'a> {
    pub(super) milter: bool,
    pub(super) entries: &'a [(&'a str, &'a str, u16)],
}

/// The configuration with Stalwart at `url` and the filter at `port`, if any.
fn settings(setup: &Setup, url: &str, port: Option<u16>) -> String {
    let base = config_text(&setup.directory, url);
    match port {
        Some(port) => format!("{base}\n[milter]\nport = {port}\n"),
        None => base,
    }
}

/// Where an earlier release kept its note of the filter's entry.
pub(super) fn note(setup: &Setup) -> std::path::PathBuf {
    setup.directory.join("credentials/stalwart-milter-id")
}

/// Bring Stalwart and the folder to `state`, as Stalwart reads them; the
/// IDs of its entries by name.
pub(super) fn arrange(
    lab: &Lab,
    setup: &Setup,
    ports: &Ports,
    state: &State<'_>,
) -> BTreeMap<String, String> {
    clear(lab, ports);
    let mut ids = BTreeMap::new();
    for (name, host, port) in state.entries {
        let made = lab.call(
            "x:MtaMilter/set",
            &json!({"create": {"n": written(host, *port)}}),
        );
        ids.insert(
            (*name).to_owned(),
            made["created"]["n"]["id"].as_str().unwrap().to_owned(),
        );
    }
    reload(lab);
    let _ = fs::remove_file(note(setup));
    let port = state.milter.then_some(ports.filter);
    fs::write(
        setup.directory.join("garrison.toml"),
        settings(setup, &lab.url, port),
    )
    .unwrap();
    ids
}

/// A setup run with the filter at `port`, if any, and `flags`, through a
/// relay that stops it at request `at` as `stop` says, or nowhere: its exit
/// code, what it said and the requests it sent.
pub(super) fn through(
    lab: &Lab,
    setup: &Setup,
    port: Option<u16>,
    at: Option<(usize, Stop)>,
    flags: &[&str],
) -> (Option<i32>, String, Vec<String>) {
    let (number, stop) = at.unwrap_or((usize::MAX, Stop::Lost));
    let relay = Stopper::new(&lab.url, number, stop);
    let path = setup.directory.join("garrison.toml");
    fs::write(&path, settings(setup, &relay.url, port)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_garrison"))
        .arg("--config")
        .arg(&path)
        .args(setup.arguments(flags))
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    relay.watch(child.id());
    let output = child.wait_with_output().unwrap();
    fs::write(&path, settings(setup, &lab.url, port)).unwrap();
    (output.status.code(), text(&output), relay.asked())
}

/// A plain run of `state`, without metrics.
pub(super) fn plain(
    lab: &Lab,
    setup: &Setup,
    ports: &Ports,
    state: &State<'_>,
    at: Option<(usize, Stop)>,
) -> (Option<i32>, String, Vec<String>) {
    let port = state.milter.then_some(ports.filter);
    through(lab, setup, port, at, &["--skip-metrics"])
}

/// The changes among the requests of a run.
pub(super) fn changes(asked: &[String]) -> Vec<&String> {
    asked
        .iter()
        .filter(|request| request.contains("/set"))
        .collect()
}

/// What is wrong after a run of `state` that ended with `code`, said `said`
/// and sent `asked`, from `before` to `after`.
pub(super) fn faults(
    state: &State<'_>,
    ports: &Ports,
    (code, said, asked): (Option<i32>, &str, &[String]),
    (before, after): (&BTreeMap<String, Value>, &BTreeMap<String, Value>),
) -> Vec<String> {
    let mut faults = Vec::new();
    if code == Some(0) {
        let vain = in_vain(after, ports);
        if !vain.is_empty() {
            faults.push(format!("success, and Stalwart asks {vain:?} in vain"));
        }
        let asking: Vec<String> = after
            .values()
            .filter(|entry| {
                entry["port"] == u64::from(ports.filter)
                    && entry["enable"]["else"] != "false"
                    && ports.answers(
                        entry["host"].as_str().unwrap_or_default(),
                        u64::from(ports.filter),
                    )
            })
            .map(address)
            .collect();
        if state.milter && asking.len() != 1 {
            faults.push(format!(
                "success with [milter], and Stalwart asks the filter at {asking:?}"
            ));
        }
    } else {
        for address in in_vain(before, ports) {
            if !said.contains(&address) {
                faults.push(format!("the refusal does not name {address}"));
            }
        }
        if !said.contains("Run `garrison stalwart setup") {
            faults.push("the refusal names no run that mends it".to_owned());
        }
        if before != after {
            faults.push("a run that refused changed Stalwart's entries".to_owned());
        }
        let changed = changes(asked);
        if !changed.is_empty() {
            faults.push(format!(
                "a run that refused sent Stalwart {changed:?} first"
            ));
        }
    }
    for (id, entry) in before {
        let others =
            entry["port"] == u64::from(ports.other) || entry["port"] == u64::from(ports.gone);
        if others && after.get(id) != Some(entry) {
            faults.push(format!("another program's entry {id} changed"));
        }
    }
    faults
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn no_run_of_setup_leaves_stalwart_asking_a_filter_in_vain() {
    let (_guard, lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    let ports = Ports {
        filter: filter(),
        other: filter(),
        old: silent(),
        gone: silent(),
        taken: held(),
    };
    clear(&lab, &ports);
    super::entry_stalwart::stalwart_asks_what_it_read_last(&lab, &ports);
    let mut found = super::entry_stalwart::every_name_is_kept_and_asked(&lab, &ports);
    let first = setup.run(&["--skip-metrics"]);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    every_state(&lab, &setup, &ports, &mut found);
    super::entry_refusals::every_refusal(&lab, &setup, &ports, &mut found);
    super::entry_stops::every_stop(&lab, &setup, &ports, &mut found);
    clear(&lab, &ports);
    reload(&lab);
    forget(&lab, &credentials);
    assert_eq!(found, Vec::<String>::new(), "{}", found.join("\n\n"));
}

/// Each state once, with a plain run; where it refuses, the run after the
/// entries it named were taken out, as the Stalwart WebUI takes them out.
fn every_state(lab: &Lab, setup: &Setup, ports: &Ports, found: &mut Vec<String>) {
    let (filter, other, old, gone) = (ports.filter, ports.other, ports.old, ports.gone);
    let mut sets: Vec<Vec<(&str, &str, u16)>> = vec![
        vec![],
        vec![("g", LOOPBACK, filter)],
        vec![("g", LOOPBACK, filter), ("d", LOOPBACK, filter)],
        vec![("g", LOOPBACK, old)],
        vec![("g", LOOPBACK, filter), ("o", LOOPBACK, other)],
        vec![("g", LOOPBACK, filter), ("o", LOOPBACK, gone)],
        vec![("o", LOOPBACK, gone)],
        vec![("g", LOOPBACK, old), ("o", LOOPBACK, other)],
    ];
    for name in NAMES {
        // The filter's entry under another name of this host, and another
        // program's under it where nothing answers.
        sets.push(vec![("g", name, filter)]);
        sets.push(vec![("g", LOOPBACK, filter), ("o", name, gone)]);
    }
    for milter in [true, false] {
        for entries in &sets {
            let state = State { milter, entries };
            let described = format!("[milter] {milter}, entries {entries:?}");
            arrange(lab, setup, ports, &state);
            let before = milters(lab, ports);
            let (code, said, asked) = plain(lab, setup, ports, &state, None);
            let after = milters(lab, ports);
            let mut wrong = faults(&state, ports, (code, &said, &asked), (&before, &after));
            if code != Some(0) && wrong.is_empty() {
                // The operator takes out what the refusal named.
                let named = vain_ids(&after, ports);
                lab.call("x:MtaMilter/set", &json!({ "destroy": named }));
                reload(lab);
                let mended = milters(lab, ports);
                let (code, again, asked) = plain(lab, setup, ports, &state, None);
                let last = milters(lab, ports);
                wrong.extend(
                    faults(&state, ports, (code, &again, &asked), (&mended, &last))
                        .into_iter()
                        .map(|fault| format!("after the named entries went: {fault}: {again}")),
                );
            }
            if !wrong.is_empty() {
                found.push(format!("{described}: {}\n{said}", wrong.join("; ")));
            }
        }
    }
}
