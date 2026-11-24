//! What the status database held of a channel's address before it was kept
//! in a file. Releases before this one kept the address as `garrison.toml`
//! wrote it for the watch, and named all of it, or all of it up to its first
//! `/`, in a failure they kept, which their card and snapshots showed; this
//! one keeps an address written there for the watch. Once the address is
//! kept in a file, the next collection run leaves none of it: not on the
//! card, in no row of the status database, in none of its files' bytes, free
//! pages included, and in no line of the journal.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use garrison_core::config::{Config, Database, Endpoint};
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_core::time::Timestamp;
use rusqlite::{Connection, params};

use crate::context::{Collected, Context, Provider, Report};
use crate::run::collect_from;
use crate::snapshot::Snapshot;
use crate::store::StatusStore;
use crate::testing::{Canned, now};

/// What the address's key holds, and no other text of the test.
const MARK: &str = "Zq7Mark4Secret9x";

/// A check that reports nothing, so that no notification is due.
struct Quiet;

impl Provider for Quiet {
    fn name(&self) -> &'static str {
        "quiet"
    }

    fn collect(&self, _context: &Context<'_>) -> Collected {
        Ok(Report::default())
    }
}

/// A collection run at the second `at`.
fn run(config: &Config, credentials: &Credentials, at: i64) -> Snapshot {
    let providers: Vec<Box<dyn Provider>> = vec![Box::new(Quiet)];
    let at = Timestamp::from_second(at).unwrap();
    collect_from(&providers, config, credentials, &Canned(String::new()), at).unwrap()
}

/// A host in `directory` whose webhook keeps its address, `address`, in its
/// file, beside the empty files the installer keeps.
fn host(directory: &Path, address: &str) -> (Config, Credentials, PathBuf) {
    let mut config = crate::testing::config(directory);
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    for (name, data) in [
        ("ntfy-url", ""),
        ("ntfy-token", ""),
        ("notify-webhook-url", address),
        ("notify-webhook-token", ""),
        ("notify-mail-password", ""),
    ] {
        let file = credentials.directory().join(name);
        fs::write(&file, data).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    config.notifications.webhook_url = Some(Endpoint::File(SecretSource::Credential(
        "notify-webhook-url".into(),
    )));
    let path = config.database(Database::Status);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    (config, credentials, path)
}

/// The status database at `path` as 0.1.2 left it: the channels its last
/// run named, `channels`, the failure it kept, `problem`, and forty
/// snapshots whose card named that failure, of which the store dropped
/// thirty, so that it stands in free pages as well.
fn as_0_1_2_left_it(path: &Path, channels: &str, problem: &str) {
    drop(StatusStore::open(path, 90).unwrap());
    let db = Connection::open(path).unwrap();
    let t0 = now().as_second();
    let finding = format!("The last notification did not go out: {problem}.");
    for id in 1..=40 {
        let document = serde_json::json!({
            "observations": [{
                "id": "notifications.channels",
                "state": "failed",
                "source": "webhook at hooks.example.org",
                "findings": [finding],
            }],
            "pad": "x".repeat(3000),
        });
        db.execute(
            "INSERT INTO snapshots(id, collected_at, document) VALUES(?1, ?2, ?3)",
            params![id, t0 - 120 - (40 - id) * 60, document.to_string()],
        )
        .unwrap();
    }
    db.execute("DELETE FROM snapshots WHERE id <= 30", [])
        .unwrap();
    for (key, value) in [
        ("notify.channel", channels.to_owned()),
        ("notify.problem", problem.to_owned()),
        ("notify.sent", (t0 - 7200).to_string()),
        ("notify.open", "{}".to_owned()),
    ] {
        db.execute(
            "INSERT OR REPLACE INTO memory(key, value) VALUES(?1, ?2)",
            params![key, value],
        )
        .unwrap();
    }
}

/// Where the mark stands after a run that stored `snapshot` in the database
/// at `path`: on the card, in a row, in the bytes of a file beside it, or in
/// a line the journal got from this thread.
fn marked(what: &str, path: &Path, snapshot: &Snapshot) -> Vec<String> {
    let mut found = Vec::new();
    let card = snapshot
        .observations
        .iter()
        .find(|card| card.id == "notifications.channels");
    let shown = serde_json::to_string(&card).unwrap();
    if shown.contains(MARK) {
        found.push(format!("{what}: the card: {shown}"));
    }
    let db = Connection::open(path).unwrap();
    let rows: Vec<String> = db
        .prepare(
            "SELECT 'memory ' || key FROM memory WHERE value LIKE ?1 \
             UNION ALL SELECT 'snapshot ' || id FROM snapshots WHERE document LIKE ?1",
        )
        .unwrap()
        .query_map([format!("%{MARK}%")], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    drop(db);
    found.extend(rows.into_iter().map(|row| format!("{what}: the row {row}")));
    for entry in fs::read_dir(path.parent().unwrap()).unwrap().flatten() {
        let bytes = fs::read(entry.path()).unwrap_or_default();
        if bytes
            .windows(MARK.len())
            .any(|window| window == MARK.as_bytes())
        {
            let name = entry.file_name();
            found.push(format!("{what}: the file {}", name.to_string_lossy()));
        }
    }
    for line in crate::journal::lines() {
        if line.text.contains(MARK) {
            found.push(format!("{what}: the journal: {}", line.text));
        }
    }
    found
}

/// 0.1.2 kept a failure that named the address the webhook has in its file
/// now, written in its configuration then: with its key in the path, which
/// 0.1.2 named whole where the webhook gave no HTTP answer; or with its key
/// right after the server, which 0.1.2 took for the server's name, as the
/// address of a webhook its last run no longer named.
#[test]
fn no_copy_of_an_address_an_earlier_release_kept_outlasts_the_next_run() {
    let path_key = format!("https://hooks.example.org/services/T0000/B0000/{MARK}");
    let channels = format!(
        "{{\"host\":\"admin.example.test\",\"ntfy\":null,\"webhook\":{{\"url\":\"{path_key}\"}},\
         \"mail\":null}}"
    );
    let mut found = Vec::new();
    for (what, address, channels, problem) in [
        (
            "the key in the path",
            path_key.clone(),
            channels,
            format!("webhook: {path_key} gave no HTTP answer"),
        ),
        (
            "the key after the server",
            format!("https://hooks.example.org/?key={MARK}"),
            String::new(),
            format!("webhook: hooks.example.org?key={MARK} does not resolve"),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let (config, credentials, path) = host(directory.path(), &address);
        as_0_1_2_left_it(&path, &channels, &problem);
        crate::journal::lines();
        let snapshot = run(&config, &credentials, now().as_second() - 60);
        found.extend(marked(what, &path, &snapshot));
    }
    assert_eq!(found, Vec::<String>::new());
}

/// This release keeps an address written in `garrison.toml` for the watch as
/// it is written; once it is kept in a file instead, the next run leaves no
/// copy of it.
#[test]
fn an_address_moved_into_its_file_leaves_no_copy_after_the_next_run() {
    let directory = tempfile::tempdir().unwrap();
    let address = format!(
        "https://hooks.example.org/hook/{MARK}?channel=alerts&username=garrison&format=json\
         &icon=https%3A%2F%2Fexample.org%2Ficons%2Fgarrison.png&threads=on&mention=here"
    );
    let (mut config, credentials, path) = host(directory.path(), &address);
    let file = config
        .notifications
        .webhook_url
        .replace(Endpoint::Written(address));
    let t0 = now().as_second();
    for minutes in [3, 2] {
        run(&config, &credentials, t0 - minutes * 60);
    }
    config.notifications.webhook_url = file;
    crate::journal::lines();
    let snapshot = run(&config, &credentials, t0 - 60);
    assert_eq!(marked("moved", &path, &snapshot), Vec::<String>::new());
}
