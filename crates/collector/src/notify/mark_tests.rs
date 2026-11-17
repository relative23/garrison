//! No secret reaches a place others read. Every setting that may hold one
//! holds a mark here, and every channel goes through every kind of failure:
//! of its file, of its secret and of its server. The mark is then in no
//! error, which `garrison notify-test` prints and the watch's journal line
//! repeats; on no card; in no line of the journal; in nothing the status
//! database keeps, which the group `garrison` reads; and in no debug line.
//! An address written in the configuration is no secret, since garrison.toml
//! shows it to every user of the host, but the page and the errors name its
//! server alone all the same: its mark may stand only in the channels the
//! database keeps for the watch, as the configuration writes them, and in a
//! debug line.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::config::{Config, Database, Endpoint, MailSettings};
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_testing::http::{answer, serve};
use garrison_testing::silent::Silent;
use garrison_testing::tls;
use rusqlite::Connection;

use super::tests::observed;
use super::*;
use crate::snapshot::{SCHEMA, Snapshot};
use crate::store::StatusStore;
use crate::testing::{certificates, now};

/// What every secret of this test holds, and no other text of it: a token,
/// a password, a topic and a part of a path or a query alike.
const MARK: &str = "Zq7Mark4Secret9x";

/// A port nothing listens on.
fn closed() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A host in `directory` with the empty files the installer keeps.
fn host(directory: &Path) -> (Config, Credentials) {
    let config = crate::testing::config(directory);
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    for name in [
        "ntfy-url",
        "ntfy-token",
        "notify-webhook-url",
        "notify-webhook-token",
        "notify-mail-password",
    ] {
        write(&credentials, name, Some(""), 0o600);
    }
    (config, credentials)
}

/// The file `name` holding `data`, or none.
fn write(credentials: &Credentials, name: &str, data: Option<&str>, mode: u32) {
    let path = credentials.directory().join(name);
    let _ = fs::remove_file(&path);
    if let Some(data) = data {
        fs::write(&path, data).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// One failure of the channels of a configuration.
struct Case<'a> {
    what: String,
    config: &'a Config,
    credentials: &'a Credentials,
    roots: Arc<RootCertStore>,
    deadline: Deadline,
    /// The configuration writes the address itself.
    written: bool,
}

impl Case<'_> {
    /// Where the mark stands after a test message and two collection runs,
    /// the second with a failure to tell: each place, with what it holds.
    fn marked(&self) -> Vec<String> {
        crate::journal::lines();
        let notifications = &self.config.notifications;
        let secrets = Secrets::read(self.credentials, notifications);
        let channels = Channels::of(self.config, secrets.clone()).located(self.credentials);
        let mut seen = Vec::new();
        let mut look = |place: &str, text: &str| {
            if text.contains(MARK) {
                seen.push(format!("{}: {place}: {text}", self.what));
            }
        };
        let test = Note::plain("test".to_owned(), "test".to_owned(), Level::Good);
        for (channel, outcome) in channels.send_with(&test, now(), &self.roots, self.deadline) {
            look(
                &format!("{channel}'s error"),
                &outcome.err().unwrap_or_default(),
            );
        }
        let path = self.config.database(Database::Status);
        let _ = fs::remove_file(&path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut store = StatusStore::open(&path, 90).unwrap();
        let failing = [observed("backup", State::Failed, "The last run failed.")];
        let run = || {
            after_run_with(
                &channels,
                &failing,
                &store,
                now(),
                &self.roots,
                self.deadline,
            )
        };
        run();
        let card = run().unwrap();
        look("the card", &serde_json::to_string(&card).unwrap());
        crate::watch::remember(&store, &channels);
        let snapshot = Snapshot {
            schema_version: SCHEMA,
            collected_at: time::isoformat(now()),
            observations: vec![card],
            provider_errors: Vec::new(),
        };
        let none = BTreeMap::new();
        store
            .write(now().as_second(), &snapshot, &none, &none)
            .unwrap();
        drop(store);
        for line in crate::journal::lines() {
            look("the journal", &line.text);
        }
        if !self.written {
            look("a debug line", &format!("{channels:?} {secrets:?}"));
            let bytes = fs::read(&path).unwrap();
            look("the status database", &String::from_utf8_lossy(&bytes));
        }
        // An address written in the configuration is kept for the watch as
        // it is written; no other row holds it.
        let db = Connection::open(&path).unwrap();
        let rows: Vec<String> = db
            .prepare(
                "SELECT value FROM memory WHERE key != 'notify.channel' \
                 UNION ALL SELECT document FROM snapshots",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for row in rows {
            look("a row of the status database", &row);
        }
        seen
    }
}

/// The deadline of a request that is answered at once.
fn soon() -> Deadline {
    Deadline::within(Duration::from_secs(5))
}

/// The topic or the webhook, its address kept in its file.
struct Kept<'a> {
    kind: &'static str,
    config: &'a Config,
    credentials: &'a Credentials,
    /// The files of the address and of the token.
    file: &'static str,
    token: &'static str,
}

impl Kept<'_> {
    /// A configuration in `directory` whose `kind` keeps its address in a
    /// file.
    fn configured(kind: &str, directory: &Path) -> (Config, Credentials) {
        let (mut config, credentials) = host(directory);
        let file = |name: &str| Some(Endpoint::File(SecretSource::Credential(name.into())));
        if kind == "ntfy" {
            config.notifications.ntfy_url = file("ntfy-url");
        } else {
            config.notifications.webhook_url = file("notify-webhook-url");
        }
        (config, credentials)
    }

    /// The address at the server `base`, marked.
    fn address(&self, base: &str) -> String {
        if self.kind == "ntfy" {
            format!("{base}/{MARK}")
        } else {
            format!("{base}/hook/{MARK}?key={MARK}")
        }
    }

    /// Where the mark stands after the channel failed as `what` says.
    fn check(
        &self,
        found: &mut Vec<String>,
        what: &str,
        roots: &RootCertStore,
        deadline: Deadline,
    ) {
        let case = Case {
            what: format!("{} {what}", self.kind),
            config: self.config,
            credentials: self.credentials,
            roots: Arc::new(roots.clone()),
            deadline,
            written: false,
        };
        found.extend(case.marked());
    }

    /// Every failure of the file of the address and of the token.
    fn files(&self, found: &mut Vec<String>) {
        let none = RootCertStore::empty();
        // The file of the address: missing, empty, open to other users, or
        // holding what no request sends.
        for (data, mode) in [
            (None, 0o600),
            (Some(String::new()), 0o600),
            (Some(self.address("https://localhost:9")), 0o644),
            (Some(format!("https://localhost?key={MARK}")), 0o600),
            (Some(format!("https://localhost:9?key={MARK}")), 0o600),
            (Some(format!("https://localhost#{MARK}")), 0o600),
            (Some(format!("https://localhost\\{MARK}")), 0o600),
            (Some(self.address("http://localhost:9")), 0o600),
            (
                Some(format!("{} {MARK}", self.address("https://localhost:9"))),
                0o600,
            ),
        ] {
            write(self.credentials, self.file, data.as_deref(), mode);
            self.check(found, &format!("address {data:?}"), &none, soon());
        }
        // The token's file: open to other users, or no token. Nothing goes
        // out without it.
        let address = self.address("https://localhost:9");
        write(self.credentials, self.file, Some(&address), 0o600);
        for (data, mode) in [(MARK.to_owned(), 0o644), (format!("{MARK} {MARK}"), 0o600)] {
            write(self.credentials, self.token, Some(&data), mode);
            self.check(found, &format!("token {data:?}"), &none, soon());
        }
        write(self.credentials, self.token, Some(MARK), 0o600);
    }

    /// Every failure of the server: an authority this host does not trust,
    /// an answer of 500, no HTTP answer, a cut head, nothing that listens, no
    /// answer at all, the run's time used up, and a name that does not
    /// resolve. Each case sends twice: the test message and the second run's.
    fn servers(&self, found: &mut Vec<String>) {
        let none = RootCertStore::empty();
        let twice = |text: String| vec![text.clone(), text];
        for (what, answers, trusted) in [
            ("an untrusted authority", twice(answer(200, "{}")), false),
            ("an answer of 500", twice(answer(500, MARK)), true),
            ("no HTTP answer", twice(format!("{MARK}\r\n\r\n")), true),
        ] {
            let stand_in = tls::serve_until(answers, 2036, 10, 26);
            let address = self.address(&stand_in.url);
            write(self.credentials, self.file, Some(&address), 0o600);
            let roots = if trusted { &stand_in.roots } else { &none };
            self.check(found, &format!("with {what}"), roots, soon());
            stand_in.finish();
        }
        let cut = tls::serve_without_notice(twice("HTTP/1.1 200 OK\r\nContent-Ty".to_owned()));
        write(
            self.credentials,
            self.file,
            Some(&self.address(&cut.url)),
            0o600,
        );
        self.check(found, "with a cut head", &cut.roots, soon());
        cut.finish();
        let quiet = Silent::new();
        for (what, base, deadline) in [
            (
                "nothing that listens",
                format!("https://127.0.0.1:{}", closed()),
                soon(),
            ),
            (
                "no answer",
                quiet.url.replace("http://", "https://"),
                Deadline::within(Duration::from_millis(300)),
            ),
            (
                "the run's time used up",
                "https://localhost:9".to_owned(),
                Deadline::within(Duration::ZERO),
            ),
            (
                "a name that does not resolve",
                "https://garrison-test.invalid".to_owned(),
                Deadline::within(Duration::from_secs(2)),
            ),
        ] {
            write(
                self.credentials,
                self.file,
                Some(&self.address(&base)),
                0o600,
            );
            self.check(found, &format!("with {what}"), &none, deadline);
        }
        let _ = quiet.finish();
    }
}

/// The topic or the webhook, its address kept in its file, through every
/// failure of the file, of the token and of the server.
fn kept_address(kind: &'static str, found: &mut Vec<String>) {
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = Kept::configured(kind, directory.path());
    let (file, token) = if kind == "ntfy" {
        ("ntfy-url", "ntfy-token")
    } else {
        ("notify-webhook-url", "notify-webhook-token")
    };
    let kept = Kept {
        kind,
        config: &config,
        credentials: &credentials,
        file,
        token,
    };
    kept.files(found);
    kept.servers(found);
}

/// Mail, its password marked, through every failure of its file and of the
/// server.
fn mail(found: &mut Vec<String>) {
    let directory = tempfile::tempdir().unwrap();
    let (mut config, credentials) = host(directory.path());
    let certificates = certificates();
    let trusted = mail::tests::trusted(&certificates);
    let password = format!("pass {MARK}");
    let mut check = |what: String, port: u16, roots: &Arc<RootCertStore>, deadline| {
        config.notifications.mail = Some(MailSettings {
            host: "localhost".to_owned(),
            port,
            user: "garrison@example.test".to_owned(),
            from: "garrison@example.test".to_owned(),
            to: "anna@example.test".to_owned(),
        });
        let case = Case {
            what: format!("mail {what}"),
            config: &config,
            credentials: &credentials,
            roots: Arc::clone(roots),
            deadline,
            written: false,
        };
        found.extend(case.marked());
    };
    for (data, mode) in [
        (None, 0o600),
        (Some(String::new()), 0o600),
        (Some(password.clone()), 0o644),
        (Some(format!("pass\t{MARK}")), 0o600),
    ] {
        write(&credentials, "notify-mail-password", data.as_deref(), mode);
        check(format!("password {data:?}"), closed(), &trusted, soon());
    }
    write(&credentials, "notify-mail-password", Some(&password), 0o600);
    // A server that refuses the sign-in and quotes it, and one that refuses
    // the recipient. A server serves one session: the second run's message
    // finds nothing that listens.
    let login = STANDARD.encode(format!("\0garrison@example.test\0{password}"));
    let quoted: &'static str =
        Box::leak(format!("535 5.7.8 Not {login} {password}\r\n").into_boxed_str());
    for (what, auth, rcpt) in [
        ("a refused sign-in", quoted, "250 OK\r\n"),
        (
            "a refused recipient",
            "235 OK\r\n",
            "550 5.1.1 No such user\r\n",
        ),
    ] {
        let (port, _) = mail::tests::server(&certificates, auth, rcpt);
        check(format!("with {what}"), port, &trusted, soon());
    }
    let (port, _) = mail::tests::server(&certificates, "235 OK\r\n", "250 OK\r\n");
    check(
        "with an untrusted authority".to_owned(),
        port,
        &Arc::new(RootCertStore::empty()),
        soon(),
    );
    let quiet = Silent::new();
    check(
        "with no answer".to_owned(),
        quiet.address.port(),
        &trusted,
        Deadline::within(Duration::from_millis(300)),
    );
    check(
        "with the run's time used up".to_owned(),
        closed(),
        &trusted,
        Deadline::within(Duration::ZERO),
    );
    let _ = quiet.finish();
}

/// A topic and a webhook whose addresses the configuration writes, with a
/// key in the path, as Slack's and Discord's carry one, or after the server
/// as a release before this one took it.
fn written(found: &mut Vec<String>) {
    let directory = tempfile::tempdir().unwrap();
    let (mut config, credentials) = host(directory.path());
    for kind in ["ntfy", "webhook"] {
        let mut check = |what: &str, url: String, deadline| {
            let endpoint = Some(Endpoint::Written(url));
            (
                config.notifications.ntfy_url,
                config.notifications.webhook_url,
            ) = if kind == "ntfy" {
                (endpoint, None)
            } else {
                (None, endpoint)
            };
            let case = Case {
                what: format!("{kind} written {what}"),
                config: &config,
                credentials: &credentials,
                roots: Arc::new(RootCertStore::empty()),
                deadline,
                written: true,
            };
            found.extend(case.marked());
        };
        let path = format!("services/{MARK}");
        for (what, reply) in [
            ("with an answer of 500", answer(500, MARK)),
            ("with no HTTP answer", format!("{MARK}\r\n\r\n")),
        ] {
            let server = serve(vec![reply.clone(), reply]);
            check(what, format!("{}/{path}", server.url), soon());
            server.requests();
        }
        let quiet = Silent::new();
        for (what, url, deadline) in [
            (
                "nothing that listens",
                format!("http://127.0.0.1:{}/{path}", closed()),
                soon(),
            ),
            (
                "no answer",
                format!("{}/{path}", quiet.url),
                Deadline::within(Duration::from_millis(300)),
            ),
            (
                "the key after the server",
                format!("http://127.0.0.1?key={MARK}"),
                Deadline::within(Duration::from_secs(2)),
            ),
            (
                "the key after the port",
                format!("http://127.0.0.1:{}?key={MARK}", closed()),
                soon(),
            ),
            (
                "the run's time used up",
                format!("http://127.0.0.1:9/{path}"),
                Deadline::within(Duration::ZERO),
            ),
        ] {
            check(what, url, deadline);
        }
        let _ = quiet.finish();
    }
}

#[test]
fn no_mark_of_a_secret_reaches_a_place_others_read() {
    let mut found = Vec::new();
    kept_address("ntfy", &mut found);
    kept_address("webhook", &mut found);
    mail(&mut found);
    written(&mut found);
    assert_eq!(found, Vec::<String>::new());
}
