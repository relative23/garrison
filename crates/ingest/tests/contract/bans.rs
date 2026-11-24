//! What the Attacks & bans page relies on of Stalwart's bans, with each
//! client counted under the address nginx forwards: an IPv6 address banned
//! for its own failed sign-ins blocks its whole /64, which Stalwart's list
//! of blocked IPs names, while its event names the address; one banned only
//! because an account it tried was tried too often is blocked alone; and a
//! block goes once its entry is removed and the list is reloaded.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::sqlite::reading;
use garrison_ingest::app::router;
use garrison_ingest::attacks::{self, Attacks};
use garrison_ingest::store::{EventStore, Limits};
use garrison_testing::lab::{Lab, random_hex, unique};
use serde_json::{Value, json};

use super::{create_webhook, one_at_a_time};

fn act(lab: &Lab, action: &str) {
    lab.call("x:Action/set", &json!({"create": {"r": {"@type": action}}}));
    std::thread::sleep(Duration::from_secs(2));
}

/// Stalwart takes each client's address from `X-Forwarded-For` and bans an
/// address after three failed sign-ins, while the guard lives; then its own
/// settings come back and its blocks go.
struct Forwarding<'a> {
    lab: &'a Lab,
}

impl<'a> Forwarding<'a> {
    fn on(lab: &'a Lab) -> Self {
        lab.call(
            "x:Http/set",
            &json!({"update": {"singleton": {"clientIpSource": "xForwardedFor"}}}),
        );
        lab.call(
            "x:Security/set",
            &json!({"update": {"singleton": {
                "authBanRate": {"count": 3, "period": 86_400_000}, "authBanPeriod": 300_000}}}),
        );
        act(lab, "ReloadSettings");
        Forwarding { lab }
    }
}

impl Drop for Forwarding<'_> {
    fn drop(&mut self) {
        let lab = self.lab;
        let blocked = lab.call("x:BlockedIp/get", &json!({"ids": null}));
        let ids: Vec<Value> = blocked["list"]
            .as_array()
            .map(|list| list.iter().map(|item| item["id"].clone()).collect())
            .unwrap_or_default();
        lab.call("x:BlockedIp/set", &json!({"destroy": ids}));
        lab.call(
            "x:Http/set",
            &json!({"update": {"singleton": {"clientIpSource": "peer"}}}),
        );
        lab.call(
            "x:Security/set",
            &json!({"update": {"singleton": {
                "authBanRate": {"count": 100, "period": 86_400_000}, "authBanPeriod": null}}}),
        );
        act(lab, "ReloadSettings");
        act(lab, "ReloadBlockedIps");
    }
}

/// The status Stalwart answers a sign-in with that nginx would forward
/// from `client`.
fn sign_in_from(lab: &Lab, credentials: &str, client: &str) -> u16 {
    let host = lab.url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(host).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let request = format!(
        "GET /jmap/session HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {}\r\n\
         X-Forwarded-For: {client}\r\nConnection: close\r\n\r\n",
        STANDARD.encode(credentials)
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    line.split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status: {line:?}"))
}

/// Failed sign-ins of names that are no account, until Stalwart bans `client`.
fn banned(lab: &Lab, client: &str) {
    for _ in 0..6 {
        let stranger = format!("stranger-{}:wrong-{}", random_hex(4), random_hex(6));
        if sign_in_from(lab, &stranger, client) == 403 {
            return;
        }
    }
    panic!("Stalwart did not ban {client}");
}

/// The addresses and networks Stalwart's list of blocked IPs holds.
fn blocked(lab: &Lab) -> Vec<String> {
    let answer = lab.call("x:BlockedIp/get", &json!({"ids": null}));
    let mut addresses: Vec<String> = answer["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["address"].as_str().map(str::to_owned))
        .collect();
    addresses.sort();
    addresses
}

/// The summary of the receiver's history once `ready` holds for it.
fn summary_once(path: &Path, ready: impl Fn(&Attacks) -> bool) -> Attacks {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        std::thread::sleep(Duration::from_secs(1));
        // The receiver may be writing at this moment.
        if let Ok(Some(db)) = reading(path, Duration::from_secs(2)) {
            let summary = attacks::attacks(&db, 0, i64::MAX).unwrap();
            if ready(&summary) {
                return summary;
            }
            assert!(Instant::now() < deadline, "{summary:?}");
        }
    }
}

fn account(lab: &mut Lab) -> (String, String) {
    let domains = lab.call(
        "x:Domain/get",
        &json!({"ids": null, "properties": ["id", "name"]}),
    );
    let (name, password) = (unique(), random_hex(18));
    lab.create(
        "Account",
        &json!({
            "@type": "User",
            "name": name,
            "domainId": domains["list"][0]["id"],
            "credentials": {"0": {"@type": "Password", "secret": password}},
            "roles": {"@type": "User"},
            "permissions": {"@type": "Inherit"},
        }),
    );
    let domain = domains["list"][0]["name"].as_str().unwrap();
    (format!("{name}@{domain}"), password)
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn an_ipv6_address_banned_for_its_own_sign_ins_blocks_its_64() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let key = random_hex(32);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.sqlite");
    let store = Arc::new(EventStore::open(&path, Limits::new(30, 10_000, 64 << 20)).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind((callback.as_str(), 0)))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = router(Arc::clone(&store), key.as_bytes());
    runtime.spawn(async move { axum::serve(listener, app).await });
    create_webhook(&mut lab, &format!("http://{callback}:{port}/webhook"), &key);
    let (name, password) = account(&mut lab);
    let admin = std::env::var("GARRISON_LAB_ADMIN").unwrap();
    let forwarding = Forwarding::on(&lab);

    // An address that fails itself: its /64 is blocked, the next one not.
    banned(&lab, "2001:db8:c0:1::5");
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(sign_in_from(&lab, &admin, "2001:db8:c0:1::77"), 403);
    assert_eq!(sign_in_from(&lab, &admin, "2001:db8:c0:2::5"), 200);
    assert_eq!(blocked(&lab), ["2001:db8:c0:1::/64"]);
    // The page names the address the event names, with the /64 Stalwart's
    // list holds, which a look-up by the address there does not find.
    let summary = summary_once(&path, |summary| !summary.bans.is_empty());
    let ban = &summary.bans[0];
    assert_eq!(
        (
            ban.address.as_str(),
            ban.network.as_deref(),
            ban.reason.as_str()
        ),
        (
            "2001:db8:c0:1::5",
            Some("2001:db8:c0:1::/64"),
            "authentication"
        )
    );
    let found = lab.call(
        "x:BlockedIp/query",
        &json!({"filter": {"address": "2001:db8:c0:1::5"}}),
    );
    assert_eq!(found["ids"], json!([]), "{found:?}");

    // Addresses of other networks that each tried one account once: the one
    // that trips the account's count is blocked alone.
    for index in 1..=4 {
        sign_in_from(
            &lab,
            &format!("{name}:wrong-{}", random_hex(4)),
            &format!("2001:db8:c1:{index}::1"),
        );
    }
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(blocked(&lab), ["2001:db8:c0:1::/64", "2001:db8:c1:4::1"]);
    assert_eq!(
        sign_in_from(&lab, &format!("{name}:{password}"), "2001:db8:c1:4::2"),
        200
    );

    // A block goes once its entry is removed and the list is reloaded.
    let entries = lab.call("x:BlockedIp/get", &json!({"ids": null}));
    let ids: Vec<Value> = entries["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].clone())
        .collect();
    lab.call("x:BlockedIp/set", &json!({"destroy": ids}));
    act(&lab, "ReloadBlockedIps");
    assert_eq!(sign_in_from(&lab, &admin, "2001:db8:c0:1::77"), 200);
    drop(forwarding);
}
