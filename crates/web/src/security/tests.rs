use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::HeaderValue;
use garrison_broker::protocol::BrokerError;

use serde_json::json;

use super::*;
use crate::store::NewSession;

/// Grants every token to subject "1" and counts the questions.
#[derive(Default)]
struct Counting {
    calls: AtomicUsize,
    subject: &'static str,
}

impl Broker for Counting {
    fn call(&self, _: &Request) -> Result<Value, CallError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.subject.is_empty() {
            return Err(CallError::Refused(BrokerError {
                status: 401,
                message: "Sign-in required again".into(),
            }));
        }
        Ok(json!({
            "subject": self.subject,
            "email": "1@example.test",
            "modules": ["dashboard"],
            "actions": [],
            "profiles": ["viewer"],
            "checkedAt": "2026-10-29T00:00:00+00:00",
        }))
    }
}

struct Fixture {
    gate: Gate,
    store: Arc<WebStore>,
    broker: Arc<Counting>,
    _directory: tempfile::TempDir,
}

fn fixture(subject: &'static str, bind_client_ip: bool, cache: Duration) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(WebStore::open(&directory.path().join("web.sqlite")).unwrap());
    let broker = Arc::new(Counting {
        subject,
        ..Counting::default()
    });
    let shared: Arc<dyn Broker> = Arc::clone(&broker) as Arc<dyn Broker>;
    let gate = Gate::new(
        Arc::clone(&store),
        shared,
        "https://admin.example.test".into(),
        BTreeSet::new(),
        bind_client_ip,
    )
    .with_cache_time(cache);
    Fixture {
        gate,
        store,
        broker,
        _directory: directory,
    }
}

impl Fixture {
    /// A session for subject "1", as the visitor that holds its cookie.
    fn visitor(&self, client_ip: Option<&str>) -> Visitor {
        let (identifier, _) = self
            .store
            .create(&NewSession {
                subject: "1",
                email: "1@example.test",
                token: "token-0123456789abcdef",
                client_ip,
                lifetime: 600,
            })
            .unwrap();
        Visitor {
            cookies: HashMap::from([(SESSION_COOKIE.to_owned(), identifier)]),
            ..Visitor::default()
        }
    }

    fn calls(&self) -> usize {
        self.broker.calls.load(Ordering::SeqCst)
    }
}

fn from(peer: &str, header: &str) -> Visitor {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-garrison-client-ip",
        HeaderValue::from_str(header).unwrap(),
    );
    Visitor {
        peer: Some(peer.parse().unwrap()),
        headers,
        ..Visitor::default()
    }
}

#[test]
fn only_a_loopback_proxy_may_name_the_client() {
    assert_eq!(
        from("127.0.0.1", "192.0.2.1").client_ip().as_deref(),
        Some("192.0.2.1")
    );
    assert_eq!(
        from("::1", "2001:DB8::1").client_ip().as_deref(),
        Some("2001:db8::1")
    );
    assert_eq!(from("192.0.2.9", "192.0.2.1").client_ip(), None);
    assert_eq!(from("127.0.0.1", "").client_ip(), None);
    assert_eq!(from("127.0.0.1", "not an address").client_ip(), None);
    let mut unproxied = from("127.0.0.1", "192.0.2.1");
    unproxied.peer = None;
    assert_eq!(unproxied.client_ip(), None);
}

#[test]
fn a_bound_session_works_only_from_its_client() {
    let bound = fixture("1", true, Duration::from_secs(60));
    let session = bound.visitor(Some("192.0.2.1"));
    let mut same = from("127.0.0.1", "192.0.2.1");
    same.cookies = session.cookies.clone();
    assert!(bound.gate.caller(&same).is_ok());
    let mut other = from("127.0.0.1", "192.0.2.2");
    other.cookies = session.cookies.clone();
    assert_eq!(bound.gate.caller(&other).unwrap_err().status.as_u16(), 401);
    let unbound = fixture("1", false, Duration::from_secs(60));
    let mut moved = from("127.0.0.1", "192.0.2.2");
    moved.cookies = unbound.visitor(Some("192.0.2.1")).cookies;
    assert!(unbound.gate.caller(&moved).is_ok());
}

#[test]
fn rights_are_reused_only_within_the_cache_time() {
    let cached = fixture("1", false, Duration::from_secs(60));
    let (first, second) = (cached.visitor(None), cached.visitor(None));
    for visitor in [&first, &second, &first, &second] {
        cached.gate.caller(visitor).unwrap();
    }
    assert_eq!(cached.calls(), 2, "one question per session");
    let uncached = fixture("1", false, Duration::ZERO);
    let visitor = uncached.visitor(None);
    uncached.gate.caller(&visitor).unwrap();
    uncached.gate.caller(&visitor).unwrap();
    assert_eq!(uncached.calls(), 2);
}

#[test]
fn the_cache_starts_over_beyond_its_limit() {
    let cached = fixture("1", false, Duration::from_secs(60));
    let visitors: Vec<Visitor> = (0..=MAX_CACHED + 1).map(|_| cached.visitor(None)).collect();
    for visitor in &visitors {
        cached.gate.caller(visitor).unwrap();
    }
    let before = cached.calls();
    cached.gate.caller(&visitors[MAX_CACHED + 1]).unwrap();
    assert_eq!(cached.calls(), before, "the newest entry survives");
    cached.gate.caller(&visitors[MAX_CACHED]).unwrap();
    assert_eq!(cached.calls(), before + 1, "older entries were dropped");
}

#[test]
fn another_subject_or_a_refusal_ends_the_session() {
    let switched = fixture("2", false, Duration::from_secs(60));
    let visitor = switched.visitor(None);
    assert_eq!(
        switched.gate.caller(&visitor).unwrap_err().status.as_u16(),
        401
    );
    assert!(switched.gate.session(&visitor).unwrap().is_none());
    let refused = fixture("", false, Duration::from_secs(60));
    let visitor = refused.visitor(None);
    assert_eq!(
        refused.gate.caller(&visitor).unwrap_err().status.as_u16(),
        401
    );
    assert!(refused.gate.session(&visitor).unwrap().is_none());
}

#[test]
fn debug_output_names_the_origin_only() {
    let fixture = fixture("1", false, Duration::from_secs(5));
    assert_eq!(
        format!("{:?}", fixture.gate),
        r#"Gate { origin: "https://admin.example.test", .. }"#
    );
}

#[test]
fn the_broker_client_carries_the_broker_answer() {
    use std::io::{BufRead, BufReader, Write};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("broker.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let broker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        stream
            .write_all(b"{\"ok\": true, \"result\": {\"answered\": true}}\n")
            .unwrap();
        line
    });
    let client: &dyn Broker = &BrokerClient::new(&path);
    let request = Request::Catalog {
        token: "admin-token".into(),
    };
    let answer = client.call(&request).unwrap();
    assert_eq!(answer, json!({"answered": true}));
    assert_eq!(
        broker.join().unwrap(),
        "{\"op\":\"catalog\",\"token\":\"admin-token\"}\n"
    );
}
