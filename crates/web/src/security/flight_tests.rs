//! Requests of one session that arrive together: one question to the
//! broker, and one answer for all of them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;

use garrison_broker::protocol::BrokerError;
use serde_json::json;

use super::*;
use crate::store::NewSession;

/// A broker that answers when it is let, and counts the questions.
#[derive(Default)]
struct Slow {
    calls: AtomicUsize,
    /// What it refuses with; 0 grants.
    refusal: u16,
    let_go: Mutex<bool>,
    going: Condvar,
}

impl Slow {
    fn answer_now(&self) {
        *self.let_go.lock().unwrap() = true;
        self.going.notify_all();
    }

    /// Wait until the broker was asked, then leave the others the time to
    /// arrive.
    fn asked(&self) {
        while self.calls.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(300));
    }
}

impl Broker for Slow {
    fn call(&self, _: &Request) -> Result<Value, CallError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut let_go = self.let_go.lock().unwrap();
        while !*let_go {
            let_go = self.going.wait(let_go).unwrap();
        }
        if self.refusal != 0 {
            return Err(CallError::Refused(BrokerError {
                status: self.refusal,
                message: "Garrison access is not authorized".into(),
            }));
        }
        Ok(json!({
            "subject": "1",
            "email": "1@example.test",
            "modules": ["dashboard"],
            "actions": [],
            "profiles": ["viewer"],
            "checkedAt": "2026-10-29T00:00:00+00:00",
        }))
    }
}

struct Fixture {
    gate: Arc<Gate>,
    store: Arc<WebStore>,
    broker: Arc<Slow>,
    revoked: Arc<AtomicUsize>,
    _directory: tempfile::TempDir,
}

fn fixture(refusal: u16) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(WebStore::open(&directory.path().join("web.sqlite")).unwrap());
    let broker = Arc::new(Slow {
        refusal,
        ..Slow::default()
    });
    let revoked = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&revoked);
    let gate = Gate::new(
        Arc::clone(&store),
        Arc::clone(&broker) as Arc<dyn Broker>,
        "https://admin.example.test".into(),
        BTreeSet::new(),
        false,
    )
    .revoking_with(move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    Fixture {
        gate: Arc::new(gate),
        store,
        broker,
        revoked,
        _directory: directory,
    }
}

impl Fixture {
    fn visitor(&self) -> Visitor {
        let (identifier, _) = self
            .store
            .create(&NewSession {
                subject: "1",
                email: "1@example.test",
                token: "token-0123456789abcdef",
                client_ip: None,
                lifetime: 600,
            })
            .unwrap();
        Visitor {
            cookies: HashMap::from([(SESSION_COOKIE.to_owned(), identifier)]),
            ..Visitor::default()
        }
    }

    /// The status of each of `count` requests of `visitor` that arrive
    /// while the broker has not answered the first; 200 for a grant.
    fn together(&self, visitors: &[Visitor], count: usize) -> Vec<u16> {
        let asking: Vec<_> = (0..count)
            .map(|index| {
                let gate = Arc::clone(&self.gate);
                let visitor = visitors[index % visitors.len()].clone();
                thread::spawn(move || match gate.caller(&visitor) {
                    Ok(_) => 200,
                    Err(error) => error.status.as_u16(),
                })
            })
            .collect();
        self.broker.asked();
        self.broker.answer_now();
        asking
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect()
    }
}

#[test]
fn the_requests_of_one_session_share_one_question_to_the_broker() {
    // A page asks for a dozen things at once when its grant has run out.
    let fixture = fixture(0);
    let visitor = fixture.visitor();
    let answers = fixture.together(&[visitor], 12);
    assert_eq!(answers, [200; 12]);
    assert_eq!(fixture.broker.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn each_session_is_asked_about_for_itself() {
    let fixture = fixture(0);
    let visitors = [fixture.visitor(), fixture.visitor(), fixture.visitor()];
    let answers = fixture.together(&visitors, 12);
    assert_eq!(answers, [200; 12]);
    assert_eq!(fixture.broker.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn a_refusal_is_the_answer_for_all_and_ends_the_session_once() {
    let fixture = fixture(403);
    let visitor = fixture.visitor();
    let answers = fixture.together(std::slice::from_ref(&visitor), 12);
    // Those that waited got the refusal; one that came after it finds no
    // session any more.
    assert!(answers.contains(&403), "{answers:?}");
    assert!(
        answers.iter().all(|status| [401, 403].contains(status)),
        "{answers:?}"
    );
    assert_eq!(fixture.broker.calls.load(Ordering::SeqCst), 1);
    // The token is revoked once, not once for each request.
    assert_eq!(fixture.revoked.load(Ordering::SeqCst), 1);
    assert!(fixture.gate.session(&visitor).unwrap().is_none());
}
