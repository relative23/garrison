//! A relay in front of the lab that stops `garrison stalwart setup` at one
//! of its requests to Stalwart, as a stop there would, and passes every
//! other request on with Stalwart's answer. A connection carries one
//! request: the relay answers it and closes it.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process};
use serde_json::Value;

use super::wire::{Request, answer, read_request};

/// How setup stops at the request it is stopped at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stop {
    /// Stalwart carries the request out, and setup is interrupted (SIGINT,
    /// as Ctrl-C or a lost SSH session) before it reads the answer.
    Interrupted,
    /// Stalwart carries the request out and the answer is lost, as when
    /// the connection drops: setup sees an error and cleans up.
    Lost,
    /// Stalwart cannot be reached from this request on, so that the clean-up
    /// after the error fails too.
    Unreachable,
}

/// What a request asks: the management API's method and what it does, or
/// the request line, as for a key try.
fn asked(request: &Request) -> String {
    let call: Option<Value> = serde_json::from_slice(&request.body).ok();
    let call = call
        .as_ref()
        .and_then(|call| call["methodCalls"][0].as_array().cloned());
    let Some(call) = call else {
        return format!("{} {}", request.method, request.path);
    };
    let name = call[0].as_str().unwrap_or("?");
    let what = ["create", "update", "destroy"].into_iter().find(|what| {
        call.get(1)
            .and_then(|arguments| arguments.get(*what))
            .is_some()
    });
    format!("{name} {}", what.unwrap_or(""))
        .trim_end()
        .to_owned()
}

struct Shared {
    upstream: String,
    at: usize,
    stop: Stop,
    seen: AtomicUsize,
    pid: AtomicI32,
    asked: Mutex<Vec<String>>,
    stopped: Mutex<Option<String>>,
    agent: ureq::Agent,
}

/// The relay and what it saw.
pub(super) struct Stopper {
    pub(super) url: String,
    shared: Arc<Shared>,
}

impl Stopper {
    /// A relay to the lab at `upstream` that stops setup at its request
    /// number `at`, counted from 1, as `stop` says.
    pub(super) fn new(upstream: &str, at: usize, stop: Stop) -> Stopper {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let agent = ureq::Agent::config_builder()
            .proxy(None)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(40)))
            .build()
            .into();
        let shared = Arc::new(Shared {
            upstream: upstream.to_owned(),
            at,
            stop,
            seen: AtomicUsize::new(0),
            pid: AtomicI32::new(0),
            asked: Mutex::new(Vec::new()),
            stopped: Mutex::new(None),
            agent,
        });
        let serving = Arc::clone(&shared);
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let shared = Arc::clone(&serving);
                thread::spawn(move || relay(client, &shared));
            }
        });
        Stopper { url, shared }
    }

    /// The process that a stop interrupts.
    pub(super) fn watch(&self, pid: u32) {
        self.shared
            .pid
            .store(i32::try_from(pid).unwrap(), Ordering::SeqCst);
    }

    /// The request setup was stopped at, if it got so far.
    pub(super) fn stopped(&self) -> Option<String> {
        self.shared.stopped.lock().unwrap().clone()
    }

    /// Every request setup sent, as far as it got.
    pub(super) fn asked(&self) -> Vec<String> {
        self.shared.asked.lock().unwrap().clone()
    }
}

fn relay(mut client: TcpStream, shared: &Shared) {
    let Some(request) = read_request(&client) else {
        return;
    };
    let number = shared.seen.fetch_add(1, Ordering::SeqCst) + 1;
    let asked = asked(&request);
    shared.asked.lock().unwrap().push(asked.clone());
    if number == shared.at {
        *shared.stopped.lock().unwrap() = Some(asked);
    }
    if shared.stop == Stop::Unreachable && number >= shared.at {
        return;
    }
    let (status, media, body) = forward(shared, &request);
    if number == shared.at {
        if shared.stop == Stop::Interrupted {
            interrupt(shared);
        }
        // Interrupted or lost: setup never reads this answer.
        return;
    }
    answer(&mut client, status, &media, &body);
}

fn forward(shared: &Shared, request: &Request) -> (u16, String, Vec<u8>) {
    let url = format!("{}{}", shared.upstream, request.path);
    let authorization = request.header("Authorization").unwrap_or_default();
    let result = if request.method == "GET" {
        shared
            .agent
            .get(&url)
            .header("Authorization", authorization)
            .call()
    } else {
        shared
            .agent
            .post(&url)
            .header("Authorization", authorization)
            .header(
                "Content-Type",
                request.header("Content-Type").unwrap_or("application/json"),
            )
            .send(&request.body[..])
    };
    let mut answer = result.unwrap_or_else(|error| panic!("{url}: {error}"));
    let media = answer
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_owned();
    let body = answer
        .body_mut()
        .with_config()
        .limit(16 << 20)
        .read_to_vec()
        .unwrap();
    (answer.status().as_u16(), media, body)
}

/// SIGINT to setup, as Ctrl-C sends it; setup keeps no handler for it.
fn interrupt(shared: &Shared) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        let pid = shared.pid.load(Ordering::SeqCst);
        if pid != 0 {
            break pid;
        }
        assert!(Instant::now() < deadline, "no process to interrupt");
        thread::sleep(Duration::from_millis(10));
    };
    kill_process(Pid::from_raw(pid).unwrap(), Signal::INT).unwrap();
}
