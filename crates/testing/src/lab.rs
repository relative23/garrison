//! A client for a disposable Stalwart instance used by the contract tests.
//!
//! `cargo xtask lab start` prints `GARRISON_LAB_URL`, `GARRISON_LAB_ADMIN`
//! ("user:password" of the bootstrap administrator) and
//! `GARRISON_LAB_CONTAINER`. The tests create uniquely named objects, remove
//! them when they finish and refuse any URL that is not on loopback, so they
//! never run against a real server.

use std::fmt::Write;
use std::hash::{BuildHasher, RandomState};
use std::io::Read;
use std::net::IpAddr;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use flate2::read::GzDecoder;
use serde_json::{Map, Value, json};

const USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];

#[derive(Debug)]
pub struct Lab {
    pub url: String,
    admin: String,
    agent: ureq::Agent,
    /// Objects to destroy afterwards, newest last.
    pub created: Vec<(String, String)>,
}

/// A random lowercase hex string; the standard library seeds it per process.
pub fn random_hex(bytes: usize) -> String {
    let mut text = String::new();
    while text.len() < bytes * 2 {
        let _ = write!(text, "{:016x}", RandomState::new().hash_one(text.len()));
    }
    text.truncate(bytes * 2);
    text
}

/// A name no other test run uses: `lab` and eight hex digits.
pub fn unique() -> String {
    format!("lab{}", random_hex(4))
}

impl Lab {
    /// The lab from the environment; panics with instructions if it is missing.
    pub fn from_environment() -> Lab {
        let (Ok(url), Ok(admin)) = (
            std::env::var("GARRISON_LAB_URL"),
            std::env::var("GARRISON_LAB_ADMIN"),
        ) else {
            panic!("set GARRISON_LAB_URL and GARRISON_LAB_ADMIN: eval \"$(cargo xtask lab start)\"")
        };
        let host = url::Url::parse(&url).ok().and_then(|parsed| {
            parsed
                .host_str()
                .map(|host| host.trim_matches(['[', ']']).to_owned())
        });
        let loopback = host
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        assert!(
            loopback,
            "contract tests run only against a loopback lab instance"
        );
        let agent = ureq::Agent::config_builder()
            .proxy(None)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Lab {
            url: url.trim_end_matches('/').to_owned(),
            admin,
            agent,
            created: Vec::new(),
        }
    }

    /// A JSON request with HTTP Basic credentials (`user:password`).
    pub fn http(&self, path: &str, credentials: &str, body: Option<&Value>) -> Value {
        let url = format!("{}{path}", self.url);
        let authorization = format!("Basic {}", STANDARD.encode(credentials));
        let answer = match body {
            None => self
                .agent
                .get(&url)
                .header("Authorization", &authorization)
                .call(),
            Some(body) => self
                .agent
                .post(&url)
                .header("Authorization", &authorization)
                .header("Content-Type", "application/json")
                .send(body.to_string()),
        };
        let mut answer = answer.unwrap_or_else(|error| panic!("{url}: {error}"));
        assert_eq!(answer.status(), 200, "{url}");
        let text = answer.body_mut().read_to_string().unwrap();
        serde_json::from_str(&text).unwrap()
    }

    /// The status Stalwart answers a request for the JMAP session with under
    /// HTTP Basic credentials (`user:password`): 401 for a sign-in it refuses.
    pub fn sign_in_status(&self, credentials: &str) -> u16 {
        let url = format!("{}/jmap/session", self.url);
        let answer = self
            .agent
            .get(&url)
            .header(
                "Authorization",
                &format!("Basic {}", STANDARD.encode(credentials)),
            )
            .call()
            .unwrap_or_else(|error| panic!("{url}: {error}"));
        answer.status().as_u16()
    }

    /// The name the bootstrap administrator signs in with.
    pub fn admin_name(&self) -> &str {
        self.admin
            .split_once(':')
            .map_or(&self.admin, |(name, _)| name)
    }

    /// A page or file as a browser gets it, without credentials: its status,
    /// its content type and its text. Stalwart sends these compressed
    /// whatever the request accepts.
    pub fn page(&self, path: &str) -> (u16, String, String) {
        let url = format!("{}{path}", self.url);
        let mut answer = self
            .agent
            .get(&url)
            .call()
            .unwrap_or_else(|error| panic!("{url}: {error}"));
        let header = |name: &str| {
            let value = answer.headers().get(name);
            value
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned()
        };
        let (media, coding) = (header("content-type"), header("content-encoding"));
        let status = answer.status().as_u16();
        let mut bytes = answer.body_mut().read_to_vec().unwrap();
        if coding.eq_ignore_ascii_case("gzip") {
            let mut unpacked = Vec::new();
            GzDecoder::new(bytes.as_slice())
                .read_to_end(&mut unpacked)
                .unwrap_or_else(|error| panic!("{url}: {error}"));
            bytes = unpacked;
        }
        (status, media, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// One management-API method as the bootstrap administrator; any failure panics.
    pub fn call(&self, method: &str, arguments: &Value) -> Map<String, Value> {
        let request = json!({"using": USING, "methodCalls": [[method, arguments, "0"]]});
        let answer = self.http("/jmap/", &self.admin, Some(&request));
        let [name, payload, _] = answer["methodResponses"][0].as_array().unwrap().as_slice() else {
            panic!("malformed answer: {answer}")
        };
        assert_eq!(name, method, "{payload}");
        for key in ["notCreated", "notUpdated", "notDestroyed"] {
            let failed = payload
                .get(key)
                .is_some_and(|value| value.as_object().is_some_and(|map| !map.is_empty()));
            assert!(!failed, "{key}: {payload}");
        }
        payload.as_object().unwrap().clone()
    }

    /// Sign in at Stalwart's authorization endpoint as its login page does
    /// (`POST /api/auth` with the request's query), consenting when asked.
    /// The answer names its `type` and, for a redirect, the `location`.
    pub fn authorize(&self, query: &str, account: &str, password: &str) -> Value {
        let url = format!("{}/api/auth", self.url);
        let post = |body: Value| -> Value {
            let mut answer = self
                .agent
                .post(&url)
                .header("Content-Type", "application/json")
                .send(body.to_string())
                .unwrap_or_else(|error| panic!("{url}: {error}"));
            assert_eq!(answer.status(), 200, "{url}");
            serde_json::from_str(&answer.body_mut().read_to_string().unwrap()).unwrap()
        };
        let answer = post(json!({
            "type": "authCode", "accountName": account, "accountSecret": password, "query": query,
        }));
        if answer["type"] != "consentRequired" {
            return answer;
        }
        post(json!({
            "type": "authConsent", "token": answer["token"], "query": query, "consent": true,
        }))
    }

    /// Create one object and remember it for cleanup.
    pub fn create(&mut self, kind: &str, value: &Value) -> String {
        let result = self.call(&format!("x:{kind}/set"), &json!({"create": {"n": value}}));
        let identifier = result["created"]["n"]["id"].as_str().unwrap().to_owned();
        self.created.push((kind.to_owned(), identifier.clone()));
        identifier
    }

    /// Restart the lab container and wait until it answers again. Settings and
    /// objects stay; what Stalwart keeps in memory, such as its metric
    /// counters, starts over. Only a container named `garrison-lab-…` is touched.
    pub fn restart(&self) {
        let name = std::env::var("GARRISON_LAB_CONTAINER")
            .expect("set GARRISON_LAB_CONTAINER: eval \"$(cargo xtask lab start)\"");
        assert!(
            name.starts_with("garrison-lab-"),
            "contract tests restart only a lab container"
        );
        let status = Command::new("docker")
            .args(["restart", &name])
            .status()
            .unwrap();
        assert!(status.success(), "docker restart {name}: {status}");
        let deadline = Instant::now() + Duration::from_secs(60);
        // Any HTTP answer means the server is up again.
        while self.agent.get(&self.url).call().is_err() {
            assert!(
                Instant::now() < deadline,
                "{name} did not answer within 60 s"
            );
            sleep(Duration::from_millis(500));
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        while let Some((kind, identifier)) = self.created.pop() {
            self.call(&format!("x:{kind}/set"), &json!({"destroy": [identifier]}));
        }
    }
}
