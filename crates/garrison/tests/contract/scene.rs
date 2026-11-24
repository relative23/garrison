//! The kinds of run the stop test stops, and the lab and the folder each
//! starts from: the administrators, the operator's own keys, the macro
//! filter and the configuration.

use std::fs;
use std::path::Path;

use garrison_testing::lab::{Lab, random_hex, unique};
use garrison_testing::{config_text, write_private};
use serde_json::{Value, json};

use super::{Setup, forget, text};

/// What a stopped run is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// The first setup: nothing in Stalwart or the folder, no service runs.
    First,
    /// `--rotate` while the services run with the secrets of the files.
    Rotation,
    /// A plain run after the broker's key file and the signature key's file
    /// were emptied while the services run with systemd's copies of the
    /// keys they held.
    Emptied,
    /// `--rotate` where the administrator's account holds as many API keys
    /// as Stalwart takes, five: the operator's own beside setup's two.
    Full,
    /// A plain run as a second administrator after the first one's setup,
    /// while the services run with the keys the first one made; the runs
    /// after it are the second one's too.
    Second,
    /// The first setup with `[milter]`, while the filter answers at its port.
    Milter,
    /// A plain run after `[milter]` was taken out, where the filter's entry
    /// and setup's note of it are there.
    MilterGone,
}

pub(super) const KINDS: [Kind; 7] = [
    Kind::First,
    Kind::Rotation,
    Kind::Emptied,
    Kind::Full,
    Kind::Second,
    Kind::Milter,
    Kind::MilterGone,
];

impl Kind {
    /// The arguments of the stopped run besides setup's own.
    pub(super) fn arguments(self) -> &'static [&'static str] {
        if matches!(self, Kind::Rotation | Kind::Full) {
            &["--rotate"]
        } else {
            &[]
        }
    }

    /// Whether the configuration of the stopped run and the runs after it
    /// has `[milter]`.
    pub(super) fn milter(self) -> bool {
        self == Kind::Milter
    }

    /// Whether the macro filter's entry is looked at after the runs.
    pub(super) fn about_the_milter(self) -> bool {
        matches!(self, Kind::Milter | Kind::MilterGone)
    }
}

/// The files of the secrets the running services hold.
pub(super) const HELD: [&str; 2] = ["broker-native-key", "webhook-signature-key"];

/// The secrets of the held files as the folder holds them now.
pub(super) fn holding(credentials: &Path) -> [String; 2] {
    HELD.map(|name| fs::read_to_string(credentials.join(name)).unwrap_or_default())
}

/// What the kinds need beside the lab: the two administrators, the
/// filter's port, where a filter answers, and the operator's own keys while
/// the kind `Full` runs.
pub(super) struct Scene {
    first: String,
    second: String,
    /// The second administrator's account.
    pub(super) account: String,
    pub(super) port: u16,
    own: Vec<String>,
}

impl Scene {
    pub(super) fn new(lab: &mut Lab) -> Scene {
        let admin = std::env::var("GARRISON_LAB_ADMIN").unwrap();
        let (user, secret) = admin.split_once(':').unwrap();
        let domains = lab.call("x:Domain/get", &json!({"ids": null, "properties": ["id"]}));
        let (name, password) = (unique(), random_hex(18));
        let account = lab.create(
            "Account",
            &json!({
                "@type": "User",
                "name": name,
                "domainId": domains["list"][0]["id"],
                "credentials": {"0": {"@type": "Password", "secret": password}},
                "roles": {"@type": "Admin"},
                "permissions": {"@type": "Inherit"},
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
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
        Scene {
            first: json!({"username": user, "secret": secret}).to_string(),
            second: json!({"username": name, "secret": password}).to_string(),
            account,
            port,
            own: Vec::new(),
        }
    }

    /// The configuration for Stalwart at `url`, with the filter or without.
    pub(super) fn settings(&self, directory: &Path, url: &str, milter: bool) -> String {
        let text = config_text(directory, url);
        if milter {
            format!("{text}\n[milter]\nport = {}\n", self.port)
        } else {
            text
        }
    }

    /// The accounts that may hold setup's keys in `kind`.
    pub(super) fn accounts(&self, kind: Kind) -> Vec<Option<&str>> {
        if kind == Kind::Second {
            vec![None, Some(&self.account)]
        } else {
            vec![None]
        }
    }

    fn act_as(&self, setup: &Setup, second: bool) {
        let document = if second { &self.second } else { &self.first };
        write_private(Path::new(&setup.credential), document.as_bytes());
    }

    fn configure(&self, setup: &Setup, url: &str, milter: bool) {
        let path = setup.directory.join("garrison.toml");
        fs::write(path, self.settings(&setup.directory, url, milter)).unwrap();
    }

    /// Bring the lab and the folder to where a stopped run of `kind` starts,
    /// and say what the running services hold, where any run.
    pub(super) fn start(
        &self,
        kind: Kind,
        setup: &Setup,
        lab: &Lab,
    ) -> Result<Option<[String; 2]>, String> {
        let credentials = setup.directory.join("credentials");
        self.act_as(setup, false);
        if matches!(kind, Kind::First | Kind::Milter) {
            self.forget(lab, &credentials);
            self.configure(setup, &lab.url, kind.milter());
            return Ok(None);
        }
        // The others start where both places agree.
        self.configure(setup, &lab.url, kind == Kind::MilterGone);
        let ready = setup.run(&[]);
        if ready.status.code() != Some(0) {
            return Err(format!("the run before the stop failed: {}", text(&ready)));
        }
        let held = holding(&credentials);
        match kind {
            Kind::Emptied => {
                for name in HELD {
                    fs::write(credentials.join(name), "").unwrap();
                }
            }
            Kind::Second => self.act_as(setup, true),
            Kind::MilterGone => self.configure(setup, &lab.url, false),
            _ => {}
        }
        Ok(Some(held))
    }

    /// Before the stops of `kind`. The operator's own keys fill the
    /// administrator's account for `Full`: Stalwart takes five API keys an
    /// account and refuses the sixth for its quota, as setup counts on.
    pub(super) fn enter(&mut self, kind: Kind, setup: &Setup, lab: &mut Lab) {
        let credentials = setup.directory.join("credentials");
        self.forget(lab, &credentials);
        if kind != Kind::Full {
            return;
        }
        self.configure(setup, &lab.url, false);
        let ready = setup.run(&[]);
        assert_eq!(ready.status.code(), Some(0), "{}", text(&ready));
        let admin = std::env::var("GARRISON_LAB_ADMIN").unwrap();
        let listed = lab.call("x:ApiKey/get", &json!({"ids": null}));
        let before = listed["list"].as_array().unwrap().len();
        let refusal = loop {
            let key = json!({
                "description": format!("an operator's own key {}", unique()),
                "permissions": {"@type": "Replace", "permissions": {"authenticate": true}},
                "allowedIps": {"127.0.0.1/32": true},
                "expiresAt": null,
            });
            let request = json!({"using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
                "methodCalls": [["x:ApiKey/set", {"create": {"k": key}}, "0"]]});
            let answer = lab.http("/jmap/", &admin, Some(&request));
            let payload = &answer["methodResponses"][0][1];
            let Some(id) = payload["created"]["k"]["id"].as_str() else {
                break payload["notCreated"]["k"].clone();
            };
            lab.created.push(("ApiKey".to_owned(), id.to_owned()));
            self.own.push(id.to_owned());
            assert!(self.own.len() <= 5, "Stalwart took more than five API keys");
        };
        assert_eq!(refusal["type"], "overQuota", "{refusal}");
        assert_eq!(before + self.own.len(), 5, "the keys the account took");
    }

    /// After the stops of `kind`: the operator's own keys go again.
    pub(super) fn leave(&mut self, lab: &mut Lab) {
        for id in self.own.drain(..) {
            lab.call("x:ApiKey/set", &json!({"destroy": [id]}));
            lab.created.retain(|(_, known)| *known != id);
        }
    }

    /// Setup's keys out of both administrators' accounts, the filter's
    /// entries out of Stalwart, which then reads its settings again, so
    /// that it no longer asks the filter, and the folder emptied, as before
    /// a first setup.
    pub(super) fn forget(&self, lab: &Lab, credentials: &Path) {
        let theirs = lab.call(
            "x:ApiKey/get",
            &json!({"accountId": self.account, "ids": null}),
        );
        for key in garrisons(&theirs) {
            lab.call(
                "x:ApiKey/set",
                &json!({"accountId": self.account, "destroy": [key]}),
            );
        }
        let entries = lab.call("x:MtaMilter/get", &json!({"ids": null}));
        let asking: Vec<&Value> = entries["list"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["host"] == "127.0.0.1" && entry["port"] == self.port)
            .collect();
        for entry in &asking {
            lab.call("x:MtaMilter/set", &json!({"destroy": [entry["id"]]}));
        }
        if !asking.is_empty() {
            lab.call(
                "x:Action/set",
                &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
            );
        }
        forget(lab, credentials);
    }
}

/// The IDs of the keys in a list of keys that are described as Garrison's.
fn garrisons(listed: &serde_json::Map<String, Value>) -> Vec<Value> {
    listed["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| {
            key["description"]
                .as_str()
                .is_some_and(|text| text.starts_with("garrison "))
        })
        .map(|key| key["id"].clone())
        .collect()
}
