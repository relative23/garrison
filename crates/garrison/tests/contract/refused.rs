//! What setup says where something refuses it, and that it leaves both
//! places agreeing: the administrator refused, a credentials folder it
//! cannot write, and key files whose secrets Stalwart no longer knows.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use garrison_testing::lab::{Lab, random_hex, unique};
use garrison_testing::{config_text, write_private};
use serde_json::json;

use super::together::{Capture, assert_together};
use super::{Setup, forget, lab, text};

/// The keys in the lab described as Garrison's.
fn garrisons_keys(lab: &Lab) -> usize {
    let listed = lab.call("x:ApiKey/get", &json!({"ids": null}));
    listed["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| {
            key["description"]
                .as_str()
                .is_some_and(|text| text.starts_with("garrison "))
        })
        .count()
}

/// A wrong password, an unknown user and an API key Stalwart does not know
/// are all answered 401, an API key of the administrator's that does not
/// allow this host's address 403: setup says that the administrator was
/// refused and what to check, where it said "x:ApiKey/get: HTTP 401", and
/// changes nothing. A user without administrator rights gets as far as the
/// first key, which Stalwart does not let it make.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_refused_administrator_is_said_as_such() {
    let (_guard, mut lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    forget(&lab, &setup.directory.join("credentials"));
    let elsewhere = lab.call(
        "x:ApiKey/set",
        &json!({"create": {"k": {
            "description": "an administrator's key for loopback alone",
            "permissions": {"@type": "Replace", "permissions": {"authenticate": true}},
            "allowedIps": {"127.0.0.1/32": true},
            "expiresAt": null,
        }}}),
    );
    let key = &elsewhere["created"]["k"];
    let domains = lab.call("x:Domain/get", &json!({"ids": null, "properties": ["id"]}));
    let (user, password) = (unique(), random_hex(18));
    lab.create(
        "Account",
        &json!({
            "@type": "User",
            "name": user,
            "domainId": domains["list"][0]["id"],
            "credentials": {"0": {"@type": "Password", "secret": password}},
            "roles": {"@type": "User"},
            "permissions": {"@type": "Inherit"},
        }),
    );
    let refused = [
        (
            json!({"username": lab.admin_name(), "secret": "not-the-password"}),
            401,
        ),
        (
            json!({"username": "nobody-here", "secret": "not-the-password"}),
            401,
        ),
        (
            json!({"apiKey": "an-api-key-that-stalwart-does-not-know"}),
            401,
        ),
        (json!({"apiKey": key["secret"]}), 403),
        (json!({"username": user, "secret": password}), 200),
    ];
    let mut said = Vec::new();
    for (wrong, status) in refused {
        write_private(Path::new(&setup.credential), wrong.to_string().as_bytes());
        let output = setup.run(&[]);
        said.push((
            status,
            output.status.code(),
            text(&output),
            garrisons_keys(&lab),
        ));
    }
    lab.call("x:ApiKey/set", &json!({"destroy": [key["id"]]}));
    for (status, code, said, keys) in said {
        let expected = match status {
            401 => {
                "Stalwart refused the administrator (HTTP 401): check the user name and the \
                 password, or the API key."
            }
            403 => "Stalwart refused the administrator from this host's address (HTTP 403)",
            _ => {
                "Stalwart refused the administrator the API key 'garrison broker', since it may \
                 not grant the key's permissions: run setup as an administrator who holds them"
            }
        };
        assert!(
            code == Some(1) && said.contains(expected) && keys == 0,
            "{status}: exit {code:?}, {keys} keys of Garrison's: {said}"
        );
    }
}

/// Without root on an installed host, the credentials folder is root's:
/// setup stops before it asks Stalwart for anything, names the folder and
/// says to run it as root, where it once made a key in Stalwart and lost
/// its secret ("Permission denied (os error 13)"). Shown with a folder of
/// this user's that it may not write, and with root's own, where this user
/// may not even look.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn setup_refuses_a_credentials_folder_it_cannot_write_before_stalwart_changes() {
    if rustix::process::geteuid().is_root() {
        println!("skipped: root may write any folder");
        return;
    }
    let (_guard, lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    fs::create_dir(&credentials).unwrap();
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o500)).unwrap();
    let settings = setup.directory.join("garrison.toml");
    let own = config_text(&setup.directory, &lab.url);
    let named = format!("credentials_directory = \"{}\"", credentials.display());
    let roots = own.replace(&named, "credentials_directory = \"/root\"");
    let mut folders = vec![(own, credentials.display().to_string())];
    if fs::metadata("/root").is_ok() && fs::read_dir("/root").is_err() {
        folders.push((roots, "/root".to_owned()));
    }
    let mut outcomes = Vec::new();
    for (configuration, folder) in folders {
        fs::write(&settings, configuration).unwrap();
        let output = setup.run(&[]);
        outcomes.push((
            folder,
            output.status.code(),
            text(&output),
            garrisons_keys(&lab),
        ));
        // Only Stalwart's side: the folder is not this user's to empty.
        forget(&lab, Path::new("/nonexistent"));
    }
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700)).unwrap();
    let wrong: Vec<String> = outcomes
        .into_iter()
        .filter(|(folder, code, said, keys)| {
            let named = format!("Setup cannot write the credentials folder {folder}");
            *code != Some(2)
                || !said.contains(&named)
                || !said.contains("Run it as root, as `sudo garrison stalwart setup`")
                || *keys != 0
        })
        .map(|(folder, code, said, keys)| {
            format!(
                "{folder}: exit {code:?}, {keys} key(s) of Garrison's in Stalwart after it: {said}"
            )
        })
        .collect();
    assert_eq!(wrong, Vec::<String>::new());
}

/// The credentials folder put back from a copy older than the last rotation,
/// as after the restore onto a new host that operations.md describes: its
/// keys are ones Stalwart no longer has. Stalwart answers such a key 401 and
/// a key it knows from an address the key does not allow 403, so a plain run
/// makes the keys anew, instead of naming a bridge network, and gives the
/// webhook and the exporter the folder's secrets.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn key_files_stalwart_no_longer_knows_get_new_keys() {
    let (_guard, lab) = lab();
    let capture = Capture::start();
    let setup = Setup::new(&lab, &capture.url);
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    let first = setup.run(&[]);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    let copy = setup.directory.join("copy");
    fs::create_dir(&copy).unwrap();
    for entry in fs::read_dir(&credentials).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
    }
    let rotated = setup.run(&["--rotate"]);
    assert_eq!(rotated.status.code(), Some(0), "{}", text(&rotated));
    for entry in fs::read_dir(&copy).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), credentials.join(entry.file_name())).unwrap();
    }
    let output = setup.run(&[]);
    let said = text(&output);
    assert_eq!(output.status.code(), Some(0), "{said}");
    for name in ["broker-native-key", "collector-native-key"] {
        assert!(
            said.contains(&format!(
                "Stalwart did not know the API key in {}; made a new one",
                credentials.join(name).display()
            )),
            "{said}"
        );
    }
    assert!(
        said.contains("Restart garrison-ingest and garrison-broker"),
        "{said}"
    );
    assert_together(&lab, &credentials, &setup.gateway, &capture, "restored");
    forget(&lab, &credentials);
}
