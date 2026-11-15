//! The key of Spamhaus' Data Query Service: a zone written without it,
//! `zen.dq.spamhaus.net`, is asked with the key the collector reads from
//! `collector.dqs_key`, which check-config needs for such a zone; a zone
//! that holds its key in garrison.toml, which every user of the host may
//! read, works as before and is warned of, without the key in the warning.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

mod support;

use support::{prepared, run, text};

/// A reputation check of one mail host against `lists`.
fn reputation(lists: &str) -> String {
    format!(
        "\n[[providers]]\ntype = \"reputation\"\nhosts = [\"mail.example.test\"]\n\
         lists = [{lists}]\nlists_ipv6 = []\n"
    )
}

#[test]
fn a_zone_without_its_key_needs_the_key_setting_and_one_with_its_key_is_warned_of() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let base = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, base.clone() + &reputation("\"zen.dq.spamhaus.net\"")).unwrap();
    let refused = run(directory.path(), &["check-config"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stdout));
    assert!(
        text(&refused.stderr).contains(
            "Configuration not usable: providers[1].lists names zen.dq.spamhaus.net, a list of \
             Spamhaus' Data Query Service written without its key, but collector.dqs_key is \
             not set, so it could not be asked. Keep the key in \
             /etc/garrison/credentials/spamhaus-dqs-key (root, mode 0600) and set \
             collector.dqs_key = \"credential:spamhaus-dqs-key\".\n"
        ),
        "{}",
        text(&refused.stderr)
    );

    let with_key = base.replacen(
        "[collector]\n",
        "[collector]\ndqs_key = \"credential:spamhaus-dqs-key\"\n",
        1,
    );
    std::fs::write(&path, with_key + &reputation("\"zen.dq.spamhaus.net\"")).unwrap();
    let valid = run(directory.path(), &["check-config"]);
    assert_eq!(valid.status.code(), Some(0), "{}", text(&valid.stderr));
    assert!(!text(&valid.stderr).contains("Data Query Service"));

    let key = "abcdefghijklmnopqrstuvwxyz";
    let zone = format!("\"{key}.zen.dq.spamhaus.net\"");
    std::fs::write(&path, base + &reputation(&zone)).unwrap();
    let warned = run(directory.path(), &["check-config"]);
    assert_eq!(warned.status.code(), Some(0), "{}", text(&warned.stderr));
    let said = text(&warned.stderr);
    assert!(
        said.contains(
            "Warning: providers[1].lists names ….zen.dq.spamhaus.net with the key of Spamhaus' \
             Data Query Service in it, in garrison.toml, which every user of this host may \
             read. Write the zone without the key, zen.dq.spamhaus.net, keep the key in \
             /etc/garrison/credentials/spamhaus-dqs-key (root, mode 0600) and set \
             collector.dqs_key = \"credential:spamhaus-dqs-key\".\n"
        ),
        "{said}"
    );
    assert!(!said.contains(key), "{said}");
}
