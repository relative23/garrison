//! The cards that name a file or a credential their check reads and does not
//! find, and what they say: each names what makes it. Every registered type
//! runs with the files its options name for it to read moved to a place
//! that does not exist, and without its credentials; a card that names such
//! a file, or a credential, is held to its words here, and there is no
//! other. A check that comes to name a missing file or credential fails this
//! test until its words are looked at and written here. The cards that need
//! the collector's key for Stalwart are held by `keyless_tests.rs`.

use std::collections::BTreeMap;

use super::ids_tests::cases;
use super::*;
use crate::context::{Context, DqsKey, Scrape, Use};
use crate::testing::{Canned, config, table};

/// Where every file the options name lies in this test: nowhere.
const GONE: &str = "/garrison-test-gone";

/// The findings of every card of every type that names a missing file or a
/// credential, by id.
fn named() -> BTreeMap<String, Vec<String>> {
    let work = tempfile::tempdir().unwrap();
    let mut named = BTreeMap::new();
    for case in cases(work.path()) {
        let mut raw = table(&format!("type = \"{}\"\n{}", case.kind, case.options));
        let options: Vec<&str> = build(std::slice::from_ref(&raw)).unwrap()[0]
            .paths()
            .into_iter()
            .filter(|path| path.used == Use::Reads)
            .map(|path| path.option)
            .collect();
        for option in options {
            raw.insert(option.to_owned(), format!("{GONE}/{option}").into());
        }
        let provider = build(&[raw]).unwrap().remove(0);
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        // The sign-in page is asked for under the issuer: no name to look up.
        config.deployment.issuer = "https://localhost:9".to_owned();
        let runner = Canned(String::new());
        let context = Context {
            metrics_credential: Scrape::Missing(format!(
                "{GONE}/credentials/metrics-credential is empty"
            )),
            dqs_key: DqsKey::Missing(format!(
                "{GONE}/credentials/spamhaus-dqs-key is empty; write the key of Spamhaus' Data \
                 Query Service into it"
            )),
            ..crate::testing::context(&config, &runner)
        };
        for card in provider.collect(&context).unwrap().observations {
            let about = |finding: &String| finding.contains(GONE) || finding.contains("credential");
            if card.findings.iter().any(about) {
                named.insert(card.id, card.findings);
            }
        }
    }
    named
}

/// Each card that names a missing file or credential says what makes it,
/// or names it: the command that writes it, the job that does, the setup,
/// or the setting and the command that name the right place.
#[test]
fn every_card_that_names_a_missing_file_or_credential_says_what_makes_it() {
    let found = named();
    let expected: BTreeMap<String, Vec<String>> = BTreeMap::from([
        (
            "clamav.configuration".to_owned(),
            [
                ("milter_config", "clamav-milter's"),
                ("clamd_config", "clamd's"),
            ]
            .map(|(option, whose)| {
                format!(
                    "{GONE}/{option} could not be read: No such file or directory (os error 2); \
                     set `{option}` to {whose} file, which `garrison detect --format toml` names."
                )
            })
            .to_vec(),
        ),
        (
            "clamav.signatures".to_owned(),
            vec![format!(
                "None of the listed signature files is in {GONE}/database_directory: set \
                 `database_directory` to clamd's, which `garrison detect --format toml` names, \
                 or `signatures` to the files it holds."
            )],
        ),
        (
            "bulwark.plugins".to_owned(),
            vec![format!(
                "No bundle's integrity is known: there is no plugins/registry.json in \
                 {GONE}/admin_directory; set `admin_directory` to Bulwark's administration folder, \
                 which holds it."
            )],
        ),
        (
            "backup-check.restic".to_owned(),
            vec![format!(
                "The repository's state is not known: no report at {GONE}/path; `garrison \
                 backup-check restic` writes it."
            )],
        ),
        (
            "prometheus.exporter".to_owned(),
            vec![format!(
                "No scrape credential: {GONE}/credentials/metrics-credential is empty. Run \
                 `garrison stalwart setup`, which writes it while Stalwart's exporter is \
                 Garrison's or off; for an exporter of another's, write its user name and \
                 password into it as configuration.md says (collector.metrics_credential)."
            )],
        ),
        (
            "receipt.restore".to_owned(),
            vec![format!(
                "No receipt at {GONE}/path: the job that writes it has written none there."
            )],
        ),
    ]);
    assert_eq!(found, expected);
}
