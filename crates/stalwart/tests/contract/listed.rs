//! The pages of `JmapClient::listed` against Stalwart's own answers.

use std::collections::BTreeSet;
use std::sync::PoisonError;

use garrison_stalwart::Error;
use garrison_stalwart::jmap::Listed;
use garrison_testing::lab::{Lab, unique};
use serde_json::{Value, json};

use super::{ACCOUNTS, domain_id, keyed};

/// Stalwart gives a `/get` of all objects the first 500 of them alone, and
/// a query pages through all of them, with a get of each page's IDs in the
/// same request: `listed` reads every one, with the `/query` permission of
/// the kind beside its `/get` one, and without it is refused.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn objects_beyond_the_500_of_one_get_are_listed_in_pages() {
    let _alone = ACCOUNTS.write().unwrap_or_else(PoisonError::into_inner);
    let mut lab = Lab::from_environment();
    let tag = unique();
    let domain = domain_id(&lab);
    for batch in 0..6 {
        let create: serde_json::Map<String, Value> = (0..100)
            .map(|number| {
                let name = format!("{tag}x{batch}x{number}");
                let account = json!({"@type": "User", "name": name, "domainId": domain});
                (format!("u{number}"), account)
            })
            .collect();
        let created = lab.call("x:Account/set", &json!({"create": create}));
        for account in created["created"].as_object().unwrap().values() {
            let id = account["id"].as_str().unwrap().to_owned();
            lab.created.push(("Account".into(), id));
        }
    }
    let client = keyed(
        &mut lab,
        &tag,
        &["authenticate", "sysAccountGet", "sysAccountQuery"],
    );
    let all: Vec<Value> = client.get("Account", None, &["id"]).unwrap();
    assert_eq!(all.len(), 500);
    let listed: Listed<Value> = client.listed("Account", &["id"], 100_000, || true).unwrap();
    assert!(listed.total > 600, "{}", listed.total);
    let ids: BTreeSet<&str> = listed
        .objects
        .iter()
        .filter_map(|account| account["id"].as_str())
        .collect();
    assert_eq!(
        (listed.objects.len(), ids.len()),
        (listed.total, listed.total)
    );
    let unqueried = keyed(
        &mut lab,
        &format!("{tag}get"),
        &["authenticate", "sysAccountGet"],
    );
    assert_eq!(
        unqueried.listed::<Value>("Account", &["id"], 10, || true),
        Err(Error::Denied("x:Account/query was refused".to_owned()))
    );
}
