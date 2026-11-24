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

/// The pages list the objects of a kind oldest first, as a `/get` of all of
/// them lists them and as the checks of 0.1.2 took them: one made later,
/// also after one was removed, comes last and pushes none of the first out.
/// So for the domains, of which the network checks take the first
/// `max_domains`, and the accounts, of which the mailbox storage takes the
/// first `max_accounts`.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_pages_list_the_oldest_first_and_one_made_later_last() {
    let _alone = ACCOUNTS.write().unwrap_or_else(PoisonError::into_inner);
    let mut lab = Lab::from_environment();
    let tag = unique();
    let domain = domain_id(&lab);
    let client = keyed(
        &mut lab,
        &tag,
        &[
            "authenticate",
            "sysDomainGet",
            "sysDomainQuery",
            "sysAccountGet",
            "sysAccountQuery",
        ],
    );
    let mut seen = Vec::new();
    for kind in ["Domain", "Account"] {
        // By name, the ones made later would come first; the one made after
        // a removal still comes last, as no ID is given again.
        for name in ["zz", "aa", "mm"] {
            if name == "mm" {
                let (_, first) = lab.created.remove(lab.created.len() - 2);
                lab.call(&format!("x:{kind}/set"), &json!({"destroy": [first]}));
            }
            let object = if kind == "Domain" {
                json!({"name": format!("{name}{tag}.example.test"), "dkimManagement": {"@type": "Manual"}})
            } else {
                json!({"@type": "User", "name": format!("{name}{tag}"), "domainId": domain})
            };
            lab.create(kind, &object);
        }
        let all = lab.call(
            &format!("x:{kind}/get"),
            &json!({"ids": null, "properties": ["id"]}),
        );
        let listed = client.listed::<Value>(kind, &["id"], 100_000, || true);
        let newest = lab.created.last().map(|(_, id)| json!({"id": id}));
        seen.push((kind, all["list"].as_array().cloned(), listed, newest));
    }
    // What was made goes before anything is judged, so that a failure
    // leaves no domain behind for the tests after this one.
    drop(lab);
    for (kind, all, listed, newest) in seen {
        let (all, listed) = (all.unwrap(), listed.unwrap().objects);
        assert_eq!(listed[..all.len()], all[..], "{kind}");
        assert_eq!(listed.last(), newest.as_ref(), "{kind}");
    }
}
