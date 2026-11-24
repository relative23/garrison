//! A reading is made with the resolver it asks and the options that decide
//! what it asks. One made with others is made again in the next run, not
//! hours later: another resolver, a list taken out or added, other mail
//! hosts or another `max_domains` show at once. So is one that an earlier
//! release kept, which says nothing of them.

use garrison_core::observations::{Observation, State};
use garrison_core::time;
use garrison_testing::http::{json as answer_json, serve};

use super::tests::{Zone, mail_host};
use super::*;
use crate::providers::dns::domains_tests::twenty_one_domains;
use crate::providers::dns::stand_in::resolver_until;
use crate::testing::{Canned, Remembered, config, now, table};

/// The Blocklists card of a run `later` seconds after the tests' clock, of
/// a check with `options`, where Stalwart at `stalwart` names the domains.
fn blocklists(options: &str, memory: &Remembered, later: i64, stalwart: &str) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    stalwart.clone_into(&mut config.deployment.stalwart_url);
    let runner = Canned(String::new());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + later).unwrap(),
        native_key: Some("key".into()),
        memory,
        ..crate::testing::context(&config, &runner)
    };
    let provider = Reputation::new(&table(&format!("type = \"reputation\"\n{options}"))).unwrap();
    provider.collect(&context).unwrap().observations.remove(0)
}

/// When the reading of `card` was made, in seconds after the tests' clock.
fn made_at(card: &Observation) -> i64 {
    let asked = card.fields[1].value.as_str().unwrap();
    time::parse(asked).unwrap().as_second() - now().as_second()
}

#[test]
fn a_reading_made_with_other_options_is_made_again_at_once() {
    let (first, first_resolver) = resolver_until(mail_host(), |_| false);
    let (second, second_resolver) = resolver_until(mail_host(), |_| false);
    let options = |resolver, hosts: &str, lists: &str, lists_ipv6: &str| {
        format!(
            "resolver = \"{resolver}\"\nhosts = [{hosts}]\nlists = [{lists}]\n\
             lists_ipv6 = [{lists_ipv6}]"
        )
    };
    let (host, list) = ("\"mail.example.test\"", "\"a.example.org\"");
    let options_before = options(first, host, list, list);
    for (option, changed, again) in [
        ("nothing", options_before.clone(), false),
        ("resolver", options(second, host, list, list), true),
        (
            "hosts",
            options(first, &format!("{host}, \"mx2.example.test\""), list, list),
            true,
        ),
        (
            "lists",
            options(first, host, "\"b.example.org\"", list),
            true,
        ),
        ("lists_ipv6", options(first, host, list, ""), true),
        // Where its cards show decides nothing of what is asked.
        (
            "modules",
            format!("{options_before}\nmodules = [\"dashboard\"]"),
            false,
        ),
    ] {
        let memory = Remembered::default();
        let made = blocklists(&options_before, &memory, 0, "http://127.0.0.1:9");
        assert_eq!(made_at(&made), 0, "{option}");
        let next = blocklists(&changed, &memory, 60, "http://127.0.0.1:9");
        assert_eq!(made_at(&next), if again { 60 } else { 0 }, "{option}");
    }
    first_resolver.questions();
    second_resolver.questions();
}

/// Without `hosts`, the mail hosts are those of Stalwart's first
/// `max_domains` domains: another number makes the reading again, and
/// Stalwart is asked again for them.
#[test]
fn a_reading_made_for_other_domains_is_made_again_at_once() {
    let (resolver, stopping) = resolver_until(Zone::new(), |_| false);
    let options = |more: &str| format!("resolver = \"{resolver}\"\nlists = []\n{more}");
    for (changed, again) in [("", false), ("max_domains = 21", true)] {
        let memory = Remembered::default();
        let stalwart = serve(vec![answer_json(&twenty_one_domains())]);
        let made = blocklists(&options(""), &memory, 0, &stalwart.url);
        stalwart.requests();
        let answers = if again {
            vec![answer_json(&twenty_one_domains())]
        } else {
            Vec::new()
        };
        let stalwart = serve(answers);
        let next = blocklists(&options(changed), &memory, 60, &stalwart.url);
        stalwart.requests();
        assert_eq!(
            (made_at(&made), made_at(&next)),
            (0, if again { 60 } else { 0 }),
            "{changed}"
        );
    }
    stopping.questions();
}

/// A reading that an earlier release kept says nothing of what it was made
/// with: it is made again in the first run, however recent it is.
#[test]
fn a_reading_an_earlier_release_kept_is_made_again_at_once() {
    let (resolver, stopping) = resolver_until(mail_host(), |_| false);
    let earlier = serde_json::json!({
        "at": now().as_second() - 60,
        "hosts": ["mail.example.test"],
        "addresses": [],
        "problem": null,
    });
    let memory = Remembered::default();
    memory
        .0
        .borrow_mut()
        .insert(MEMORY.to_owned(), earlier.to_string());
    let options = format!("resolver = \"{resolver}\"\nhosts = [\"mail.example.test\"]");
    let card = blocklists(&options, &memory, 0, "http://127.0.0.1:9");
    assert_eq!(made_at(&card), 0);
    // It was asked: the mail host's addresses first.
    assert_eq!(
        stopping.questions().first(),
        Some(&("mail.example.test".to_owned(), Kind::A.code()))
    );
}

/// Without `hosts`, the check asks Stalwart for the mail hosts. Where
/// Stalwart did not give them with the collector's key, as before `garrison
/// stalwart setup` gave the key its rights, while it was down, over its
/// rate limit, in an answer this release does not read, or named none, the
/// reading is made again in the next run, which asks Stalwart alone: once
/// Stalwart gives them, the cards follow at once, not an hour later.
#[test]
fn a_reading_stalwart_gave_no_mail_hosts_for_is_made_again_in_the_next_run() {
    use garrison_testing::http::answer;
    let (resolver, stopping) = resolver_until(mail_host(), |_| false);
    let options =
        format!("resolver = \"{resolver}\"\nlists = [\"up.example.org\"]\nlists_ipv6 = []");
    let domains = |zone: Option<&str>| {
        answer_json(&crate::providers::dns::domains_tests::domains_value(
            &serde_json::json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone}]),
        ))
    };
    let forbidden = answer_json(
        &serde_json::json!({"methodResponses": [["error", {"type": "forbidden"}, "0"]]}),
    );
    for (failure, first) in [
        ("a method refused the key", forbidden),
        ("the key refused", answer(403, "")),
        ("an outage", answer(503, "")),
        ("its rate limit", answer(429, "")),
        (
            "an answer this release does not read",
            answer(200, "<html>"),
        ),
        ("no mail host", domains(None)),
    ] {
        let memory = Remembered::default();
        let stalwart = serve(vec![first]);
        let before = blocklists(&options, &memory, 0, &stalwart.url);
        stalwart.requests();
        assert_eq!(before.state, State::Unknown, "{failure}");
        let stalwart = serve(vec![domains(Some(
            "example.test. IN MX 10 mail.example.test.\n",
        ))]);
        let after = blocklists(&options, &memory, 60, &stalwart.url);
        stalwart.requests();
        assert_eq!(
            (made_at(&after), after.state),
            (60, State::Ok),
            "{failure}: {:?}",
            after.findings
        );
    }
    stopping.questions();
}
