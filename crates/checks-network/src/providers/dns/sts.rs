//! The MTA-STS policy of a domain that publishes the record for one.
//!
//! The record `_mta-sts.<domain>` only says that a policy exists. The policy
//! itself is a file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`; a
//! sender that honours it delivers to the hosts it names and to no other. A
//! record without a readable policy, or a policy that leaves a mail host out,
//! stops those senders. The file is fetched once an hour.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::context::Context;
use crate::fetch;

const EVERY: i64 = 3600;

/// A policy as far as it is read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Policy {
    pub(super) mode: String,
    pub(super) hosts: Vec<String>,
    pub(super) max_age: Option<u64>,
}

/// What the status database keeps of the last fetch.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Fetched {
    at: i64,
    outcome: Result<Policy, String>,
}

/// The policy a file states, or why it states none (RFC 8461, section 3.2).
pub(super) fn parse(text: &str) -> Result<Policy, String> {
    let mut policy = Policy::default();
    let mut version = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "version" => version = Some(value.to_owned()),
            "mode" => value.clone_into(&mut policy.mode),
            "mx" => policy
                .hosts
                .push(value.trim_end_matches('.').to_lowercase()),
            "max_age" => policy.max_age = value.parse().ok(),
            _ => {}
        }
    }
    if version.as_deref() != Some("STSv1") {
        return Err("the file is no MTA-STS policy (no `version: STSv1`)".to_owned());
    }
    if !["enforce", "testing", "none"].contains(&policy.mode.as_str()) {
        return Err("the policy names no mode".to_owned());
    }
    Ok(policy)
}

/// Whether the policy lets a sender deliver to `host`: by its name, or by a
/// pattern such as `*.example.org` that stands for one more label.
pub(super) fn names(policy: &Policy, host: &str) -> bool {
    let host = host.to_lowercase();
    policy
        .hosts
        .iter()
        .any(|pattern| match pattern.strip_prefix("*.") {
            Some(parent) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == parent),
            None => *pattern == host,
        })
}

/// The policy at `url`, from the status database where it was fetched within
/// the hour.
pub(super) fn policy(context: &Context<'_>, domain: &str, url: &str) -> Result<Policy, String> {
    let key = format!("dns.sts.{domain}");
    let now = context.now.as_second();
    let kept: Option<Fetched> = context
        .memory
        .recall(&key)
        .and_then(|text| serde_json::from_str(&text).ok());
    if let Some(kept) = kept.filter(|kept| (0..EVERY).contains(&(now - kept.at))) {
        return kept.outcome;
    }
    let outcome = fetch::get(url, &fetch::roots()).and_then(|answer| {
        if answer.status == 200 {
            parse(&answer.body)
        } else {
            Err(format!("the server answered {}", answer.status))
        }
    });
    let fetched = Fetched { at: now, outcome };
    if let Ok(text) = serde_json::to_string(&fetched) {
        context.memory.keep(&key, &text);
    }
    fetched.outcome
}

/// What the policy means for the domain's mail hosts: a line for the table
/// and, where a sender that honours the policy would stop, a finding.
pub(super) fn judged(
    domain: &str,
    hosts: &[String],
    read: &Result<Policy, String>,
) -> (String, &'static str, Option<String>) {
    match read {
        Err(reason) => (
            String::new(),
            "not readable",
            Some(format!(
                "{domain} publishes an MTA-STS record, but its policy could not be read: {reason}."
            )),
        ),
        Ok(policy) => {
            let stated = format!(
                "mode {}; mx {}{}",
                policy.mode,
                policy.hosts.join(", "),
                policy
                    .max_age
                    .map(|age| format!("; max_age {age}"))
                    .unwrap_or_default()
            );
            let left: Vec<&str> = hosts
                .iter()
                .filter(|host| !names(policy, host))
                .map(String::as_str)
                .collect();
            if policy.mode == "none" || left.is_empty() {
                (stated, "fits", None)
            } else {
                let consequence = if policy.mode == "enforce" {
                    "senders that honour it do not deliver there"
                } else {
                    "senders that honour it will not deliver there once the mode is enforce"
                };
                (
                    stated,
                    "leaves a mail host out",
                    Some(format!(
                        "The MTA-STS policy of {domain} does not name {}: {consequence}.",
                        left.join(", ")
                    )),
                )
            }
        }
    }
}

/// The table's row for the policy of `domain` and, where it stops senders, a
/// finding. `url` is where the tests serve a policy.
pub(super) fn checked(
    context: &Context<'_>,
    domain: &str,
    hosts: &[String],
    url: Option<&str>,
) -> (Vec<serde_json::Value>, Option<String>) {
    let own = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let read = policy(context, domain, url.unwrap_or(&own));
    let (stated, result, finding) = judged(domain, hosts, &read);
    let row = vec![
        json!(format!("mta-sts.{domain}")),
        json!("policy"),
        json!("optional"),
        json!(format!("mx {}", hosts.join(", "))),
        json!(stated.chars().take(120).collect::<String>()),
        json!(result),
    ];
    (row, finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.test\r\nmx: *.backup.example.net.\r\nmax_age: 604800\r\n";

    #[test]
    fn a_policy_is_read_line_by_line() {
        let policy = parse(POLICY).unwrap();
        assert_eq!(
            policy,
            Policy {
                mode: "enforce".into(),
                hosts: vec!["mail.example.test".into(), "*.backup.example.net".into()],
                max_age: Some(604_800),
            }
        );
        assert_eq!(
            parse("<html>Not found</html>").unwrap_err(),
            "the file is no MTA-STS policy (no `version: STSv1`)"
        );
        assert_eq!(
            parse("version: STSv1\nmx: a.example").unwrap_err(),
            "the policy names no mode"
        );
    }

    #[test]
    fn a_pattern_stands_for_one_label_and_no_more() {
        let policy = parse(POLICY).unwrap();
        assert!(names(&policy, "Mail.Example.Test"));
        assert!(names(&policy, "mx1.backup.example.net"));
        assert!(!names(&policy, "backup.example.net"));
        assert!(!names(&policy, "a.b.backup.example.net"));
        assert!(!names(&policy, "other.example.test"));
    }

    #[test]
    fn a_policy_that_leaves_a_mail_host_out_or_cannot_be_read_is_a_finding() {
        let hosts = vec![
            "mail.example.test".to_owned(),
            "mx2.example.test".to_owned(),
        ];
        let (stated, result, finding) = judged("example.test", &hosts, &parse(POLICY));
        assert_eq!(
            stated,
            "mode enforce; mx mail.example.test, *.backup.example.net; max_age 604800"
        );
        assert_eq!(result, "leaves a mail host out");
        assert_eq!(
            finding.unwrap(),
            "The MTA-STS policy of example.test does not name mx2.example.test: senders that honour it do not deliver there."
        );
        let testing = parse(&POLICY.replace("enforce", "testing"));
        assert!(
            judged("example.test", &hosts, &testing)
                .2
                .unwrap()
                .ends_with("once the mode is enforce.")
        );
        // All hosts named, or a policy that asks for nothing: in order.
        assert_eq!(
            judged("example.test", &hosts[..1], &parse(POLICY)).1,
            "fits"
        );
        assert_eq!(
            judged(
                "example.test",
                &hosts,
                &parse(&POLICY.replace("enforce", "none"))
            )
            .2,
            None
        );
        let unread = judged(
            "example.test",
            &hosts,
            &Err("the server answered 404".to_owned()),
        );
        assert_eq!(unread.1, "not readable");
        assert_eq!(
            unread.2.unwrap(),
            "example.test publishes an MTA-STS record, but its policy could not be read: the server answered 404."
        );
    }
}
