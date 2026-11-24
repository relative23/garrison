//! doctor's lines on hosts that are broken in one way each. A line that
//! says "ok" has looked at what it claims, as the service that needs it
//! meets it; one that could not look says so with the reason; and a fix it
//! names works from the state it found. So on each host here the check that
//! looks at what is broken must say something other than "ok", with the fix
//! that mends it, or, where it could not look, why.

use super::{Finding, Level};

mod local;
mod outside;

/// A host broken in one way, and what doctor must say of it.
struct Broken {
    /// What is broken.
    host: &'static str,
    /// What the check that looks at it found there.
    found: Vec<Finding>,
    /// Words of the line that must say it.
    said: String,
    /// Words its fix must hold; `None` for a line that says why the check
    /// could not look, which is unknown and names no fix.
    fix: Option<String>,
}

/// Every "ok" doctor can say, in the file that says it, with what it
/// claims and the hosts where that does not hold. A new ok gets its line
/// here; `every_ok_of_doctor_has_a_host_where_it_does_not_hold` counts them.
/// The hosts where one claim does not hold.
type Hosts = &'static [fn() -> Broken];

const PLACES: [(&str, &str, Hosts); 24] = [
    (
        "host.rs",
        "a release, and the one before",
        &[local::no_release],
    ),
    ("host.rs", "a release, none before", &[local::no_release]),
    ("host.rs", "a unit is active", &[local::unit_failed]),
    (
        "host.rs",
        "the last collection run finished lately",
        &[local::collector_stopped],
    ),
    (
        "host.rs",
        "the clock is synchronized",
        &[local::clock_unsynchronized],
    ),
    ("host.rs", "a folder has room", &[local::space_unknown]),
    (
        "host.rs",
        "nginx may connect to every port",
        &[local::selinux_module_for_another_port],
    ),
    (
        "host.rs",
        "the SELinux module lets nginx reach web.port",
        &[local::selinux_module_for_another_port],
    ),
    (
        "host.rs",
        "a Stalwart event arrived lately",
        &[local::events_database_is_a_folder],
    ),
    (
        "files.rs",
        "a credential is root's alone",
        &[local::key_not_roots],
    ),
    (
        "files.rs",
        "an empty file means none",
        &[
            local::metrics_credential_empty_where_read,
            local::metrics_credential_as_user_and_password,
            local::dqs_key_of_two_words,
        ],
    ),
    (
        "policy.rs",
        "the broker may read the access policy",
        &[local::policy_root_alone],
    ),
    (
        "policy.rs",
        "the access policy grants as the broker reads it",
        &[
            local::policy_binds_nobody,
            local::policy_names_a_dropped_action,
        ],
    ),
    (
        "keys.rs",
        "Stalwart takes a service's API key from this host",
        &[outside::stalwart_does_not_know_the_brokers_key],
    ),
    (
        "milter.rs",
        "the macro milter answers",
        &[local::milter_silent],
    ),
    (
        "milter.rs",
        "Stalwart asks the macro milter as configured",
        &[local::milter_on_another_port],
    ),
    (
        "notify.rs",
        "the notification channels can send",
        &[local::channel_without_its_address],
    ),
    (
        "public.rs",
        "Garrison's certificate is valid on its port",
        &[outside::origin_with_a_port],
    ),
    (
        "public.rs",
        "Garrison answers a visitor",
        &[outside::nginx_answers_502],
    ),
    (
        "public.rs",
        "nginx sends Strict-Transport-Security",
        &[outside::no_hsts],
    ),
    (
        "public.rs",
        "Stalwart's public hosts do not serve its metrics",
        &[outside::metrics_public],
    ),
    (
        "public.rs",
        "Stalwart knows Garrison's sign-in client",
        &[outside::issuer_answers_with_a_web_page],
    ),
    (
        "public.rs",
        "Stalwart names itself deployment.issuer",
        &[outside::issuer_states_another_name],
    ),
    (
        "public.rs",
        "the issuer's name shows Stalwart's sign-in page",
        &[outside::sign_in_page_answers_404],
    ),
];

/// doctor's checks, as their source holds them.
const CHECKS: [(&str, &str); 8] = [
    ("mod.rs", include_str!("mod.rs")),
    ("host.rs", include_str!("host.rs")),
    ("files.rs", include_str!("files.rs")),
    ("keys.rs", include_str!("keys.rs")),
    ("policy.rs", include_str!("policy.rs")),
    ("milter.rs", include_str!("milter.rs")),
    ("notify.rs", include_str!("notify.rs")),
    ("public.rs", include_str!("public.rs")),
];

/// What is wrong with what doctor said on `broken`, if anything.
fn fault(broken: &Broken) -> Option<String> {
    let lines: Vec<String> = broken.found.iter().map(Finding::line).collect();
    let Some(finding) = broken
        .found
        .iter()
        .find(|finding| finding.what.contains(&broken.said))
    else {
        return Some(format!(
            "{}: no line says {:?}:\n{}",
            broken.host,
            broken.said,
            lines.join("\n")
        ));
    };
    if finding.level == Level::Ok {
        return Some(format!("{}: {}", broken.host, finding.line()));
    }
    match &broken.fix {
        Some(fix)
            if !finding
                .fix
                .as_deref()
                .is_some_and(|text| text.contains(fix.as_str())) =>
        {
            Some(format!(
                "{}: the fix does not name {fix:?}:\n{}",
                broken.host,
                finding.line()
            ))
        }
        None if finding.level != Level::Unknown => Some(format!(
            "{}: a check that could not look is unknown:\n{}",
            broken.host,
            finding.line()
        )),
        _ => None,
    }
}

#[test]
fn on_a_broken_host_no_check_says_ok_of_what_is_broken() {
    let faults: Vec<String> = PLACES
        .iter()
        .flat_map(|(_, _, hosts)| hosts.iter())
        .filter_map(|host| fault(&host()))
        .collect();
    assert_eq!(faults, Vec::<String>::new(), "{}", faults.join("\n\n"));
}

/// Each file of doctor's checks says "ok" in as many places as `PLACES`
/// holds for it, so that a new ok cannot go without a host where it does
/// not hold.
#[test]
fn every_ok_of_doctor_has_a_host_where_it_does_not_hold() {
    for (file, source) in CHECKS {
        // The product's code, before the file's tests.
        let product = source.split("#[cfg(test)]").next().unwrap_or_default();
        let said = product.matches("Finding::ok(").count();
        let held = PLACES.iter().filter(|(place, ..)| *place == file).count();
        assert_eq!(
            said, held,
            "{file} says ok in {said} places, and PLACES holds {held} of them: give each new \
             one a host where it does not hold"
        );
    }
}
