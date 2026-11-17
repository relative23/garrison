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

const HOSTS: [fn() -> Broken; 12] = [
    local::events_database_is_a_folder,
    outside::origin_with_a_port,
    outside::issuer_answers_with_a_web_page,
    outside::issuer_states_another_name,
    local::policy_root_alone,
    local::policy_binds_nobody,
    local::policy_names_a_dropped_action,
    local::metrics_credential_as_user_and_password,
    local::dqs_key_of_two_words,
    local::selinux_module_for_another_port,
    local::milter_on_another_port,
    outside::nginx_answers_502,
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
    let faults: Vec<String> = HOSTS.iter().filter_map(|host| fault(&host())).collect();
    assert_eq!(faults, Vec::<String>::new(), "{}", faults.join("\n\n"));
}
