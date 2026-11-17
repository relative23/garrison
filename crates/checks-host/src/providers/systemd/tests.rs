use super::*;

/// What `pattern` relies on: every pattern of this file compiles.
#[test]
fn the_patterns_compile() {
    for found in [&TIMESTAMP, &CALENDAR, &INTERVAL, &SPAN] {
        LazyLock::force(found);
    }
}

fn properties(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn states_follow_systemd_and_idle_jobs_may_rest() {
    let loaded = |active: &str| properties(&[("LoadState", "loaded"), ("ActiveState", active)]);
    for (values, idle, expected) in [
        (properties(&[]), false, State::Unknown),
        (
            properties(&[("ActiveState", "active")]),
            false,
            State::Unknown,
        ),
        (
            properties(&[("LoadState", "not-found"), ("ActiveState", "active")]),
            false,
            State::Failed,
        ),
        (loaded("failed"), true, State::Failed),
        (loaded("active"), false, State::Ok),
        (loaded("activating"), true, State::Ok),
        (loaded("deactivating"), true, State::Ok),
        (loaded("reloading"), false, State::Warning),
        (loaded("inactive"), false, State::Failed),
        (
            properties(&[
                ("LoadState", "loaded"),
                ("ActiveState", "inactive"),
                ("Result", "success"),
            ]),
            true,
            State::Ok,
        ),
        (
            properties(&[
                ("LoadState", "loaded"),
                ("ActiveState", "inactive"),
                ("Result", "exit-code"),
            ]),
            true,
            State::Failed,
        ),
    ] {
        assert_eq!(classify(&values, idle), expected, "{values:?} idle={idle}");
    }
}
