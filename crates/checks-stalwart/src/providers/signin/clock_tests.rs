//! The page's certificate is judged at the run's time, as every check judges
//! what it finds; `garrison doctor`, asking by hand, judges it by the clock.

use std::sync::Arc;

use garrison_core::time;
use garrison_testing::http::serve;
use garrison_testing::tls::serve_until;

use super::tests::{STALWART, html, in_order};
use super::*;
use crate::context::Deadline;
use crate::testing::{Canned, Remembered, config, table};

/// How the page is asked at `at`, trusting the authority of `roots`.
fn at<'a>(roots: &'a Roots, at: &str) -> Asking<'a> {
    Asking {
        roots,
        deadline: Deadline::NONE,
        at: Some(time::parse(at).unwrap()),
    }
}

#[test]
fn the_pages_certificate_is_judged_at_the_time_it_is_asked_at() {
    // The certificate ends 2026-11-13 00:00 UTC, before this host's clock.
    // A minute before its end the page, Stalwart's own page and the two
    // files it loads are read, and the page is in order.
    let public = serve_until(in_order(), 2026, 11, 13);
    let own = serve(vec![html(STALWART)]);
    let roots = Arc::new(public.roots.clone());
    let page = format!("{}/login", public.url);
    let before = examine(
        &page,
        &format!("{}/login", own.url),
        "a=b",
        at(&roots, "2026-11-12T23:59:00Z"),
    );
    own.requests();
    assert_eq!(public.finish(), 3);
    assert_eq!(before.state, State::Ok, "{}", before.what);
    // A minute after its end the page cannot be read, and nothing more is
    // asked.
    let public = serve_until(in_order(), 2026, 11, 13);
    let roots = Arc::new(public.roots.clone());
    let page = format!("{}/login", public.url);
    let after = examine(
        &page,
        "http://127.0.0.1:9/login",
        "a=b",
        at(&roots, "2026-11-13T00:01:00Z"),
    );
    assert_eq!(public.finish(), 1);
    assert_eq!(after.state, State::Failed);
    assert!(after.what.contains("certificate"), "{}", after.what);
}

/// The check asks at its run's time: the tests' run is dated 2026-10-29,
/// before the certificate's end, while this host's clock is after it.
#[test]
fn the_check_judges_the_page_at_its_runs_time() {
    let public = serve_until(in_order(), 2026, 11, 13);
    let own = serve(vec![html(STALWART)]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.issuer.clone_from(&public.url);
    config.deployment.stalwart_url.clone_from(&own.url);
    let runner = Canned(String::new());
    let memory = Remembered::default();
    let context = Context {
        memory: &memory,
        ..crate::testing::context(&config, &runner)
    };
    let check = SignIn::new(&table("type = \"sign-in\""))
        .unwrap()
        .with_roots(Arc::new(public.roots.clone()));
    let observation = check.collect(&context).unwrap().observations.remove(0);
    own.requests();
    assert_eq!(public.finish(), 3);
    assert_eq!(observation.state, State::Ok, "{:?}", observation.findings);
}
