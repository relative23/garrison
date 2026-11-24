//! What the sign-in card says to do follows why the page could not be
//! read: the certificate of the issuer's host, the issuer's name, or the
//! proxy, for a status or a connection that did not reach Stalwart.

use std::sync::Arc;

use garrison_core::time;
use garrison_testing::http::{answer, serve};
use garrison_testing::tls::serve_until;

use super::tests::in_order;
use super::*;
use crate::context::Deadline;
use crate::fetch::roots;

const CERTIFICATE: &str = "The issuer's host must present a certificate for its name from an \
                           authority visitors trust; renew or replace it.";
const NAME: &str = "This host must resolve the issuer's name as visitors do; check its DNS \
                    records and this host's resolver.";
const PROXY: &str = "This address must reach Stalwart; check the proxy rules of the issuer's host.";

#[test]
fn the_advice_follows_why_the_page_could_not_be_read() {
    // A certificate that ran out on 2026-11-13, asked a minute after.
    let public = serve_until(in_order(), 2026, 11, 13);
    let trusted = Arc::new(public.roots.clone());
    let expired = examine(
        &format!("{}/login", public.url),
        "http://127.0.0.1:9/login",
        "a=b",
        Asking {
            roots: &trusted,
            deadline: Deadline::NONE,
            at: Some(time::parse("2026-11-13T00:01:00Z").unwrap()),
        },
    );
    public.finish();
    // A name that never exists (RFC 6761).
    let unnamed = examine(
        "https://garrison-test.invalid/login",
        "http://127.0.0.1:9/login",
        "a=b",
        Asking::by_hand(&roots()),
    );
    // A proxy that answers for Stalwart with an error.
    let server = serve(vec![answer(502, "bad gateway")]);
    let status = examine(
        &format!("{}/login", server.url),
        "http://127.0.0.1:9/login",
        "a=b",
        Asking::by_hand(&roots()),
    );
    server.requests();
    // Nothing listens where the page is.
    let closed = examine(
        "http://127.0.0.1:9/login",
        "http://127.0.0.1:9/login",
        "a=b",
        Asking::by_hand(&roots()),
    );
    let said: Vec<(State, Option<String>)> = [expired, unnamed, status, closed]
        .into_iter()
        .map(|examined| (examined.state, examined.fix))
        .collect();
    let failed = |fix: &str| (State::Failed, Some(fix.to_owned()));
    assert_eq!(
        said,
        [
            failed(CERTIFICATE),
            failed(NAME),
            failed(PROXY),
            failed(PROXY)
        ]
    );
}
