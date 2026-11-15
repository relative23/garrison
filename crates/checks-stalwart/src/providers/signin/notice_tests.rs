//! A server that ends TLS without its closing notice may have had its
//! answer cut anywhere by whoever can end the connection. The sign-in check
//! reads the page's body, so it takes only an answer that its own length
//! calls whole, whatever a notification takes.

use std::sync::Arc;

use garrison_testing::tls::serve_without_notice;

use super::tests::STALWART;
use super::*;

#[test]
fn a_page_without_a_length_from_a_server_that_ends_without_notice_is_no_answer() {
    // As Python's `http.server` behind `ssl` answers: no length, and the
    // connection ends with the body, without TLS's closing notice.
    let answer =
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{STALWART}");
    let public = serve_without_notice(vec![answer]);
    let roots = Arc::new(public.roots.clone());
    let page = format!("{}/login", public.url);
    let examined = examine(
        &page,
        "http://127.0.0.1:9/login",
        "client_id=x",
        Asking::by_hand(&roots),
    );
    assert_eq!(public.finish(), 1);
    assert_eq!(examined.state, State::Failed, "{}", examined.what);
    assert_eq!(
        examined.what,
        format!("Stalwart's sign-in page {page}: the connection ended before its answer was whole")
    );
}
