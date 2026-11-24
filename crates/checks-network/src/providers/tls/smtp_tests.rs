//! A listener that speaks SMTP is asked for STARTTLS after its greeting and
//! EHLO: where it stops before, the card says where, not that STARTTLS was
//! refused.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::thread;

use super::tests::roots;
use super::*;
use crate::testing::{certificates, now};

/// A listener that greets with `greeting`, answers EHLO with `ehlo` and
/// STARTTLS with `starttls`, as far as each is given, and then closes.
fn speaking(
    greeting: Option<&'static str>,
    ehlo: Option<&'static str>,
    starttls: Option<&'static str>,
) -> u16 {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        for reply in [greeting, ehlo, starttls] {
            let Some(reply) = reply else {
                return;
            };
            if !reply.is_empty() {
                stream.write_all(reply.as_bytes()).unwrap();
            }
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
        }
    });
    port
}

#[test]
fn the_card_says_where_a_listener_stopped_before_tls() {
    let refused_at = |port: u16| {
        probe(
            "localhost",
            port,
            "127.0.0.1",
            true,
            &Arc::new(roots(&certificates())),
            now(),
        )
    };
    let greeting = "220 mail.example.test ESMTP\r\n";
    let ehlo = "250-mail.example.test\r\n250 STARTTLS\r\n";
    let said = [
        (speaking(None, None, None), "SMTP connection closed"),
        (
            speaking(Some("554 5.3.2 No service here\r\n"), None, None),
            "refused at the SMTP greeting",
        ),
        (
            speaking(Some(greeting), Some("500 5.5.1 Unknown command\r\n"), None),
            "EHLO refused",
        ),
        (
            speaking(Some(greeting), Some(ehlo), Some("454 4.7.0 Not now\r\n")),
            "STARTTLS refused",
        ),
    ]
    .into_iter()
    .map(|(port, words)| (words, refused_at(port)))
    .filter(|(words, said)| *said != Err(Failure(words)))
    .collect::<Vec<_>>();
    assert_eq!(said, Vec::new());
}
