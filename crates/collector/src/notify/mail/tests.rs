use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};

use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use super::*;
use crate::testing::{Certificates, certificates, now};

/// A mail server for `localhost` with TLS from the first byte that serves
/// one session. It answers `AUTH` and `RCPT` as told and every other command
/// as a server that takes the message; what it was sent comes back.
pub(crate) fn server(
    certificates: &Certificates,
    auth: &'static str,
    rcpt: &'static str,
) -> (u16, Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (server, key) = (certificates.server.clone(), certificates.key.clone_key());
    let (sender, received) = channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![server], key)
            .unwrap();
        let connection = ServerConnection::new(Arc::new(config)).unwrap();
        let mut session = BufReader::new(StreamOwned::new(connection, stream));
        let mut lines = Vec::new();
        let say = |session: &mut BufReader<StreamOwned<ServerConnection, std::net::TcpStream>>,
                   text: &str| {
            let _ = session.get_mut().write_all(text.as_bytes());
            let _ = session.get_mut().flush();
        };
        say(&mut session, "220 mail.example.test ESMTP\r\n");
        let mut data = false;
        loop {
            let mut line = String::new();
            if session.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let line = line.trim_end().to_owned();
            lines.push(line.clone());
            if data {
                if line == "." {
                    data = false;
                    say(
                        &mut session,
                        "250 2.0.0 Message queued with id 4b786a616e00000.\r\n",
                    );
                }
                continue;
            }
            let answer = match line.split_whitespace().next().unwrap_or_default() {
                "EHLO" => "250-mail.example.test\r\n250 AUTH PLAIN LOGIN\r\n",
                "AUTH" => auth,
                "RCPT" => rcpt,
                "DATA" => {
                    data = true;
                    "354 Start mail input\r\n"
                }
                "QUIT" => {
                    say(&mut session, "221 Bye\r\n");
                    break;
                }
                _ => "250 OK\r\n",
            };
            say(&mut session, answer);
        }
        let _ = sender.send(lines);
    });
    (port, received)
}

pub(crate) fn trusted(certificates: &Certificates) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(certificates.ca.clone()).unwrap();
    Arc::new(roots)
}

pub(crate) fn mail(port: u16) -> Mail {
    Mail {
        host: "localhost".to_owned(),
        port,
        user: "garrison@example.test".to_owned(),
        password: Secret::Text("app-password-of-sixteen".to_owned()),
        from: "garrison@example.test".to_owned(),
        to: "anna@example.test".to_owned(),
    }
}

#[test]
fn a_message_is_submitted_signed_in_and_its_text_arrives_as_written() {
    let certificates = certificates();
    let (port, received) = server(
        &certificates,
        "235 2.7.0 Authentication succeeded\r\n",
        "250 OK\r\n",
    );
    let text = "Failed: Backup: Der letzte Lauf schlug fehl – Platte voll.\n.\nIn order again: DNS";
    submit(
        &mail(port),
        "garrison.example.org",
        "Garrison on garrison.example.org: 1 failed",
        text,
        now(),
        &trusted(&certificates),
    )
    .unwrap();
    let lines = received.recv().unwrap();
    assert_eq!(lines[0], "EHLO garrison.example.org");
    let login = STANDARD
        .decode(lines[1].strip_prefix("AUTH PLAIN ").unwrap())
        .unwrap();
    assert_eq!(login, b"\0garrison@example.test\0app-password-of-sixteen");
    assert_eq!(
        &lines[2..5],
        [
            "MAIL FROM:<garrison@example.test>",
            "RCPT TO:<anna@example.test>",
            "DATA"
        ]
    );
    let end = lines.iter().position(|line| line == ".").unwrap();
    let (headers, body) =
        lines[5..end].split_at(lines[5..end].iter().position(String::is_empty).unwrap());
    assert!(headers.contains(
        &"From: \"Garrison on garrison.example.org\" <garrison@example.test>".to_owned()
    ));
    assert!(headers.contains(&"Subject: Garrison on garrison.example.org: 1 failed".to_owned()));
    assert!(headers.contains(&"Auto-Submitted: auto-generated".to_owned()));
    assert!(headers.contains(&"Date: Thu, 29 Oct 2026 12:00:00 +0000".to_owned()));
    // No line of the body can end the message early or pass the length a server takes.
    assert!(
        body.iter()
            .all(|line| line.len() <= 76 && !line.starts_with('.'))
    );
    assert_eq!(
        String::from_utf8(STANDARD.decode(body.concat()).unwrap()).unwrap(),
        text
    );
    assert_eq!(lines.last().unwrap(), "QUIT");
}

#[test]
fn a_refusal_is_said_without_what_was_sent_to_sign_in() {
    let certificates = certificates();
    let (port, _) = server(
        &certificates,
        "535 5.7.8 Authentication credentials invalid: app-password-of-sixteen\r\n",
        "250 OK\r\n",
    );
    let refused = submit(
        &mail(port),
        "garrison.example.org",
        "x",
        "y",
        now(),
        &trusted(&certificates),
    )
    .unwrap_err();
    assert_eq!(refused, "the mail server did not sign in (535)");
    let (port, _) = server(&certificates, "235 OK\r\n", "550 5.1.1 No such mailbox\r\n");
    let refused = submit(
        &mail(port),
        "garrison.example.org",
        "x",
        "y",
        now(),
        &trusted(&certificates),
    )
    .unwrap_err();
    assert_eq!(
        refused,
        "the mail server did not take the recipient: 550 5.1.1 No such mailbox"
    );
}

#[test]
fn a_certificate_that_is_not_trusted_ends_the_session_before_the_password() {
    let certificates = certificates();
    let (port, received) = server(&certificates, "235 OK\r\n", "250 OK\r\n");
    // The system's own authorities do not know the test's.
    let refused = submit(
        &mail(port),
        "garrison.example.org",
        "x",
        "y",
        now(),
        &Arc::new(RootCertStore::empty()),
    )
    .unwrap_err();
    assert!(refused.contains("certificate"), "{refused}");
    assert_eq!(received.recv().unwrap_or_default(), Vec::<String>::new());
    // Nothing listens there.
    let unreachable = submit(
        &mail(9),
        "garrison.example.org",
        "x",
        "y",
        now(),
        &trusted(&certificates),
    );
    assert!(unreachable.is_err());
}

/// A reply ends with its line: a server that ends TLS without its closing
/// notice right after it took the message, before QUIT, has taken it. Only
/// a reply cut within its line is no reply.
#[test]
fn a_reply_line_counts_however_the_session_then_ends() {
    let certificates = certificates();
    for (last, taken) in [("250 2.0.0 Message queued\r\n", true), ("250 2.0", false)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (server, key) = (certificates.server.clone(), certificates.key.clone_key());
        let ended = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![server], key)
            .unwrap();
            let connection = ServerConnection::new(Arc::new(config)).unwrap();
            let mut session = BufReader::new(StreamOwned::new(connection, stream));
            for answer in [
                "220 mail.example.test ESMTP\r\n",
                "250 AUTH PLAIN\r\n",
                "235 OK\r\n",
                "250 OK\r\n",
                "250 OK\r\n",
                "354 Go on\r\n",
            ] {
                session.get_mut().write_all(answer.as_bytes()).unwrap();
                session.get_mut().flush().unwrap();
                let mut line = String::new();
                session.read_line(&mut line).unwrap();
            }
            let mut line = String::new();
            while line.trim_end() != "." {
                line.clear();
                session.read_line(&mut line).unwrap();
            }
            session.get_mut().write_all(last.as_bytes()).unwrap();
            session.get_mut().flush().unwrap();
            // Dropped as it is: the socket closes, and TLS was never ended.
        });
        let sent = submit(
            &mail(port),
            "garrison.example.org",
            "x",
            "y",
            now(),
            &trusted(&certificates),
        );
        ended.join().unwrap();
        assert_eq!(sent.is_ok(), taken, "{last:?}: {sent:?}");
    }
}

#[test]
fn headers_stay_one_line_and_other_scripts_are_encoded() {
    assert_eq!(
        header("Garrison on host: 1 failed"),
        "Garrison on host: 1 failed"
    );
    assert_eq!(header("a\r\nBcc: x@example.org"), "aBcc: x@example.org");
    assert_eq!(header("Prüfung"), "=?utf-8?B?UHLDvGZ1bmc=?=");
    assert!(!format!("{:?}", mail(465)).contains("app-password"));
}

#[test]
fn a_reply_line_without_an_end_is_read_only_so_far() {
    use std::io::Read as _;
    // A greeting of 64 MiB without an end of line: the session gives up
    // after the longest line a reply may have, and reads no further.
    let mut source = BufReader::new(std::io::repeat(b'2').take(64 << 20));
    assert_eq!(
        reply(&mut source),
        Err("the server's reply is too long".to_owned())
    );
    let read = (64 << 20) - source.get_ref().limit();
    assert!(read < 64 << 10, "{read} bytes read");
}

/// The greeting and the Message-ID name this installation's host without
/// the port `public_origin` may name; the greeting names an address as an
/// address literal (RFC 5321, 4.1.3).
#[test]
fn the_greeting_and_the_message_id_name_the_host_alone() {
    let certificates = certificates();
    for (name, greeting, domain) in [
        (
            "garrison.example.org",
            "garrison.example.org",
            "garrison.example.org",
        ),
        (
            "garrison.example.org:8443",
            "garrison.example.org",
            "garrison.example.org",
        ),
        ("192.0.2.1", "[192.0.2.1]", "192.0.2.1"),
        ("192.0.2.1:8443", "[192.0.2.1]", "192.0.2.1"),
        ("[2001:db8::1]", "[IPv6:2001:db8::1]", "[2001:db8::1]"),
        ("[2001:db8::1]:8443", "[IPv6:2001:db8::1]", "[2001:db8::1]"),
    ] {
        let (port, received) = server(&certificates, "235 OK\r\n", "250 OK\r\n");
        submit(
            &mail(port),
            name,
            "Garrison: test",
            "A test.",
            now(),
            &trusted(&certificates),
        )
        .unwrap();
        let lines = received.recv().unwrap();
        assert_eq!(lines[0], format!("EHLO {greeting}"), "{name}");
        let id = lines
            .iter()
            .find(|line| line.starts_with("Message-ID: "))
            .unwrap();
        assert!(id.ends_with(&format!("@{domain}>")), "{name}: {id}");
    }
}

/// The channels of an installation whose `public_origin` names a port greet
/// with its host alone; the messages still name it with its port.
#[test]
fn an_origin_with_a_port_greets_with_its_host_alone() {
    use garrison_core::config::MailSettings;

    let certificates = certificates();
    let (port, received) = server(&certificates, "235 OK\r\n", "250 OK\r\n");
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::testing::config(directory.path());
    config.deployment.public_origin = "https://garrison.example.org:8443".to_owned();
    config.notifications.mail = Some(MailSettings {
        host: "localhost".to_owned(),
        port,
        user: "garrison@example.test".to_owned(),
        from: "garrison@example.test".to_owned(),
        to: "anna@example.test".to_owned(),
    });
    let secrets = crate::notify::Secrets {
        mail: Secret::Text("app-password-of-sixteen".to_owned()),
        ..crate::notify::Secrets::default()
    };
    let channels = crate::notify::Channels::of(&config, secrets);
    assert_eq!(channels.host, "garrison.example.org:8443");
    let note = crate::notify::Note::plain(
        format!("Garrison on {}: test", channels.host),
        "A test.".to_owned(),
        crate::notify::Level::Good,
    );
    let roots = trusted(&certificates);
    let sent = channels.send_with(&note, now(), &roots, crate::context::Deadline::NONE);
    assert_eq!(sent, [("mail", Ok(()))]);
    let lines = received.recv().unwrap();
    assert_eq!(lines[0], "EHLO garrison.example.org");
    assert!(
        lines.contains(&"Subject: Garrison on garrison.example.org:8443: test".to_owned()),
        "{lines:?}"
    );
}

/// The sender's name is one quoted word, so that the From line names one
/// mailbox whatever `public_origin` names: a port or an IPv6 address, whose
/// colons and brackets would make a group of it or no address at all (RFC
/// 5322, 3.2.3 and 3.4). A name beyond ASCII is an encoded word.
#[test]
fn the_from_line_names_one_mailbox_for_every_origin() {
    let from = |name: &str| {
        message(&mail(465), name, "x", "y", now())
            .lines()
            .find(|line| line.starts_with("From: "))
            .unwrap()
            .to_owned()
    };
    for (name, line) in [
        (
            "garrison.example.org",
            r#"From: "Garrison on garrison.example.org" <garrison@example.test>"#,
        ),
        (
            "garrison.example.org:8443",
            r#"From: "Garrison on garrison.example.org:8443" <garrison@example.test>"#,
        ),
        (
            "192.0.2.1:8443",
            r#"From: "Garrison on 192.0.2.1:8443" <garrison@example.test>"#,
        ),
        (
            "[2001:db8::1]",
            r#"From: "Garrison on [2001:db8::1]" <garrison@example.test>"#,
        ),
        (
            "[2001:db8::1]:8443",
            r#"From: "Garrison on [2001:db8::1]:8443" <garrison@example.test>"#,
        ),
        (
            r#"a"b\c"#,
            r#"From: "Garrison on a\"b\\c" <garrison@example.test>"#,
        ),
        (
            "bücher.example",
            "From: =?utf-8?B?R2Fycmlzb24gb24gYsO8Y2hlci5leGFtcGxl?= <garrison@example.test>",
        ),
    ] {
        assert_eq!(from(name).trim_end(), line, "{name}");
    }
}
