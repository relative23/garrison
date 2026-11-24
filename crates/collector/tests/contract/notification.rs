//! Stalwart takes a notification that its own account submits, also one
//! whose account signs in with a password that has spaces in it.

use std::time::{Duration, Instant};

use garrison_core::time;
use garrison_testing::lab::{Lab, random_hex};

use super::{delivered, one_at_a_time};

/// A certificate check that accepts the lab's self-made certificate. The
/// product never does this: it checks the name against the system's
/// authorities.
#[derive(Debug)]
struct AnyCertificate(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, certificate, signature, algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, certificate, signature, algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_takes_a_notification_its_own_account_submits_past_the_spam_filter() {
    use garrison_collector::notify::Secret;
    use garrison_collector::notify::mail::{Mail, message, submit_over};

    let _guard = one_at_a_time();
    let lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let admin = std::env::var("GARRISON_LAB_ADMIN").expect("GARRISON_LAB_ADMIN");
    let (user, password) = admin.split_once(':').expect("user:password");
    let mail = Mail {
        host: smtp.clone(),
        port: 465,
        user: user.to_owned(),
        password: Secret::Text(password.to_owned()),
        from: user.to_owned(),
        to: user.to_owned(),
    };
    // A name of this run's own, to find the message by.
    let name = format!("garrison-{}.example.org", random_hex(4));
    let text = message(
        &mail,
        &name,
        &format!("Garrison on {name}: 1 failed"),
        "Failed: Local full backup: The last run failed.\n",
        time::now(),
    );
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), server).unwrap();
    let stream = std::net::TcpStream::connect((smtp.as_str(), 465)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    submit_over(
        rustls::StreamOwned::new(connection, stream),
        &mail,
        &name,
        &text,
    )
    .unwrap();

    // A wrong password is refused, and the refusal does not repeat it.
    let wrong = Mail {
        password: Secret::Text(format!("wrong-{}", random_hex(8))),
        ..mail.clone()
    };
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), server).unwrap();
    let stream = std::net::TcpStream::connect((smtp.as_str(), 465)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let refused = submit_over(
        rustls::StreamOwned::new(connection, stream),
        &wrong,
        &name,
        &text,
    );
    assert_eq!(
        refused,
        Err("the mail server did not sign in (535)".to_owned())
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let verdict = loop {
        let found = delivered(&lab)
            .into_iter()
            .find(|(id, _)| id.ends_with(&name));
        if let Some((_, verdict)) = found {
            break verdict;
        }
        assert!(
            Instant::now() < deadline,
            "the notification was not delivered"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    // A stranger's mail gets a verdict of the spam filter; the account's own does not.
    assert_eq!(verdict, "", "the spam filter judged the notification");
}

/// An account whose password has spaces in it signs in for a notification
/// with the password as the collector reads it from its credential file,
/// where a token's form would refuse it.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_password_with_spaces_read_from_its_file_signs_the_account_in() {
    use garrison_collector::notify::mail::{Mail, message, submit_over};
    use garrison_collector::notify::{Secret, Secrets};
    use garrison_core::credentials::Credentials;
    use serde_json::json;

    let _guard = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let admin = std::env::var("GARRISON_LAB_ADMIN").expect("GARRISON_LAB_ADMIN");
    let (admin_name, _) = admin.split_once(':').expect("user:password");
    let name = format!("notify-{}", random_hex(4));
    let password = format!("correct horse {} battery staple", random_hex(6));
    let domains = lab.call("x:Domain/get", &json!({"ids": null, "properties": ["id"]}));
    lab.create(
        "Account",
        &json!({
            "@type": "User",
            "name": name,
            "domainId": domains["list"][0]["id"],
            "credentials": {"0": {"@type": "Password", "secret": password}},
            "roles": {"@type": "User"},
            "permissions": {"@type": "Inherit"},
        }),
    );
    // As the operator writes it: one line, with its end of line.
    let directory = tempfile::tempdir().unwrap();
    garrison_testing::write_private(
        &directory.path().join("notify-mail-password"),
        format!("{password}\n").as_bytes(),
    );
    let read = Secrets::loaded(&Credentials::new(directory.path())).mail;
    assert!(read == Secret::Text(password.clone()), "{read:?}");
    let account = format!("{name}@example.test");
    let mail = Mail {
        host: smtp.clone(),
        port: 465,
        user: account.clone(),
        password: read,
        from: account,
        to: admin_name.to_owned(),
    };
    let host = format!("garrison-{}.example.org", random_hex(4));
    let text = message(
        &mail,
        &host,
        &format!("Garrison on {host}: 1 failed"),
        "Failed: Local full backup: The last run failed.\n",
        time::now(),
    );
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), server).unwrap();
    let stream = std::net::TcpStream::connect((smtp.as_str(), 465)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    submit_over(
        rustls::StreamOwned::new(connection, stream),
        &mail,
        &host,
        &text,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !delivered(&lab).iter().any(|(id, _)| id.ends_with(&host)) {
        assert!(
            Instant::now() < deadline,
            "the notification was not delivered"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// A TLS session with the lab's submission listener, whose certificate the
/// lab made itself.
fn session(smtp: &str) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), server).unwrap();
    let stream = std::net::TcpStream::connect((smtp, 465)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    rustls::StreamOwned::new(connection, stream)
}

/// An installation whose public origin names a port greets Stalwart with
/// its host alone and names its message by it, and Stalwart takes it.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_takes_a_notification_of_an_origin_with_a_port() {
    use garrison_collector::notify::Secret;
    use garrison_collector::notify::mail::{Mail, message, submit_over};

    let _guard = one_at_a_time();
    let lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let admin = std::env::var("GARRISON_LAB_ADMIN").expect("GARRISON_LAB_ADMIN");
    let (user, password) = admin.split_once(':').expect("user:password");
    let mail = Mail {
        host: smtp.clone(),
        port: 465,
        user: user.to_owned(),
        password: Secret::Text(password.to_owned()),
        from: user.to_owned(),
        to: user.to_owned(),
    };
    let host = format!("garrison-{}.example.org", random_hex(4));
    // As the channels name the host of `https://HOST:8443`.
    let name = format!("{host}:8443");
    let text = message(
        &mail,
        &name,
        &format!("Garrison on {name}: 1 failed"),
        "Failed: Local full backup: The last run failed.\n",
        time::now(),
    );
    submit_over(session(&smtp), &mail, &name, &text).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let ids: Vec<String> = delivered(&lab)
            .into_iter()
            .map(|(id, _)| id)
            .filter(|id| id.contains(&host))
            .collect();
        if ids.iter().any(|id| id.ends_with(&format!("@{host}"))) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no notification named by {host} alone was delivered: {ids:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Who sent the delivered message whose Message-ID is `id`, as Stalwart
/// read its From line: each mailbox's name and address.
fn sender(lab: &Lab, id: &str) -> Option<serde_json::Value> {
    let admin = std::env::var("GARRISON_LAB_ADMIN").expect("GARRISON_LAB_ADMIN");
    let session = lab.http("/jmap/session", &admin, None);
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        .as_str()
        .expect("the administrator has a mailbox")
        .to_owned();
    let answer = lab.http(
        "/jmap/",
        &admin,
        Some(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Email/query", {
                    "accountId": account,
                    "sort": [{"property": "receivedAt", "isAscending": false}],
                    "limit": 20,
                }, "0"],
                ["Email/get", {
                    "accountId": account,
                    "#ids": {"resultOf": "0", "name": "Email/query", "path": "/ids"},
                    "properties": ["messageId", "from"],
                }, "1"],
            ],
        })),
    );
    answer["methodResponses"][1][1]["list"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer}"))
        .iter()
        .find(|message| message["messageId"][0].as_str() == Some(id))
        .map(|message| message["from"].clone())
}

/// An installation whose public origin is an address greets Stalwart with
/// an address literal, `[192.0.2.1]` or `[IPv6:2001:db8::1]`, and its From
/// line, whose name holds the port or the IPv6 address, is one mailbox:
/// Stalwart takes the message and reads the name and the address.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_takes_a_notification_of_an_origin_that_is_an_address() {
    use garrison_collector::notify::Secret;
    use garrison_collector::notify::mail::{Mail, message, submit_over};

    let _guard = one_at_a_time();
    let lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let admin = std::env::var("GARRISON_LAB_ADMIN").expect("GARRISON_LAB_ADMIN");
    let (user, password) = admin.split_once(':').expect("user:password");
    let mail = Mail {
        host: smtp.clone(),
        port: 465,
        user: user.to_owned(),
        password: Secret::Text(password.to_owned()),
        from: user.to_owned(),
        to: user.to_owned(),
    };
    for name in ["192.0.2.1:8443", "[2001:db8::1]"] {
        // A text of this run's own, so that the Message-ID is too.
        let text = message(
            &mail,
            name,
            &format!("Garrison on {name}: test"),
            &format!("A test, {}.\n", random_hex(8)),
            time::now(),
        );
        let id = text
            .lines()
            .find_map(|line| line.strip_prefix("Message-ID: <")?.strip_suffix('>'))
            .expect("the message has an ID")
            .to_owned();
        submit_over(session(&smtp), &mail, name, &text).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let from = loop {
            if let Some(from) = sender(&lab, &id) {
                break from;
            }
            assert!(
                Instant::now() < deadline,
                "the notification of {name} was not delivered"
            );
            std::thread::sleep(Duration::from_secs(1));
        };
        assert_eq!(
            from,
            serde_json::json!([{"name": format!("Garrison on {name}"), "email": user}]),
            "{name}"
        );
    }
}
