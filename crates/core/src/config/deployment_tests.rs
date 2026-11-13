//! The addresses of `[deployment]`: links, Stalwart's own listener and the
//! origins of Garrison and Stalwart.

use super::tests::{error, section, table};
use super::*;

#[test]
fn links_keep_their_order_and_must_be_https() {
    let config = parse(&table()).unwrap();
    let names: Vec<&str> = config
        .deployment
        .links
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(names, ["webmail", "status"]);
    let mut raw = table();
    section(&mut raw, "deployment")["links"]["webmail"] = "http://mail.example.test/".into();
    assert_eq!(
        error(&raw),
        "deployment.links.webmail must be an https:// URL"
    );
    let mut raw = table();
    let many: toml::Table = (0..17)
        .map(|index| (format!("link{index}"), "https://a.example.test/".into()))
        .collect();
    section(&mut raw, "deployment").insert("links".into(), many.into());
    assert_eq!(
        error(&raw),
        "[deployment] links must be a small table of names to URLs"
    );
}

#[test]
fn stalwart_url_must_be_a_loopback_ip_origin() {
    for url in [
        "http://10.0.0.1:8080",
        "http://localhost:8080",
        "https://127.0.0.1:8080",
        "http://127.0.0.1:8080/api",
        "http://user@127.0.0.1:8080",
        "http://127.0.0.1:8080/?a=b",
    ] {
        let mut raw = table();
        section(&mut raw, "deployment").insert("stalwart_url".into(), url.into());
        assert!(error(&raw).contains("loopback"), "{url}");
    }
    let mut raw = table();
    section(&mut raw, "deployment").insert("stalwart_url".into(), "http://[::1]:8080/".into());
    assert_eq!(
        parse(&raw).unwrap().deployment.stalwart_url,
        "http://[::1]:8080"
    );
}

#[test]
fn garrison_never_shares_an_origin_with_stalwart() {
    for (key, value) in [
        ("issuer", "https://admin.example.test"),
        ("admin_url", "https://ADMIN.example.test:443/admin/"),
    ] {
        let mut raw = table();
        section(&mut raw, "deployment").insert(key.into(), value.into());
        assert!(
            error(&raw).starts_with("deployment.public_origin must be a host name of its own"),
            "{key}: {}",
            error(&raw)
        );
    }
    // Another host of the same domain is another origin.
    let mut raw = table();
    section(&mut raw, "deployment").insert(
        "admin_url".into(),
        "https://stalwart.example.test/admin/".into(),
    );
    assert_eq!(
        parse(&raw).unwrap().deployment.admin_url,
        "https://stalwart.example.test/admin/"
    );
}

#[test]
fn origins_take_the_form_browsers_send() {
    let mut raw = table();
    section(&mut raw, "deployment").insert(
        "public_origin".into(),
        "https://Admin.Example.TEST:443/".into(),
    );
    let config = parse(&raw).unwrap();
    assert_eq!(
        config.deployment.public_origin,
        "https://admin.example.test"
    );
    for origin in [
        "http://admin.example.test",
        "https://admin.example.test/path",
        "https://a@b.test",
        "admin",
    ] {
        let mut raw = table();
        section(&mut raw, "deployment").insert("public_origin".into(), origin.into());
        assert_eq!(
            error(&raw),
            "deployment.public_origin must be an https:// origin without a path",
            "{origin}"
        );
    }
}
