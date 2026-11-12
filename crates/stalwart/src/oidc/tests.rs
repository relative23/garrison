use serde_json::json;

use super::*;
use garrison_testing::http::{answer, json as respond, serve};

const TOKEN: &str = "token-0123456789abcdef";

fn provider(url: &str) -> Provider {
    Provider::new(url, "https://Mail.Example.test")
}

#[test]
fn userinfo_forwards_the_public_host_and_reads_the_subject() {
    let server = serve(vec![
        respond(&json!({"sub": "42", "email": "ann@example.test"})),
        respond(&json!({"sub": "43", "email": "", "preferred_username": "bob"})),
        respond(&json!({"sub": "44"})),
    ]);
    let oidc = provider(&server.url);
    let ann = oidc.userinfo(TOKEN, Some("192.0.2.7")).unwrap();
    assert_eq!(
        ann,
        Identity {
            subject: "42".into(),
            email: "ann@example.test".into()
        }
    );
    // An empty client address is not forwarded.
    assert_eq!(oidc.userinfo(TOKEN, Some("")).unwrap().email, "bob");
    assert_eq!(oidc.userinfo(TOKEN, None).unwrap().email, "44");
    let mut requests = server.requests();
    assert!(!requests[1].contains("x-forwarded-for"), "{}", requests[1]);
    let request = requests.remove(0);
    assert!(
        request.starts_with("GET /auth/userinfo HTTP/1.1\r\n"),
        "{request}"
    );
    for header in [
        "host: mail.example.test\r\n",
        "x-forwarded-proto: https\r\n",
        "x-forwarded-for: 192.0.2.7\r\n",
        "authorization: Bearer token-0123456789abcdef\r\n",
        "accept: application/json\r\n",
    ] {
        assert!(request.contains(header), "{header} missing in {request}");
    }
}

#[test]
fn bad_tokens_and_subjects_are_told_apart() {
    let long = "x".repeat(300);
    let server = serve(vec![
        answer(401, ""),
        respond(&json!({"sub": "has space"})),
        respond(&json!({"email": "a@b"})),
        respond(&json!({"sub": "45", "email": long})),
    ]);
    let oidc = provider(&server.url);
    assert_eq!(
        oidc.userinfo("short", None),
        Err(Error::InvalidToken("Malformed access token".into()))
    );
    assert_eq!(
        oidc.userinfo(&format!("{TOKEN} x"), None),
        Err(Error::InvalidToken("Malformed access token".into()))
    );
    assert_eq!(
        oidc.userinfo(TOKEN, None),
        Err(Error::InvalidToken(
            "The access token is no longer valid".into()
        ))
    );
    for _ in 0..2 {
        assert_eq!(
            oidc.userinfo(TOKEN, None),
            Err(Error::denied("The provider returned no stable subject"))
        );
    }
    assert_eq!(oidc.userinfo(TOKEN, None).unwrap().email.len(), 254);
    server.requests();
}

#[test]
fn code_exchange_accepts_only_bearer_tokens_with_a_lifetime() {
    let token = |kind: &str, expires: Value| {
        respond(&json!({"access_token": TOKEN, "token_type": kind, "expires_in": expires}))
    };
    let server = serve(vec![
        token("Bearer", json!(3600)),
        token("mac", json!(3600)),
        token("bearer", json!(0)),
        token("bearer", json!(1.5)),
        answer(400, r#"{"error": "invalid_grant"}"#),
    ]);
    let oidc = provider(&server.url);
    let exchange = CodeExchange {
        client_id: "garrison",
        redirect_uri: "https://admin.example.test/auth/callback",
        code: "code with+space",
        verifier: "verifier",
        client_ip: None,
    };
    let accepted = oidc.exchange_code(&exchange).unwrap();
    assert_eq!(
        (accepted.access_token.as_str(), accepted.expires_in),
        (TOKEN, 3600)
    );
    assert_eq!(format!("{accepted:?}"), "Token { expires_in: 3600, .. }");
    for _ in 0..3 {
        assert_eq!(
            oidc.exchange_code(&exchange),
            Err(Error::denied("The provider returned an unusable token"))
        );
    }
    assert_eq!(
        oidc.exchange_code(&exchange),
        Err(Error::denied("The authorization code was not accepted"))
    );
    let request = server.requests().remove(0);
    assert!(
        request.starts_with("POST /auth/token HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("content-type: application/x-www-form-urlencoded\r\n"));
    assert!(request.ends_with(
        "grant_type=authorization_code&code=code+with%2Bspace&client_id=garrison\
         &redirect_uri=https%3A%2F%2Fadmin.example.test%2Fauth%2Fcallback\
         &code_verifier=verifier"
    ));
}

#[test]
fn revocation_ignores_the_answer() {
    let server = serve(vec![answer(400, "")]);
    provider(&server.url).revoke("garrison", TOKEN).unwrap();
    let request = server.requests().remove(0);
    assert!(request.ends_with("token=token-0123456789abcdef&client_id=garrison"));
}

#[test]
fn subjects_and_tokens_have_fixed_shapes() {
    assert!(is_subject("42") && is_subject("user@example.test") && is_subject("a:b_c.d-e"));
    assert!(!is_subject("") && !is_subject("a b") && !is_subject(&"a".repeat(129)));
    assert!(is_token(&"!".repeat(16)) && is_token(&"~".repeat(4096)));
    assert!(
        !is_token(&"a".repeat(15))
            && !is_token(&"a".repeat(4097))
            && !is_token("é123456789abcdefg")
    );
}
