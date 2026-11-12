use serde_json::json;

use super::*;
use garrison_testing::http::{answer, json as respond, serve};

fn client(url: &str) -> JmapClient {
    JmapClient::new(url, "native-key-0123456789")
}

#[test]
fn calls_carry_the_key_and_answers_are_matched_by_tag() {
    let server = serve(vec![respond(&json!({"methodResponses": [
        ["x:B/get", {"list": []}, "1"],
        ["error", {"type": "forbidden"}, "2"],
        ["x:A/get", {"list": [1]}, "0"],
    ]}))]);
    let results = client(&server.url)
        .call_many(
            &[
                ("x:A/get", json!({})),
                ("x:B/get", json!({})),
                ("x:C/get", json!({})),
            ],
            MAX_RESPONSE,
        )
        .unwrap();
    assert_eq!(results[0].as_ref().unwrap()["list"], json!([1]));
    assert_eq!(results[1].as_ref().unwrap()["list"], json!([]));
    assert_eq!(results[2], None);
    let request = server.requests().remove(0);
    assert!(request.starts_with("POST /jmap/ HTTP/1.1"), "{request}");
    assert!(
        request.contains("authorization: Bearer native-key-0123456789\r\n"),
        "{request}"
    );
    assert!(
        request.contains(
            r#""methodCalls":[["x:A/get",{},"0"],["x:B/get",{},"1"],["x:C/get",{},"2"]]"#
        ),
        "{request}"
    );
    assert!(request.contains(r#""using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]"#));
}

#[test]
fn server_failures_are_unavailable_and_refusals_denied() {
    let server = serve(vec![
        respond(&json!({"methodResponses": [["error", {"type": "serverFail"}, "0"]]})),
        answer(401, ""),
        answer(404, ""),
        respond(&json!({"methodResponses": [["x:Other/get", {}, "0"]]})),
        respond(&json!({"methodResponses": [["x:A/get", {}, "00"]]})),
        respond(&json!({"methodResponses": [["x:A/get", {}, "1"]]})),
        respond(&json!({"methodResponses": [["x:A/get", {}]]})),
        respond(&json!({"methods": []})),
        answer(200, r#"{"methodResponses": [], "methodResponses": []}"#),
        respond(&json!({"methodResponses": [["error", {"type": "forbidden"}, "0"]]})),
    ]);
    let jmap = client(&server.url);
    let call = || jmap.call("x:A/get", json!({}));
    assert_eq!(
        call(),
        Err(Error::Unavailable(
            "Stalwart could not complete the request".into()
        ))
    );
    assert_eq!(
        call(),
        Err(Error::denied("The native API key was rejected"))
    );
    assert_eq!(
        call(),
        Err(Error::denied("Unexpected native API status 404"))
    );
    for _ in 0..3 {
        assert_eq!(
            call(),
            Err(Error::denied(
                "Native API answered with an unexpected method"
            ))
        );
    }
    for _ in 0..3 {
        assert_eq!(call(), Err(Error::denied("Malformed native API response")));
    }
    assert_eq!(call(), Err(Error::denied("x:A/get was refused")));
    server.requests();
}

#[test]
fn get_requires_every_requested_object() {
    let list = |ids: Value, not_found: Value| {
        respond(&json!({"methodResponses": [
            ["x:Role/get", {"list": ids, "notFound": not_found}, "0"]
        ]}))
    };
    let server = serve(vec![
        list(json!([{"id": "a"}, {"id": "b"}]), json!([])),
        list(json!([{"id": "a"}]), json!([])),
        list(json!([{"id": "a"}, {"id": "b"}]), json!(["c"])),
        list(json!([{"id": "a"}, {"id": 2}]), json!(null)),
        list(json!([{"id": "z"}]), json!(null)),
    ]);
    let jmap = client(&server.url);
    let get = || jmap.get::<Object>("Role", Some(&["a", "b"]), &["id"]);
    assert_eq!(get().unwrap().len(), 2);
    let incomplete = Err(Error::denied("x:Role/get returned incomplete data"));
    for _ in 0..3 {
        assert_eq!(get(), incomplete);
    }
    assert_eq!(jmap.get::<Object>("Role", None, &["id"]).unwrap().len(), 1);
    let request = server.requests().pop().unwrap();
    assert!(request.contains(r#"[["x:Role/get",{"ids":null,"properties":["id"]},"0"]]"#));
}

#[test]
fn get_reads_objects_as_the_callers_type_or_not_at_all() {
    #[derive(Debug, PartialEq, serde::Deserialize)]
    struct Named {
        id: String,
        name: String,
    }
    let list = |objects: Value| {
        respond(&json!({"methodResponses": [
            ["x:Thing/get", {"list": objects, "notFound": []}, "0"]
        ]}))
    };
    let server = serve(vec![
        list(json!([{"id": "a", "name": "first", "more": 1}, {"id": "b", "name": "second"}])),
        // One object of another shape spoils the answer; nothing is left out.
        list(json!([{"id": "a", "name": "first"}, {"id": "b", "name": 2}])),
        list(json!([{"id": "a"}])),
    ]);
    let jmap = client(&server.url);
    let get = || jmap.get::<Named>("Thing", None, &["id", "name"]);
    let named = |id: &str, name: &str| Named {
        id: id.to_owned(),
        name: name.to_owned(),
    };
    assert_eq!(get(), Ok(vec![named("a", "first"), named("b", "second")]));
    let unsupported = Err(Error::denied("x:Thing/get returned an unsupported object"));
    assert_eq!(get(), unsupported);
    assert_eq!(get(), unsupported);
    server.requests();
}

#[test]
fn debug_output_omits_the_key() {
    let text = format!("{:?}", client("http://127.0.0.1:1"));
    assert_eq!(
        text,
        r#"JmapClient { url: "http://127.0.0.1:1/jmap/", timeout: 5s, .. }"#
    );
}
