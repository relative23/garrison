use garrison_testing::http::{Server, json as respond, serve, serve_each};
use serde_json::{Value, json};

use super::*;

/// What Stalwart answers a page: the query's IDs of `numbers` with the
/// `total`, and the get's objects of `objects` (by default the same).
fn page(numbers: std::ops::Range<usize>, total: usize, objects: Option<Vec<usize>>) -> String {
    let ids: Vec<String> = numbers.clone().map(|number| format!("a{number}")).collect();
    let list: Vec<Value> = objects
        .unwrap_or_else(|| numbers.collect())
        .into_iter()
        .map(|number| json!({"id": format!("a{number}"), "name": format!("n{number}")}))
        .collect();
    respond(&json!({"methodResponses": [
        ["x:Account/query", {"ids": ids, "position": 0, "total": total}, "0"],
        ["x:Account/get", {"list": list, "notFound": []}, "1"],
    ]}))
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Named {
    name: String,
}

fn client(url: &str) -> JmapClient {
    JmapClient::new(url, "native-key-0123456789")
}

fn names(listed: &Listed<Named>) -> Vec<String> {
    listed
        .objects
        .iter()
        .map(|named| named.name.clone())
        .collect()
}

/// A page is a query and a get of its IDs in one request, from the last
/// object the pages before read, up to `most`, the oldest first.
#[test]
fn objects_come_in_pages_of_a_query_and_a_get_of_its_ids() {
    let server = serve(vec![page(0..500, 700, None), page(499..600, 700, None)]);
    let listed: Listed<Named> = client(&server.url)
        .listed("Account", &["name"], 600, || true)
        .unwrap();
    assert_eq!(listed.total, 700);
    let expected: Vec<String> = (0..600).map(|number| format!("n{number}")).collect();
    assert_eq!(names(&listed), expected);
    let requests = server.requests();
    for (request, position, limit) in [(&requests[0], 0, 500), (&requests[1], 499, 101)] {
        let body: Value = serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(
            body["methodCalls"],
            json!([
                ["x:Account/query", {"sort": [{"property": "id", "isAscending": true}],
                    "position": position, "limit": limit, "calculateTotal": true}, "0"],
                ["x:Account/get", {"#ids": {"resultOf": "0", "name": "x:Account/query", "path": "/ids"},
                    "properties": ["name"]}, "1"],
            ])
        );
    }
}

/// Where Stalwart has fewer than `most`, the pages end with its last
/// object, and where there is no time for the next page, with the pages
/// before it.
#[test]
fn the_pages_end_with_the_last_object_or_the_time() {
    let server = serve(vec![page(0..3, 3, None)]);
    let listed: Listed<Named> = client(&server.url)
        .listed("Account", &["name"], 1000, || true)
        .unwrap();
    server.requests();
    assert_eq!((listed.objects.len(), listed.total), (3, 3));
    let server = serve(vec![page(0..500, 900, None)]);
    let listed: Listed<Named> = client(&server.url)
        .listed("Account", &["name"], 1000, || false)
        .unwrap();
    server.requests();
    assert_eq!((listed.objects.len(), listed.total), (500, 900));
}

/// An object that comes again in a later page is listed once, and a page
/// that brings nothing new ends the pages.
#[test]
fn an_object_that_comes_again_is_listed_once() {
    let server = serve(vec![
        page(0..500, 1000, None),
        page(400..900, 1000, None),
        page(899..1000, 1000, None),
    ]);
    let listed: Listed<Named> = client(&server.url)
        .listed("Account", &["name"], 1000, || true)
        .unwrap();
    server.requests();
    let expected: Vec<String> = (0..1000).map(|number| format!("n{number}")).collect();
    assert_eq!(names(&listed), expected);
    let server = serve(vec![page(0..500, 1000, None), page(0..500, 1000, None)]);
    let listed: Listed<Named> = client(&server.url)
        .listed("Account", &["name"], 1000, || true)
        .unwrap();
    server.requests();
    assert_eq!(listed.objects.len(), 500);
}

/// A query Stalwart refused the key is a refusal; a get that does not give
/// the IDs the query gave, or a query without its total, is an answer this
/// release does not read.
#[test]
fn a_refused_or_unread_page_says_why() {
    let refused = respond(&json!({"methodResponses": [
        ["error", {"type": "forbidden"}, "0"],
        ["error", {"type": "invalidResultReference"}, "1"],
    ]}));
    let without_total = respond(&json!({"methodResponses": [
        ["x:Account/query", {"ids": ["a0"], "position": 0}, "0"],
        ["x:Account/get", {"list": [{"id": "a0", "name": "n0"}], "notFound": []}, "1"],
    ]}));
    for (answer, error) in [
        (
            refused,
            Error::Denied("x:Account/query was refused".to_owned()),
        ),
        (
            page(0..3, 3, Some(vec![0, 1])),
            Error::Unreadable("x:Account/get did not return the objects asked for".to_owned()),
        ),
        (
            without_total,
            Error::Unreadable("x:Account/query returned no IDs and no total".to_owned()),
        ),
    ] {
        let server = serve(vec![answer]);
        let listed = client(&server.url).listed::<Named>("Account", &["name"], 10, || true);
        server.requests();
        assert_eq!(listed, Err(error));
    }
}

/// A stand-in that answers `count` pages as Stalwart does, from the list
/// of the accounts `a0` to `a{accounts - 1}` in that order, at the position
/// and with the limit each page asks; after its first answer it changes the
/// list as `change` says.
fn changing(accounts: usize, count: usize, change: fn(&mut Vec<usize>)) -> Server {
    let mut list: Vec<usize> = (0..accounts).collect();
    let mut answered = 0;
    serve_each(count, move |body| {
        let asked: Value = serde_json::from_str(body).unwrap();
        let query = &asked["methodCalls"][0][1];
        let position = usize::try_from(query["position"].as_u64().unwrap()).unwrap();
        let limit = usize::try_from(query["limit"].as_u64().unwrap()).unwrap();
        let numbers: Vec<usize> = list.iter().skip(position).take(limit).copied().collect();
        let ids: Vec<String> = numbers.iter().map(|number| format!("a{number}")).collect();
        let objects: Vec<Value> = numbers
            .iter()
            .map(|number| json!({"id": format!("a{number}"), "name": format!("n{number}")}))
            .collect();
        let answer = respond(&json!({"methodResponses": [
            ["x:Account/query", {"ids": ids, "position": position, "total": list.len()}, "0"],
            ["x:Account/get", {"list": objects, "notFound": []}, "1"],
        ]}));
        answered += 1;
        if answered == 1 {
            change(&mut list);
        }
        answer
    })
}

/// An object removed after a page held it moves the ones after it up a
/// place: the page that follows still brings every object the list holds,
/// where it began one too far and left one out without a word.
#[test]
fn an_object_removed_between_two_pages_costs_no_other_object() {
    // One of the first page's is removed before the second is asked.
    let server = changing(603, 4, |list| {
        list.retain(|number| *number != 3);
    });
    let listed: Listed<Named> = client(&server.url)
        .listed("Account", &["name"], 100_000, || true)
        .unwrap();
    server.requests();
    let expected: Vec<String> = (0..603).map(|number| format!("n{number}")).collect();
    assert_eq!(names(&listed), expected);
    // Three of the first page's are removed and two are made, which come
    // last: the ones removed stay as they were read, every other is there.
    let server = changing(603, 4, |list| {
        list.retain(|number| ![3, 250, 499].contains(number));
        list.extend([603, 604]);
    });
    let listed: Listed<Named> = client(&server.url)
        .listed("Account", &["name"], 100_000, || true)
        .unwrap();
    server.requests();
    let expected: Vec<String> = (0..605).map(|number| format!("n{number}")).collect();
    assert_eq!(names(&listed), expected);
}
