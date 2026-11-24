//! A stand-in for Stalwart's management API that holds objects of one kind
//! and answers `/query` and `/get` of them as Stalwart 1.2.0 does (measured
//! in the lab, the 5000 on 1.1.0 only): a `/get` of all objects (`ids: null`)
//! gives the first 500 of them, the oldest first, and says nothing of the
//! rest; a `/query` gives the IDs from `position` on, `limit` of them and
//! 5000 at the most, the newest first, or the oldest first where it sorts
//! by ID, with the total where it is asked to count; a `/get` may take the
//! IDs a query before it in the same request gave (`#ids`). A sort Garrison
//! does not ask for, and every other method, it does not know.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Map, Value, json};

/// The most objects Stalwart gives a `/get` of all of them.
const MOST_IN_GET: usize = 500;
/// The most IDs Stalwart gives a `/query`.
const MOST_IN_QUERY: usize = 5000;

/// A stand-in at work.
#[derive(Debug)]
pub struct Objects {
    /// `http://` and its address, as `stalwart_url` names it.
    pub url: String,
    done: Arc<AtomicBool>,
    handle: JoinHandle<Vec<Vec<Value>>>,
}

impl Objects {
    /// Stops the stand-in: the method calls of each request it was asked.
    pub fn requests(self) -> Vec<Vec<Value>> {
        self.done.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}

/// A stand-in that holds `objects` of `kind`, such as `Domain`, in the
/// order they were made, the oldest first; each has an `id`.
pub fn objects(kind: &str, objects: Vec<Value>) -> Objects {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let done = Arc::new(AtomicBool::new(false));
    let kind = kind.to_owned();
    let handle = thread::spawn({
        let done = Arc::clone(&done);
        move || {
            let mut requests = Vec::new();
            while !done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => requests.push(answer(stream, &kind, &objects)),
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            requests
        }
    });
    Objects { url, done, handle }
}

/// Reads one request and answers each of its method calls; its calls.
fn answer(stream: TcpStream, kind: &str, objects: &[Value]) -> Vec<Value> {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap();
        }
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let request: Value = serde_json::from_slice(&body).unwrap();
    let calls = request["methodCalls"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut answered: Vec<Value> = Vec::new();
    for call in &calls {
        answered.push(answered_call(call, kind, objects, &answered));
    }
    let body = json!({"methodResponses": answered}).to_string();
    let mut stream = reader.into_inner();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    calls
}

/// The answer to one `call`, after the answers `before` it in its request.
fn answered_call(call: &Value, kind: &str, objects: &[Value], before: &[Value]) -> Value {
    let (method, arguments, tag) = (&call[0], &call[1], &call[2]);
    let id = |object: &Value| object["id"].clone();
    if *method == format!("x:{kind}/query") {
        let ordered: Vec<&Value> = match &arguments["sort"] {
            Value::Null => objects.iter().rev().collect(),
            sort if *sort == json!([{"property": "id", "isAscending": true}]) => {
                objects.iter().collect()
            }
            _ => return json!(["error", {"type": "unsupportedSort"}, tag]),
        };
        let position = arguments["position"].as_u64().unwrap_or(0);
        let position = usize::try_from(position).unwrap().min(objects.len());
        let limit = arguments["limit"].as_u64().map_or(MOST_IN_QUERY, |limit| {
            usize::try_from(limit).unwrap().min(MOST_IN_QUERY)
        });
        let ids: Vec<Value> = ordered[position..]
            .iter()
            .take(limit)
            .map(|object| id(object))
            .collect();
        let mut answer = json!({"ids": ids, "position": position});
        if arguments["calculateTotal"] == json!(true) {
            answer["total"] = json!(objects.len());
        }
        return json!([method, answer, tag]);
    }
    if *method != format!("x:{kind}/get") {
        return json!(["error", {"type": "unknownMethod"}, tag]);
    }
    let asked: Option<Vec<Value>> = match (&arguments["#ids"], &arguments["ids"]) {
        (Value::Object(reference), _) => before
            .iter()
            .find(|answer| answer[2] == reference["resultOf"])
            .and_then(|answer| answer[1]["ids"].as_array().cloned()),
        (_, Value::Array(ids)) => Some(ids.clone()),
        _ => None,
    };
    let properties = arguments["properties"].as_array();
    let shown = |object: &Value| -> Value {
        let mut fields = Map::new();
        for (key, value) in object.as_object().unwrap() {
            let asked = properties.is_none_or(|names| names.iter().any(|name| name == key));
            if key == "id" || asked {
                fields.insert(key.clone(), value.clone());
            }
        }
        Value::Object(fields)
    };
    let (list, not_found): (Vec<Value>, Vec<Value>) = match asked {
        None => (
            objects.iter().take(MOST_IN_GET).map(shown).collect(),
            Vec::new(),
        ),
        Some(ids) => {
            let found = |wanted: &Value| objects.iter().find(|object| id(object) == *wanted);
            (
                ids.iter().filter_map(found).map(shown).collect(),
                ids.iter()
                    .filter(|wanted| found(wanted).is_none())
                    .cloned()
                    .collect(),
            )
        }
    };
    json!([method, {"list": list, "notFound": not_found}, tag])
}
