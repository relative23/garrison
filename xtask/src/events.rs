//! The event labels from a Stalwart management schema.
//!
//! `cargo xtask event-types SCHEMA.json`, where SCHEMA.json is the body of
//! `GET /api/schema` from the supported Stalwart release, writes the native
//! label and explanation of every recorded event type to
//! `crates/ingest/event_types.json`. It fails if the policy names an event the
//! server does not know, which also catches typos: Stalwart rejects unknown
//! webhook event keys.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use serde_json::ser::{PrettyFormatter, Serializer};

const OUTPUT: &str = "crates/ingest/event_types.json";

#[derive(Serialize)]
struct Labels<'a> {
    label: &'a Value,
    explanation: &'a Value,
}

pub(crate) fn event_types(root: &Path, schema: Option<&str>) -> Result<(), String> {
    let path = Path::new(schema.ok_or("usage: cargo xtask event-types SCHEMA.json")?);
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let schema: Value =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let known: BTreeMap<&str, &Value> = schema["enums"]["EventType"]
        .as_array()
        .ok_or("the schema has no enums.EventType")?
        .iter()
        .filter_map(|item| Some((item["name"].as_str()?, item)))
        .collect();
    let recorded = garrison_ingest::policy::event_types();
    let missing: Vec<&str> = recorded
        .iter()
        .copied()
        .filter(|name| !known.contains_key(name))
        .collect();
    if !missing.is_empty() {
        return Err(format!("Unknown event types: {}", missing.join(", ")));
    }
    let empty = Value::String(String::new());
    let document: BTreeMap<&str, Labels> = recorded
        .iter()
        .map(|name| {
            let item = known[name];
            let labels = Labels {
                label: &item["label"],
                explanation: item.get("explanation").unwrap_or(&empty),
            };
            (*name, labels)
        })
        .collect();
    // One-space indentation, as the committed file is written.
    let mut bytes = Vec::new();
    document
        .serialize(&mut Serializer::with_formatter(
            &mut bytes,
            PrettyFormatter::with_indent(b" "),
        ))
        .map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let output = root.join(OUTPUT);
    fs::write(&output, bytes).map_err(|error| format!("{}: {error}", output.display()))?;
    println!("Wrote {} event types to {OUTPUT}", document.len());
    Ok(())
}
