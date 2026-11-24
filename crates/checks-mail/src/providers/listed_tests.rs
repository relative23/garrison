//! One rule held over every place of this crate's code and the collector's
//! that asks Stalwart for objects: a list of a kind is read in pages
//! (`JmapClient::listed`), which say how many objects there are, and never
//! with one get of all of them, which Stalwart answers with the first 500
//! alone and not a word of the rest (measured on 1.2.0). A new place that
//! asks Stalwart, or a new way of asking in a place, fails here until it is
//! named below with what it asks.

use std::collections::BTreeSet;
use std::path::Path;

/// How code asks Stalwart, with blanks taken out: through the client, by
/// its pages, by a get, by calls written by hand, or by HTTP of its own. A
/// get of SQLite's (`row.get::<_, T>`) is no get of Stalwart's.
const ASKS: [&str; 6] = [
    "JmapClient",
    ".listed::<",
    ".get::<",
    "call_many(",
    "\"x:",
    "garrison_stalwart::http",
];

/// The code of the sources below `source`, by their path below it, each
/// without its tests: what follows a file's first `#[cfg(test)]`, the files
/// whose names end in `tests.rs` and the folders whose names end in `tests`
/// are left out. Blanks are taken out, so that a call reads the same
/// however it is wrapped.
fn product_code(source: &Path) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut folders = vec![source.to_path_buf()];
    while let Some(folder) = folders.pop() {
        for entry in std::fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if !name.ends_with("tests") {
                    folders.push(path);
                }
            } else if path.extension().is_some_and(|suffix| suffix == "rs")
                && !name.ends_with("tests.rs")
            {
                let text = std::fs::read_to_string(&path).unwrap();
                let code = text.split("#[cfg(test)]").next().unwrap();
                let packed = code.split_whitespace().collect::<String>();
                let file = path.strip_prefix(source).unwrap().display().to_string();
                found.push((file, packed.replace(".get::<_,", "")));
            }
        }
    }
    found
}

#[test]
fn no_place_takes_the_first_objects_of_a_kind_for_all_of_them() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let found: BTreeSet<(String, String)> = ["checks-mail", "collector"]
        .iter()
        .flat_map(|name| {
            product_code(&crates.join(name).join("src"))
                .into_iter()
                .flat_map(move |(file, code)| {
                    ASKS.iter()
                        .filter(|mark| code.contains(**mark))
                        .map(|mark| (format!("{name}/{file}"), (*mark).to_owned()))
                        .collect::<Vec<_>>()
                })
        })
        .collect();
    let known = [
        (
            "checks-mail/providers/flow.rs",
            "JmapClient",
            "the client of the mail flow, with the collector's key",
        ),
        (
            "checks-mail/providers/flow.rs",
            ".listed::<",
            "the accounts whose domains name the mail by domain, the first of them in \
             pages, the others counted",
        ),
    ];
    let named: BTreeSet<(String, String)> = known
        .iter()
        .map(|(place, mark, _)| ((*place).to_owned(), (*mark).to_owned()))
        .collect();
    assert_eq!(
        found, named,
        "a place that asks Stalwart, or a way of asking, that is not named here"
    );
}
