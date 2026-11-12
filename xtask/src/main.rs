//! `cargo xtask <task>`: project checks that a compiler or linter cannot express.

// A command-line tool reports on the terminal.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod api;
mod brand;
mod components;
mod events;
mod lab;
mod layering;
mod notices;
mod release;
mod sbom;
mod sizes;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
Usage: cargo xtask <task>

Tasks:
  check     run every structural check below
  layering  privileged crates must not depend on a web framework or async runtime
  sizes     handwritten source files stay at or below 500 lines
  api       write frontend/api/ from the Rust service (cargo test checks it)
  brand     write the logo files in docs/brand (needs Inkscape, rsvg-convert, Noto Sans)
  event-types SCHEMA.json  write crates/ingest/event_types.json from Stalwart's /api/schema
  lab       start [RELEASE]|stop the Stalwart instance for contract tests (eval the output of start)
  notices   print THIRD_PARTY_NOTICES.txt for one target (default x86_64 musl)
  sbom      print the CycloneDX SBOM of a release for one target (default x86_64 musl)
  release   build dist/garrison-<version>-<arch>.tar.gz [ARCH ...]";

/// The repository root: the parent of this crate's directory.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the repository")
        .to_owned()
}

fn report(name: &str, problems: Result<Vec<String>, String>) -> bool {
    match problems {
        Ok(problems) if problems.is_empty() => {
            println!("{name}: ok");
            true
        }
        Ok(problems) => {
            eprintln!("{name}: {} problem(s)", problems.len());
            for problem in problems {
                eprintln!("  {problem}");
            }
            false
        }
        Err(error) => {
            eprintln!("{name}: {error}");
            false
        }
    }
}

fn main() -> ExitCode {
    let root = root();
    let task = std::env::args().nth(1);
    let passed = match task.as_deref() {
        Some("layering") => report("layering", layering::check(&root)),
        Some("sizes") => report("sizes", Ok(sizes::check(&root))),
        Some("check") => {
            let layering = report("layering", layering::check(&root));
            let sizes = report("sizes", Ok(sizes::check(&root)));
            layering && sizes
        }
        Some("api") => api::api(&root)
            .map_err(|error| eprintln!("api: {error}"))
            .is_ok(),
        Some("brand") => brand::brand(&root)
            .map_err(|error| eprintln!("brand: {error}"))
            .is_ok(),
        Some("event-types") => events::event_types(&root, std::env::args().nth(2).as_deref())
            .map_err(|error| eprintln!("event-types: {error}"))
            .is_ok(),
        Some("lab") => lab::lab(
            std::env::args().nth(2).as_deref(),
            std::env::args().nth(3).as_deref(),
        )
        .map_err(|error| eprintln!("lab: {error}"))
        .is_ok(),
        Some("notices") => {
            let target = std::env::args()
                .nth(2)
                .unwrap_or_else(|| "x86_64-unknown-linux-musl".into());
            match notices::text(&root, &target) {
                Ok(text) => {
                    print!("{text}");
                    true
                }
                Err(error) => {
                    eprintln!("notices: {error}");
                    false
                }
            }
        }
        Some("sbom") => {
            let target = std::env::args()
                .nth(2)
                .unwrap_or_else(|| "x86_64-unknown-linux-musl".into());
            match release::sbom(&root, &target) {
                Ok(text) => {
                    print!("{text}");
                    true
                }
                Err(error) => {
                    eprintln!("sbom: {error}");
                    false
                }
            }
        }
        Some("release") => {
            let architectures: Vec<String> = std::env::args().skip(2).collect();
            release::release(&root, &architectures)
                .map_err(|error| eprintln!("release: {error}"))
                .is_ok()
        }
        Some("-h" | "--help") => {
            println!("{USAGE}");
            true
        }
        _ => {
            eprintln!("{USAGE}");
            false
        }
    };
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
