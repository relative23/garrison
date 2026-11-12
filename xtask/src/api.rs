//! The web API contract for the frontend, from the Rust service itself.
//!
//! Writes `frontend/api/openapi.json` (from the response types of crate `web`)
//! and `frontend/api/modules.json` (from the module registry in `core`);
//! `npm run api` then generates `frontend/src/api/schema.gen.ts`. The test
//! `crates/web/tests/contract_files.rs` fails while the files are outdated.

use std::fs;
use std::path::Path;

/// Write the files that differ from what the code produces.
pub(crate) fn api(root: &Path) -> Result<(), String> {
    let target = root.join("frontend/api");
    for (name, content) in [
        ("openapi.json", garrison_web::openapi::text()),
        ("modules.json", garrison_core::modules::document()),
    ] {
        let path = target.join(name);
        if fs::read_to_string(&path).is_ok_and(|current| current == content) {
            continue;
        }
        fs::write(&path, content).map_err(|error| format!("{}: {error}", path.display()))?;
        println!("Wrote frontend/api/{name}");
    }
    Ok(())
}
