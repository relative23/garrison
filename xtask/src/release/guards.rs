//! What a release build checks before it builds anything.

use std::process::Command;

use super::output;

/// The cross toolchain is build input like the compiler: other versions
/// compile the C parts and link differently. Raise them deliberately.
const ZIG: &str = "0.17.0";
const ZIGBUILD: &str = "cargo-zigbuild 0.23.4";

fn require(program: &str, argument: &str, expected: &str) -> Result<(), String> {
    let found = output(Command::new(program).arg(argument))
        .map_err(|error| format!("{program} is required ({expected}): {error}"))?;
    if found == expected {
        Ok(())
    } else {
        Err(format!(
            "{program}: found {found}, need {expected} for a reproducible archive"
        ))
    }
}

/// The tools on `PATH` are the pinned ones.
pub(super) fn tools() -> Result<(), String> {
    require("zig", "version", ZIG)?;
    require("cargo-zigbuild", "--version", ZIGBUILD)
}
