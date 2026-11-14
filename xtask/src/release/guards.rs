//! What a release build checks before it builds anything.

use std::process::Command;

use super::output;

/// The cross toolchain is build input like the compiler: other versions
/// compile the C parts and link differently. Raise them deliberately.
const ZIG: &str = "0.17.0";
const ZIGBUILD: &str = "cargo-zigbuild 0.23.4";
/// Node.js builds the interface and compresses it with its own zlib and
/// brotli (`frontend/precompress.mjs`), so it is build input too. Its release
/// line is pinned, as the Release workflow and `engines` in
/// `frontend/package.json` name it; raise all three together.
const NODE: u32 = 24;
/// npm installs exactly what `frontend/package-lock.json` names, so a newer
/// one than Node.js brings builds the same interface.
const NPM: u32 = 11;

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

/// `found`, as `--version` prints it (`v24.22.3`, `11.3.0`), belongs to
/// release line `line`, or to a later one where `later` allows that.
fn fits(program: &str, found: &str, line: u32, later: bool, need: &str) -> Result<(), String> {
    let major = found
        .strip_prefix('v')
        .unwrap_or(found)
        .split('.')
        .next()
        .and_then(|first| first.parse::<u32>().ok());
    match major {
        Some(major) if major == line || (later && major > line) => Ok(()),
        _ => Err(format!("{program}: found {found}, need {need}")),
    }
}

fn release_line(program: &str, line: u32, later: bool, need: &str) -> Result<(), String> {
    let found = output(Command::new(program).arg("--version"))
        .map_err(|error| format!("{program} is required ({need}): {error}"))?;
    fits(program, &found, line, later, need)
}

/// The tools on `PATH` are the pinned ones.
pub(super) fn tools() -> Result<(), String> {
    require("zig", "version", ZIG)?;
    require("cargo-zigbuild", "--version", ZIGBUILD)?;
    release_line(
        "node",
        NODE,
        false,
        &format!("Node.js {NODE}, as the Release workflow uses"),
    )?;
    release_line(
        "npm",
        NPM,
        true,
        &format!("npm {NPM} or newer, as Node.js {NODE} brings it"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_and_npm_are_held_to_their_release_lines() {
        let node = |found| fits("node", found, NODE, false, "Node.js 24");
        assert_eq!(node("v24.0.0"), Ok(()));
        assert_eq!(node("v24.22.3"), Ok(()));
        assert_eq!(node("24"), Ok(()));
        for other in ["v22.11.0", "v26.1.0", "v2.4.0", ""] {
            assert_eq!(
                node(other),
                Err(format!("node: found {other}, need Node.js 24")),
                "{other}"
            );
        }
        let npm = |found| fits("npm", found, NPM, true, "npm 11 or newer");
        assert_eq!(npm("11.3.0"), Ok(()));
        assert_eq!(npm("12.0.2"), Ok(()));
        assert_eq!(
            npm("10.8.2"),
            Err("npm: found 10.8.2, need npm 11 or newer".to_owned())
        );
        assert_eq!(
            npm("not a version"),
            Err("npm: found not a version, need npm 11 or newer".to_owned())
        );
    }

    #[test]
    fn a_missing_tool_is_named_with_what_is_needed() {
        let error = release_line("garrison-no-such-tool", NODE, false, "Node.js 24").unwrap_err();
        assert!(
            error.starts_with("garrison-no-such-tool is required (Node.js 24): "),
            "{error}"
        );
    }

    /// A tag's Release run that finds other tools than this task asks for
    /// fails, and a tag is never moved: so both name the same ones, and the
    /// interface accepts the Node.js release line the archives are built with.
    #[test]
    fn the_release_workflow_installs_the_pinned_tools() {
        let workflow = include_str!("../../../.github/workflows/release.yml");
        let zig = format!("https://ziglang.org/download/{ZIG}/zig-x86_64-linux-{ZIG}.tar.xz");
        assert!(workflow.contains(&zig), "{zig}");
        let zigbuild = ZIGBUILD.replace("cargo-zigbuild ", "cargo-zigbuild --version ");
        assert!(workflow.contains(&format!("cargo install --locked {zigbuild}")));
        assert!(workflow.contains(&format!("node-version: \"{NODE}\"")));
        let package: serde_json::Value =
            serde_json::from_str(include_str!("../../../frontend/package.json")).unwrap();
        let least = package["engines"]["node"]
            .as_str()
            .and_then(|range| range.strip_prefix(">="))
            .and_then(|least| least.parse::<u32>().ok())
            .expect("engines.node in the form >=N");
        assert!(
            least <= NODE,
            "the interface needs Node.js {least} or newer"
        );
    }
}
