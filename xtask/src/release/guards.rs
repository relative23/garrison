//! What a release build refuses before it builds anything: tools other than
//! the pinned ones, and a source other than a clean checkout of the release's
//! tag, unless it is a rehearsal. A rehearsal is for tests, is never
//! published and is never signed with a key that releases trust.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::output;

/// The public keys whose signatures releases accept (`garrison upgrade`).
const KEYS: &str = "deploy/signing/keys.txt";
/// How many uncommitted changes a refusal lists before it counts the rest.
const LISTED: usize = 10;

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

/// The archive is packed with options only GNU tar has; another tar refuses
/// them, or orders and dates the files its own way.
fn gnu_tar(found: &str) -> Result<(), String> {
    let first = found.lines().next().unwrap_or_default();
    if first.contains("GNU tar") {
        Ok(())
    } else {
        Err(format!(
            "tar: found {first:?}, need GNU tar for a reproducible archive"
        ))
    }
}

/// The tools on `PATH` are the pinned ones.
pub(super) fn tools() -> Result<(), String> {
    let tar = output(Command::new("tar").arg("--version"))
        .map_err(|error| format!("tar is required (GNU tar): {error}"))?;
    gnu_tar(&tar)?;
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

/// What the archives are built from.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Source {
    /// A clean checkout of the tag `v<version>`: what the Release workflow
    /// attests, the maintainer signs and installations upgrade to.
    Release,
    /// Anything else, built on request for tests; the text says what it is.
    Rehearsal(String),
}

fn git(root: &Path, arguments: &[&str]) -> Result<String, String> {
    output(Command::new("git").args(arguments).current_dir(root))
        .map_err(|error| format!("git {}: {}", arguments.join(" "), error.trim()))
}

/// A release is built from its tagged commit alone: nothing changed that is
/// not committed, no file that Git does not know of (one it ignores, such as
/// build output, does not count), and `HEAD` on the tag `v<version>`.
pub(super) fn source(root: &Path, version: &str, rehearsal: bool) -> Result<Source, String> {
    // Untracked files are named whatever status.showUntrackedFiles says.
    let changes = git(root, &["status", "--porcelain", "--untracked-files=normal"])?;
    let changes: Vec<&str> = changes.lines().collect();
    let tags = git(root, &["tag", "--points-at", "HEAD"])?;
    let tags: Vec<&str> = tags.lines().collect();
    let head = git(root, &["rev-parse", "--short", "HEAD"])?;
    let tag = format!("v{version}");
    let tagged = tags.contains(&tag.as_str());
    if rehearsal {
        let uncommitted = match changes.len() {
            0 => String::new(),
            count => format!(" with {count} uncommitted change(s)"),
        };
        let other = if tagged {
            String::new()
        } else {
            format!(", which is not the tag {tag}")
        };
        return Ok(Source::Rehearsal(format!(
            "rehearsal of {head}{uncommitted}{other}"
        )));
    }
    let instead = "or build a rehearsal, which is never published: cargo xtask release --rehearsal";
    if !changes.is_empty() {
        let mut listed: Vec<String> = changes
            .iter()
            .take(LISTED)
            .map(|line| format!("  {}", line.trim_start()))
            .collect();
        if changes.len() > LISTED {
            listed.push(format!("  and {} more", changes.len() - LISTED));
        }
        return Err(format!(
            "the working tree has changes that are not committed, and a release is \
             built from its tag alone:\n{}\nCommit or remove them, {instead}",
            listed.join("\n")
        ));
    }
    if !tagged {
        let carries = if tags.is_empty() {
            String::new()
        } else {
            format!(" (it carries {})", tags.join(", "))
        };
        return Err(format!(
            "HEAD ({head}) is not the commit of the tag {tag}{carries}, and a release \
             of {version} is built from that tag alone. Build it in a checkout of the \
             tag (git worktree add --detach ../garrison-{tag} {tag}), {instead}"
        ));
    }
    Ok(Source::Release)
}

/// The id of the key in a minisign public key (`Ed`) or signature (`ED`, or
/// `Ed` in legacy mode): eight bytes after the two of the algorithm.
fn key_id(line: &str) -> Option<[u8; 8]> {
    let bytes = STANDARD.decode(line.trim()).ok()?;
    match bytes.get(..10)? {
        [b'E', b'd' | b'D', id @ ..] => id.try_into().ok(),
        _ => None,
    }
}

/// Every key the keys file named in the history of `HEAD`: an installation
/// keeps trusting a key until it runs a release that no longer names it.
fn release_keys(root: &Path) -> Result<Vec<[u8; 8]>, String> {
    let history = git(root, &["log", "--format=", "--patch", "--", KEYS])?;
    Ok(history
        .lines()
        .filter_map(|line| line.strip_prefix('+'))
        .filter_map(key_id)
        .collect())
}

/// A rehearsal's archive must not pass for a release: if a key that releases
/// trust made one of `signatures`, all of them are removed again.
pub(super) fn signed_by_no_release_key(root: &Path, signatures: &[PathBuf]) -> Result<(), String> {
    let trusted = release_keys(root)?;
    let mut refused = false;
    for path in signatures {
        let text =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let id = text.lines().nth(1).and_then(key_id);
        refused |= id.is_some_and(|id| trusted.contains(&id));
    }
    if !refused {
        return Ok(());
    }
    for path in signatures {
        let _ = fs::remove_file(path);
    }
    Err(format!(
        "a rehearsal is never signed with a key that releases trust ({KEYS}): sign it \
         with a throwaway key, as scripts/signed-releases.sh does. Its signatures were \
         removed."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_gnu_tar_packs_the_archive() {
        assert_eq!(gnu_tar("tar (GNU tar) 1.35\nCopyright (C) 2023"), Ok(()));
        for other in ["bsdtar 3.7.4 - libarchive 3.7.4 zlib/1.3", ""] {
            let refused = gnu_tar(other).unwrap_err();
            assert!(refused.contains("need GNU tar"), "{refused}");
        }
    }

    /// A repository of its own in a temporary folder, with one commit: a
    /// README and a .gitignore that ignores `dist/`. Git runs without the
    /// user's or the system's configuration, so no signing or hook applies.
    struct Repository(tempfile::TempDir);

    impl Repository {
        fn new() -> Self {
            let repository = Repository(tempfile::tempdir().unwrap());
            repository.git(&["init", "--quiet"]);
            repository.write("README.md", "A test.\n");
            repository.write(".gitignore", "dist/\n");
            repository.git(&["add", "README.md", ".gitignore"]);
            repository.git(&["commit", "--quiet", "--message", "First"]);
            repository
        }

        fn root(&self) -> &Path {
            self.0.path()
        }

        fn write(&self, name: &str, text: &str) {
            let path = self.root().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }

        fn git(&self, arguments: &[&str]) {
            let status = Command::new("git")
                .args([
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                ])
                .args(["-c", "init.defaultBranch=main"])
                .args(arguments)
                .current_dir(self.root())
                .env_remove("GIT_DIR")
                .env_remove("GIT_WORK_TREE")
                .env_remove("GIT_INDEX_FILE")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()
                .unwrap();
            assert!(status.success(), "git {arguments:?}");
        }

        fn source(&self, rehearsal: bool) -> Result<Source, String> {
            source(self.root(), "1.2.3", rehearsal)
        }
    }

    #[test]
    fn a_release_is_built_from_a_clean_checkout_of_its_tag_only() {
        let repository = Repository::new();
        let untagged = repository.source(false).unwrap_err();
        assert!(
            untagged.contains(") is not the commit of the tag v1.2.3, and a release of 1.2.3"),
            "{untagged}"
        );
        assert!(untagged.contains("git worktree add --detach ../garrison-v1.2.3 v1.2.3"));
        assert!(untagged.ends_with("cargo xtask release --rehearsal"));
        repository.git(&["tag", "v1.2.2"]);
        let other = repository.source(false).unwrap_err();
        assert!(other.contains("tag v1.2.3 (it carries v1.2.2)"), "{other}");
        repository.git(&["tag", "v1.2.3"]);
        assert_eq!(repository.source(false), Ok(Source::Release));
        repository.git(&["tag", "--delete", "v1.2.3"]);
        repository.git(&["tag", "--annotate", "--message", "Release", "v1.2.3"]);
        assert_eq!(repository.source(false), Ok(Source::Release));
        // Build output and other ignored files are no part of the source.
        repository.write("dist/garrison-1.2.3-x86_64.tar.gz", "");
        assert_eq!(repository.source(false), Ok(Source::Release));
    }

    #[test]
    fn changes_that_are_not_committed_are_listed() {
        let repository = Repository::new();
        repository.git(&["tag", "v1.2.3"]);
        repository.write("README.md", "Changed.\n");
        repository.write("notes.txt", "Not added.\n");
        let error = repository.source(false).unwrap_err();
        assert_eq!(
            error,
            "the working tree has changes that are not committed, and a release is built \
             from its tag alone:\n  M README.md\n  ?? notes.txt\nCommit or remove them, \
             or build a rehearsal, which is never published: cargo xtask release --rehearsal"
        );
        repository.git(&["checkout", "--quiet", "--", "README.md"]);
        // A setting that hides untracked files from `git status` hides none here.
        repository.git(&["config", "status.showUntrackedFiles", "no"]);
        assert!(
            repository
                .source(false)
                .unwrap_err()
                .contains(":\n  ?? notes.txt\n")
        );
        for number in 10..22 {
            repository.write(&format!("note-{number}.txt"), "");
        }
        let error = repository.source(false).unwrap_err();
        assert!(error.contains(":\n  ?? note-10.txt\n"), "{error}");
        assert!(
            error.contains("\n  ?? note-19.txt\n  and 3 more\n"),
            "{error}"
        );
    }

    #[test]
    fn a_rehearsal_builds_any_tree_and_says_what_it_is() {
        let repository = Repository::new();
        repository.write("README.md", "Changed.\n");
        let Ok(Source::Rehearsal(what)) = repository.source(true) else {
            panic!("a rehearsal is not refused");
        };
        assert!(what.starts_with("rehearsal of "), "{what}");
        assert!(
            what.ends_with(" with 1 uncommitted change(s), which is not the tag v1.2.3"),
            "{what}"
        );
        repository.git(&["checkout", "--quiet", "--", "README.md"]);
        repository.git(&["tag", "v1.2.3"]);
        let Ok(Source::Rehearsal(what)) = repository.source(true) else {
            panic!("a rehearsal of the tag is not refused");
        };
        assert!(
            !what.contains("uncommitted") && !what.contains("not the tag"),
            "{what}"
        );
        let elsewhere = tempfile::tempdir().unwrap();
        let error = source(elsewhere.path(), "1.2.3", true).unwrap_err();
        assert!(error.starts_with("git status --porcelain"), "{error}");
    }

    /// Real minisign output: a public key and a signature it made, and a
    /// signature by another key.
    const KEY: &str = include_str!("../../../crates/garrison/src/upgrade/fixtures/trusted.key.txt");
    const SIGNED: &str = include_str!("../../../crates/garrison/src/upgrade/fixtures/good.minisig");
    const FOREIGN: &str =
        include_str!("../../../crates/garrison/src/upgrade/fixtures/foreign.minisig");

    #[test]
    fn keys_and_signatures_name_their_key() {
        let signed = SIGNED.lines().nth(1).and_then(key_id);
        assert!(signed.is_some());
        assert_eq!(key_id(KEY), signed);
        assert_ne!(FOREIGN.lines().nth(1).and_then(key_id), signed);
        let published = include_str!("../../../deploy/signing/keys.txt");
        let listed = published
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .count();
        assert!(listed > 0);
        assert_eq!(published.lines().filter_map(key_id).count(), listed);
        for other in ["", "# a comment", "not base64", "AAAAAAAAAAAAAAAA"] {
            assert_eq!(key_id(other), None, "{other}");
        }
    }

    #[test]
    fn a_rehearsal_signed_with_a_key_releases_trust_loses_its_signatures() {
        let repository = Repository::new();
        repository.write(KEYS, &format!("# Trusted keys\n{KEY}"));
        repository.git(&["add", KEYS]);
        repository.git(&["commit", "--quiet", "--message", "Trust a key"]);
        // A later release drops the key; earlier ones still trust it.
        repository.write(KEYS, "# Trusted keys\n");
        repository.git(&["commit", "--quiet", "--all", "--message", "Drop the key"]);
        let signatures = [
            repository.root().join("dist/a.tar.gz.minisig"),
            repository.root().join("dist/a.cdx.json.minisig"),
        ];
        repository.write("dist/a.tar.gz.minisig", FOREIGN);
        repository.write("dist/a.cdx.json.minisig", FOREIGN);
        assert_eq!(
            signed_by_no_release_key(repository.root(), &signatures),
            Ok(())
        );
        assert!(signatures.iter().all(|path| path.exists()));
        repository.write("dist/a.cdx.json.minisig", SIGNED);
        let error = signed_by_no_release_key(repository.root(), &signatures).unwrap_err();
        assert!(
            error.starts_with("a rehearsal is never signed with a key that releases trust"),
            "{error}"
        );
        assert!(signatures.iter().all(|path| !path.exists()));
    }

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
