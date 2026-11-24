//! A reproducible release archive per architecture. Nothing is published.
//!
//! Builds the interface (npm ci, npm run build), a static binary for each
//! target (musl, cross-compiled with cargo-zigbuild), the third-party notices
//! and SHA256SUMS, and packs `dist/garrison-<version>-<arch>.tar.gz` with
//! fixed timestamps, owners and modes, so the same commit always yields the
//! same archive.

mod guards;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use garrison_core::hex;
use sha2::{Digest, Sha256};

/// Where `npm run build` writes the interface (vite's `outDir`).
const INTERFACE: &str = "frontend/dist";
const ARCHITECTURES: [&str; 2] = ["aarch64", "x86_64"];

fn run(command: &mut Command) -> Result<(), String> {
    let shown = format!("{command:?}");
    eprintln!("$ {shown}");
    let status = command
        .status()
        .map_err(|error| format!("{shown}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{shown} failed: {status}"))
    }
}

fn output(command: &mut Command) -> Result<String, String> {
    let result = command.output().map_err(|error| error.to_string())?;
    if !result.status.success() {
        return Err(String::from_utf8_lossy(&result.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
}

/// Timestamps come from the last commit, never from the build machine's clock.
fn source_date(root: &Path) -> Result<String, String> {
    output(
        Command::new("git")
            .args(["log", "-1", "--format=%ct"])
            .current_dir(root),
    )
}

fn version(root: &Path) -> Result<String, String> {
    let text = fs::read_to_string(root.join("Cargo.toml")).map_err(|error| error.to_string())?;
    let start = text
        .find("[workspace.package]")
        .ok_or("no [workspace.package]")?;
    text[start..]
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| "no workspace version".to_owned())
}

/// Sign `file` with the minisign secret key at `key`; minisign asks for the
/// key's password. The trusted comment names what was signed, and `garrison
/// upgrade` refuses a signature whose comment names another release.
fn sign(file: &Path, key: &Path, comment: &str) -> Result<(), String> {
    run(Command::new("minisign")
        .args(["-S", "-s"])
        .arg(key)
        .arg("-m")
        .arg(file)
        .args(["-t", comment]))
}

/// The pinned toolchain, as rust-toolchain.toml names it.
fn toolchain(root: &Path) -> Result<String, String> {
    let text =
        fs::read_to_string(root.join("rust-toolchain.toml")).map_err(|error| error.to_string())?;
    text.parse::<toml::Table>()
        .map_err(|error| format!("rust-toolchain.toml: {error}"))?
        .get("toolchain")
        .and_then(|table| table.get("channel"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "rust-toolchain.toml names no channel".into())
}

/// The notices of the Rust standard library, musl libc's among them, as the
/// pinned toolchain ships them: the binary links both statically.
fn standard_library_notices(root: &Path) -> Result<PathBuf, String> {
    let sysroot = output(
        Command::new("rustc")
            .args(["--print", "sysroot"])
            .current_dir(root),
    )?;
    let path = Path::new(&sysroot).join("share/doc/rust/COPYRIGHT-library.html");
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("{} is missing from the toolchain", path.display()))
    }
}

fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("{}: {error}", source.display()))?
        .flatten()
    {
        let (from, to) = (entry.path(), target.join(entry.file_name()));
        if from.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            fs::copy(&from, &to).map_err(|error| format!("{}: {error}", from.display()))?;
        }
    }
    Ok(())
}

/// The committed files below `folder`, so local leftovers never ship.
fn copy_tracked(root: &Path, folder: &str, target: &Path) -> Result<(), String> {
    let listed = output(
        Command::new("git")
            .args(["ls-files", "--", folder])
            .current_dir(root),
    )?;
    for name in listed.lines() {
        let relative = Path::new(name)
            .strip_prefix(folder)
            .map_err(|error| error.to_string())?;
        let destination = target.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        fs::copy(root.join(name), &destination).map_err(|error| format!("{name}: {error}"))?;
    }
    Ok(())
}

fn files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, found);
        } else {
            found.push(path);
        }
    }
}

fn checksums(stage: &Path) -> Result<(), String> {
    let mut found = Vec::new();
    files(stage, &mut found);
    let mut lines: Vec<String> = Vec::new();
    for path in found {
        let relative = path
            .strip_prefix(stage)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .into_owned();
        if relative == "SHA256SUMS" {
            continue;
        }
        let digest = Sha256::digest(fs::read(&path).map_err(|error| error.to_string())?);
        lines.push(format!("{}  {relative}", hex::encode(&digest)));
    }
    lines.sort_by(|left, right| left[66..].cmp(&right[66..]));
    fs::write(stage.join("SHA256SUMS"), lines.join("\n") + "\n").map_err(|error| error.to_string())
}

/// GNU tar and gzip with every varying field fixed, one after the other: a
/// pipe ends with gzip's status alone, and a tar that failed would leave an
/// archive of what it wrote until then.
fn pack(dist: &Path, name: &str, epoch: &str) -> Result<PathBuf, String> {
    let archive = dist.join(format!("{name}.tar.gz"));
    let tar = dist.join(format!("{name}.tar"));
    let packed = run(Command::new("tar")
        .args([
            "--sort=name",
            &format!("--mtime=@{epoch}"),
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mode=u=rwX,go=rX",
            "--format=pax",
            "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
            "-C",
        ])
        .arg(dist)
        .arg("-cf")
        .arg(&tar)
        .arg(name))
    // gzip puts the archive in the tar file's place.
    .and_then(|()| run(Command::new("gzip").args(["-n", "-9", "-f"]).arg(&tar)));
    if let Err(error) = packed {
        let _ = fs::remove_file(&tar);
        return Err(error);
    }
    let digest = Sha256::digest(fs::read(&archive).map_err(|error| error.to_string())?);
    let sum = hex::encode(&digest);
    let file = archive
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    fs::write(
        dist.join(format!("{file}.sha256")),
        format!("{sum}  {file}\n"),
    )
    .map_err(|error| error.to_string())?;
    eprintln!("{}  sha256 {sum}", archive.display());
    Ok(archive)
}

fn binary(root: &Path, triple: &str, epoch: &str) -> Result<PathBuf, String> {
    let cargo_home = std::env::var("CARGO_HOME")
        .unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap_or_default()));
    // Paths of this machine must not end up in panic messages of the binary.
    let flags = format!(
        "--remap-path-prefix={}=/build --remap-path-prefix={cargo_home}=/cargo",
        root.display()
    );
    run(
        Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args([
                "zigbuild",
                "--release",
                "--locked",
                "--package",
                "garrison",
                "--target",
                triple,
            ])
            .env("RUSTFLAGS", flags)
            .env("SOURCE_DATE_EPOCH", epoch)
            .current_dir(root),
    )?;
    Ok(target_directory(root)?
        .join(triple)
        .join("release/garrison"))
}

/// Cargo's build directory, which `CARGO_TARGET_DIR` or a config may move.
fn target_directory(root: &Path) -> Result<PathBuf, String> {
    let metadata = output(
        Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
            .current_dir(root),
    )?;
    let value: serde_json::Value =
        serde_json::from_str(&metadata).map_err(|error| error.to_string())?;
    value["target_directory"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| "cargo metadata names no target directory".into())
}

/// `[--rehearsal] [ARCH ...]`: whether a rehearsal is asked for, and the
/// architectures to build, all of them where none is named.
fn options(arguments: &[String]) -> Result<(bool, Vec<&str>), String> {
    let mut rehearsal = false;
    let mut chosen = Vec::new();
    for argument in arguments {
        match argument.as_str() {
            "--rehearsal" => rehearsal = true,
            option if option.starts_with('-') => {
                return Err(format!("unknown option {option}; known: --rehearsal"));
            }
            name if ARCHITECTURES.contains(&name) => chosen.push(name),
            name => {
                return Err(format!(
                    "unknown architecture {name}; known: {}",
                    ARCHITECTURES.join(", ")
                ));
            }
        }
    }
    if chosen.is_empty() {
        chosen = ARCHITECTURES.to_vec();
    }
    Ok((rehearsal, chosen))
}

/// minisign writes the signature of `file` beside it.
fn signature(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".minisig");
    PathBuf::from(name)
}

/// Build the archives `arguments` ask for: from a clean checkout of the
/// release's tag, or, with `--rehearsal`, from any tree for tests.
pub(crate) fn release(root: &Path, arguments: &[String]) -> Result<(), String> {
    let (rehearsal, chosen) = options(arguments)?;
    let version = version(root)?;
    let source = guards::source(root, &version, rehearsal)?;
    guards::tools()?;
    if let guards::Source::Rehearsal(what) = &source {
        eprintln!("{what}: never publish these archives");
    }
    let epoch = source_date(root)?;
    let (toolchain, standard_library) = (toolchain(root)?, standard_library_notices(root)?);
    // The secret key stays with the maintainer; without it the archives are unsigned.
    let signing = std::env::var_os("GARRISON_SIGNING_KEY").map(PathBuf::from);
    let frontend = root.join("frontend");
    run(Command::new("npm")
        .args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])
        .current_dir(&frontend)
        .env("SOURCE_DATE_EPOCH", &epoch))?;
    run(Command::new("npm")
        .args(["run", "build"])
        .current_dir(&frontend)
        .env("SOURCE_DATE_EPOCH", &epoch))?;
    let dist = root.join("dist");
    for architecture in chosen {
        let triple = format!("{architecture}-unknown-linux-musl");
        let name = format!("garrison-{version}-{architecture}");
        let stage = dist.join(&name);
        let _ = fs::remove_dir_all(&stage);
        fs::create_dir_all(stage.join("bin")).map_err(|error| error.to_string())?;
        fs::copy(binary(root, &triple, &epoch)?, stage.join("bin/garrison"))
            .map_err(|error| error.to_string())?;
        copy_tree(&root.join(INTERFACE), &stage.join("static"))?;
        copy_tracked(root, "deploy", &stage.join("deploy"))?;
        copy_tracked(root, "docs", &stage.join("docs"))?;
        for file in ["LICENSE", "README.md"] {
            fs::copy(root.join(file), stage.join(file)).map_err(|error| error.to_string())?;
        }
        fs::write(
            stage.join("THIRD_PARTY_NOTICES.txt"),
            crate::notices::text(root, &triple)?,
        )
        .map_err(|error| error.to_string())?;
        fs::create_dir_all(stage.join("licenses")).map_err(|error| error.to_string())?;
        fs::copy(
            &standard_library,
            stage.join("licenses/rust-standard-library.html"),
        )
        .map_err(|error| error.to_string())?;
        let sbom =
            crate::sbom::cyclonedx(root, &triple, &version, architecture, &epoch, &toolchain)?;
        fs::write(stage.join("sbom.cdx.json"), &sbom).map_err(|error| error.to_string())?;
        fs::write(stage.join("VERSION"), format!("{version}\n"))
            .map_err(|error| error.to_string())?;
        checksums(&stage)?;
        let archive = pack(&dist, &name, &epoch)?;
        // Next to the archive too, for scanners that do not unpack it.
        let listing = dist.join(format!("{name}.cdx.json"));
        fs::write(&listing, &sbom).map_err(|error| error.to_string())?;
        let comment = format!("garrison {version} {architecture}");
        match &signing {
            Some(key) => {
                sign(&archive, key, &comment)?;
                sign(&listing, key, &format!("{comment} sbom"))?;
                if rehearsal {
                    guards::signed_by_no_release_key(
                        root,
                        &[signature(&archive), signature(&listing)],
                    )?;
                }
            }
            None => eprintln!("{name}: unsigned (GARRISON_SIGNING_KEY is not set)"),
        }
    }
    Ok(())
}

/// The SBOM that `release` writes for `target`, to review without a build.
pub(crate) fn sbom(root: &Path, target: &str) -> Result<String, String> {
    let architecture = target.split('-').next().unwrap_or(target);
    crate::sbom::cyclonedx(
        root,
        target,
        &version(root)?,
        architecture,
        &source_date(root)?,
        &toolchain(root)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn a_rehearsal_is_asked_for_by_name_beside_the_architectures() {
        let all = vec!["aarch64", "x86_64"];
        assert_eq!(options(&arguments(&[])), Ok((false, all.clone())));
        assert_eq!(options(&arguments(&["--rehearsal"])), Ok((true, all)));
        for order in [["--rehearsal", "x86_64"], ["x86_64", "--rehearsal"]] {
            assert_eq!(options(&arguments(&order)), Ok((true, vec!["x86_64"])));
        }
        assert_eq!(
            options(&arguments(&["--allow-dirty"])),
            Err("unknown option --allow-dirty; known: --rehearsal".to_owned())
        );
        assert_eq!(
            options(&arguments(&["x86_64", "riscv64"])),
            Err("unknown architecture riscv64; known: aarch64, x86_64".to_owned())
        );
    }

    /// What tar wrote before it failed is never packed, hashed and signed.
    #[test]
    fn a_tar_that_fails_fails_the_packing() {
        let dist = tempfile::tempdir().unwrap();
        // Nothing is staged under this name, so tar cannot read it.
        let name = "garrison-0.0.0-x86_64";
        let packed = pack(dist.path(), name, "0");
        assert!(packed.is_err(), "{packed:?}");
        let left: Vec<_> = fs::read_dir(dist.path()).unwrap().flatten().collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn signatures_lie_beside_what_they_sign() {
        assert_eq!(
            signature(Path::new("dist/garrison-1.2.3-x86_64.tar.gz")),
            Path::new("dist/garrison-1.2.3-x86_64.tar.gz.minisig")
        );
    }
}
