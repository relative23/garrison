//! A reproducible release archive per architecture. Nothing is published.
//!
//! Builds the interface (npm ci, npm run build), a static binary for each
//! target (musl, cross-compiled with cargo-zigbuild), the third-party notices
//! and SHA256SUMS, and packs `dist/garrison-<version>-<arch>.tar.gz` with
//! fixed timestamps, owners and modes, so the same commit always yields the
//! same archive.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use garrison_core::hex;
use sha2::{Digest, Sha256};

/// Where `npm run build` writes the interface (vite's `outDir`).
const INTERFACE: &str = "frontend/dist";
const ARCHITECTURES: [&str; 2] = ["aarch64", "x86_64"];
/// The cross toolchain is build input like the compiler: other versions
/// compile the C parts and link differently. Raise them deliberately.
const ZIG: &str = "0.17.0";
const ZIGBUILD: &str = "cargo-zigbuild 0.23.4";

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

/// GNU tar and gzip with every varying field fixed.
fn pack(dist: &Path, name: &str, epoch: &str) -> Result<PathBuf, String> {
    let archive = dist.join(format!("{name}.tar.gz"));
    let tar = format!(
        "tar --sort=name --mtime=@{epoch} --owner=0 --group=0 --numeric-owner \
         --mode=u=rwX,go=rX --format=pax \
         --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
         -C '{dist}' -cf - '{name}' | gzip -n -9 > '{archive}'",
        dist = dist.display(),
        archive = archive.display()
    );
    run(Command::new("sh").args(["-c", &tar]))?;
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

/// Build the archives for `architectures` (all if empty).
pub(crate) fn release(root: &Path, architectures: &[String]) -> Result<(), String> {
    let chosen: Vec<&str> = if architectures.is_empty() {
        ARCHITECTURES.to_vec()
    } else {
        architectures.iter().map(String::as_str).collect()
    };
    if let Some(unknown) = chosen.iter().find(|name| !ARCHITECTURES.contains(name)) {
        return Err(format!(
            "unknown architecture {unknown}; known: {}",
            ARCHITECTURES.join(", ")
        ));
    }
    require("zig", "version", ZIG)?;
    require("cargo-zigbuild", "--version", ZIGBUILD)?;
    let (epoch, version) = (source_date(root)?, version(root)?);
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
