//! One rule held over every place of this crate's code that calls the file
//! system: each form of call is counted in each file, with the names that
//! the file takes from `garrison_core::files` and `garrison_core::sqlite`,
//! and named below with what it reads and what bounds its wait, so that a
//! new call, or one more of a form in a file, fails here until it is looked
//! at. Where another user may replace the file, as the job's own user may a
//! receipt in its folder or the webmail's user its plugins, it is opened
//! through `garrison_core::files`, which follows no link, does not wait for
//! a FIFO's writer and reads regular files only. A path that an operator
//! names may lie on a file system that does not answer, as a hard NFS
//! mount whose server is gone: it is asked through `answered_by`, which
//! waits no longer than the check's time. Comment lines are not read; a
//! path's `is_dir`, `is_file` and `is_symlink`, which read as a metadata's
//! do, and other crates' helpers, but for core's, are not seen.

use std::collections::BTreeMap;

use crate::testing::product_code;

/// The forms by which code opens, makes, writes, looks at or lists a file.
const CALLS: [&str; 22] = [
    "File::open(",
    "File::create(",
    "File::options(",
    "OpenOptions",
    "fs::read(",
    "read_to_string(",
    "fs::write(",
    "fs::copy(",
    "fs::rename(",
    "remove_file(",
    "remove_dir",
    "create_dir",
    "symlink_metadata(",
    "fs::metadata(",
    ".metadata()",
    "read_dir(",
    ".exists()",
    "try_exists(",
    "read_link(",
    "canonicalize(",
    "rustix::fs::",
    "openat(",
];

/// How often each form of call stands in `code`, comment lines left out:
/// the forms of [`CALLS`], and each name that `code` takes from core's
/// `files` or `sqlite`, as `files::<name>`, by its calls.
fn calls(code: &str) -> BTreeMap<String, usize> {
    let code: String = code
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut found = BTreeMap::new();
    for call in CALLS {
        let count = code.matches(call).count();
        if count > 0 {
            found.insert(call.to_owned(), count);
        }
    }
    for module in ["files", "sqlite"] {
        let path = format!("garrison_core::{module}::");
        for (at, _) in code.match_indices(&path) {
            let rest = &code[at + path.len()..];
            let names = match rest.strip_prefix('{') {
                Some(list) => list.split('}').next().unwrap_or_default(),
                None => rest
                    .split(|letter: char| !letter.is_alphanumeric() && letter != '_')
                    .next()
                    .unwrap_or_default(),
            };
            for name in names
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
            {
                let count = code.matches(&format!("{name}(")).count();
                found.insert(format!("{module}::{name}"), count);
            }
        }
    }
    found
}

/// Below `root` and `proc` lie the host's own system folders and the
/// kernel's /proc, which a test alone moves: where those do not answer, the
/// collector, whose database is there too, does not run at all.
const SYSTEM: &str = "below `root`, the host's own system folders";

/// Every call on the file system in this crate's code: the file, the form,
/// how often it stands there, and what it reads, with what bounds its wait.
const KNOWN: [(&str, &str, usize, &str); 30] = [
    (
        "providers/backupcheck.rs",
        "files::changed_only_by_trusted",
        1,
        "the report's metadata, read with it",
    ),
    (
        "providers/backupcheck.rs",
        "files::read_json_with_metadata",
        1,
        "the report, through core, waited for as long as its file system takes",
    ),
    (
        "providers/backupcheck.rs",
        "symlink_metadata(",
        1,
        "the report's path, waited for as long as its file system takes",
    ),
    (
        "providers/hidden.rs",
        "read_to_string(",
        1,
        "/proc/self/mountinfo, the kernel's",
    ),
    (
        "providers/host.rs",
        "files::answered_by",
        1,
        "the file system at `disk_path`, by the check's time",
    ),
    (
        "providers/host.rs",
        "read_to_string(",
        1,
        "the files below `proc`, the kernel's",
    ),
    (
        "providers/host.rs",
        "rustix::fs::",
        1,
        "statvfs of `disk_path`, in answered_by",
    ),
    (
        "providers/hostcare.rs",
        "files::answered_by",
        1,
        "the file system at `disk_path`, by the check's time",
    ),
    (
        "providers/hostcare.rs",
        "rustix::fs::",
        1,
        "statvfs of `disk_path`, in answered_by",
    ),
    ("providers/hostcare/packages.rs", ".exists()", 2, SYSTEM),
    ("providers/hostcare/packages.rs", ".metadata()", 1, SYSTEM),
    ("providers/hostcare/packages.rs", "File::open(", 1, SYSTEM),
    ("providers/hostcare/packages.rs", "fs::metadata(", 2, SYSTEM),
    ("providers/hostcare/packages.rs", "read_dir(", 4, SYSTEM),
    (
        "providers/hostcare/packages.rs",
        "read_to_string(",
        1,
        "below `root`, the head of a Release file of apt's",
    ),
    ("providers/hostcare/restart.rs", ".exists()", 1, SYSTEM),
    ("providers/hostcare/restart.rs", "read_dir(", 1, SYSTEM),
    (
        "providers/hostcare/restart.rs",
        "read_to_string(",
        1,
        "below `root`, the kernel's osrelease and root's /run/reboot-required.pkgs",
    ),
    ("providers/hostcare/restart.rs", "try_exists(", 1, SYSTEM),
    (
        "providers/receipt.rs",
        "files::changed_only_by_trusted",
        1,
        "the receipt's metadata, read with it",
    ),
    (
        "providers/receipt/unread.rs",
        "files::answered_by",
        2,
        "the receipt and the looks at why it was not read, by the check's time",
    ),
    (
        "providers/receipt/unread.rs",
        "files::open_regular_file",
        1,
        "the receipt again, to say why it was not read, in answered_by",
    ),
    (
        "providers/receipt/unread.rs",
        "files::read_json_with_metadata",
        1,
        "the receipt, through core, in answered_by",
    ),
    (
        "providers/receipt/unread.rs",
        "read_link(",
        1,
        "a link on the way to the receipt, in answered_by",
    ),
    (
        "providers/receipt/unread.rs",
        "symlink_metadata(",
        2,
        "the receipt's path and its folders, in answered_by",
    ),
    (
        "providers/version.rs",
        "files::answered_by",
        1,
        "the program's file, by the check's time",
    ),
    (
        "providers/version.rs",
        "fs::metadata(",
        1,
        "the program's file, in answered_by",
    ),
    (
        "providers/web.rs",
        "files::answered_by",
        2,
        "the registry, the bundles and the looks at them, by the card's time",
    ),
    (
        "providers/web.rs",
        "files::read_bounded",
        1,
        "the webmail's registry and bundles, through core, in answered_by",
    ),
    (
        "providers/web.rs",
        "symlink_metadata(",
        1,
        "a file below the folder that could not be read, in answered_by",
    ),
];

#[test]
fn every_call_on_the_file_system_is_named_with_what_bounds_its_wait() {
    let found: BTreeMap<(String, String), usize> = product_code()
        .iter()
        .flat_map(|(file, code)| {
            calls(code)
                .into_iter()
                .map(|(call, count)| ((file.clone(), call), count))
        })
        .collect();
    let named: BTreeMap<(String, String), usize> = KNOWN
        .iter()
        .map(|(file, call, count, _)| (((*file).to_owned(), (*call).to_owned()), *count))
        .collect();
    assert_eq!(
        found, named,
        "a call on the file system that is not named here, or one more of it"
    );
}

/// The forms the rule counts: a second plain read, a write, a creation, an
/// open through `File::options`, `openat` and a protected read of core's,
/// which an earlier form of this rule let pass, each count.
#[test]
fn the_rule_counts_every_form_and_every_call() {
    let before = "fn a() { fs::read_to_string(x); }";
    let after = "use garrison_core::files::{read_protected};\nfn a() { fs::read_to_string(x); }\n\
                 fn b() { fs::read_to_string(y); std::fs::write(y, b\"\"); \
                 File::create(y); File::options().read(true).open(y); \
                 rustix::fs::openat(CWD, y); read_protected(y, 1); }\n\
                 // fs::read_to_string(z) in a comment";
    assert_eq!(
        calls(before),
        BTreeMap::from([("read_to_string(".to_owned(), 1)])
    );
    let counted = calls(after);
    assert_eq!(counted["read_to_string("], 2);
    for form in [
        "fs::write(",
        "File::create(",
        "File::options(",
        "rustix::fs::",
        "openat(",
    ] {
        assert_eq!(counted.get(form), Some(&1), "{form}");
    }
    assert_eq!(counted.get("files::read_protected"), Some(&1));
}
