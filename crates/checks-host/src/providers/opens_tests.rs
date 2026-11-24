//! One rule held over every place of this crate that opens a file: no check
//! waits for a FIFO's writer, or follows a link, where another user may
//! replace the file, as the job's own user may a receipt in its folder or
//! the webmail's user its plugins. Such a file is opened through
//! `garrison_core::files` alone, which opens without following a link and
//! without waiting, and reads regular files only. A new place that opens a
//! file fails here until it is named below with what it opens.

use std::collections::BTreeSet;

use crate::testing::product_code;

/// The calls by which this crate's code opens a file.
const OPENS: [&str; 9] = [
    "File::open(",
    "OpenOptions",
    "fs::read(",
    "read_to_string(",
    "rustix::fs::open(",
    "read_bounded(",
    "read_json(",
    "read_json_with_metadata(",
    "open_regular_file(",
];

#[test]
fn no_check_waits_for_a_file_that_another_user_may_replace() {
    let found: BTreeSet<(String, String)> = product_code()
        .iter()
        .flat_map(|(file, code)| {
            OPENS
                .iter()
                .filter(|call| code.contains(**call))
                .map(|call| (file.clone(), (*call).to_owned()))
        })
        .collect();
    let known = [
        (
            "providers/backupcheck.rs",
            "read_json_with_metadata(",
            "the report, through core",
        ),
        (
            "providers/hidden.rs",
            "read_to_string(",
            "/proc/self/mountinfo, the kernel's",
        ),
        (
            "providers/host.rs",
            "read_to_string(",
            "the files below `proc`, which only the kernel writes",
        ),
        (
            "providers/hostcare/restart.rs",
            "read_to_string(",
            "below `root`, the kernel's osrelease and root's /run/reboot-required.pkgs",
        ),
        (
            "providers/receipt.rs",
            "read_json_with_metadata(",
            "the receipt, through core",
        ),
        (
            "providers/receipt/unread.rs",
            "open_regular_file(",
            "the receipt again, to say why it was not read, through core",
        ),
        (
            "providers/web.rs",
            "read_bounded(",
            "the webmail's registry and bundles, through core",
        ),
    ];
    let named: BTreeSet<(String, String)> = known
        .iter()
        .map(|(file, call, _)| ((*file).to_owned(), (*call).to_owned()))
        .collect();
    assert_eq!(
        found, named,
        "a place that opens a file and is not named here"
    );
}
