//! Setup's states, each with its whole line: the one place in setup's tests
//! where their words stand.

use std::path::Path;

use garrison_core::files::ProtectedFileError;

use super::*;
use crate::state::State;

type Rows = Vec<(State, &'static str)>;

/// What setup refuses before it asks Stalwart anything.
fn before() -> Rows {
    let folder = Path::new("/etc/garrison/credentials");
    let denied = "Permission denied (os error 13)";
    let missing = ProtectedFileError::Unavailable("/root/admin.json".into());
    vec![
        (
            no_administrator(),
            "Name the Stalwart administrator: run this at a terminal to be asked, or pass \
             --admin-credential - with the JSON on standard input, or --admin-credential FILE. \
             [setup-no-administrator]",
        ),
        (
            again(file_unread(missing), "garrison stalwart setup"),
            "Protected file is unavailable: /root/admin.json. Run `garrison stalwart setup` again \
             once this is mended. [setup-file-unread]",
        ),
        (
            input_unread("Input/output error (os error 5)"),
            "standard input: Input/output error (os error 5) [setup-input-unread]",
        ),
        (
            administrator_too_long(),
            "The administrator on standard input is too long. [setup-administrator-too-long]",
        ),
        (
            administrator_not_json("invalid JSON: expected value at line 1 column 1"),
            "invalid JSON: expected value at line 1 column 1 [setup-administrator-not-json]",
        ),
        (
            administrator_unusable(),
            r#"The administrator needs {"username","secret"} or {"apiKey"} [setup-administrator-unusable]"#,
        ),
        (
            ask_failed(
                "/usr/bin/systemd-ask-password",
                "No such file or directory (os error 2)",
            ),
            "/usr/bin/systemd-ask-password: No such file or directory (os error 2) \
             [setup-ask-failed]",
        ),
        (
            no_secret(),
            "No secret was entered; nothing was changed. [setup-no-secret]",
        ),
        (
            not_root(folder, denied),
            "Setup cannot write the credentials folder /etc/garrison/credentials: Permission \
             denied (os error 13). Run it as root, as `sudo garrison stalwart setup`; nothing was \
             changed. [setup-not-root]",
        ),
        (
            folder_unwritable(
                folder,
                "Read-only file system (os error 30)",
                "garrison setup",
            ),
            "Setup cannot write the credentials folder /etc/garrison/credentials: Read-only file \
             system (os error 30). Nothing was changed; run `garrison setup` again once this is \
             mended. [setup-folder-unwritable]",
        ),
        (
            network_invalid("nonsense"),
            "invalid network nonsense [setup-network-invalid]",
        ),
        (
            network_host_bits("172.17.0.1/16"),
            "172.17.0.1/16 has host bits set [setup-network-host-bits]",
        ),
    ]
}

#[test]
fn every_state_of_setup_says_its_line() {
    let rows = [before()].concat();
    let sources = [include_str!("../states.rs"), include_str!("keys.rs")];
    crate::state::table(&sources, &rows);
}

/// A failure keeps its name with the run that mends it; the table holds the
/// words that clause adds.
#[test]
fn a_failure_keeps_its_name_with_the_run_that_mends_it() {
    let refused = administrator_unusable;
    let said = again(refused(), "garrison setup");
    assert_eq!(said.name, refused().name);
    assert_ne!(said, refused());
}
