//! Every refusal of `garrison upgrade`: its one constructor each.

use std::fmt::Display;
use std::path::Path;

use crate::install::BASE;
use crate::state::{State, states};

/// The refusal as printed: nothing was installed, whichever it is.
pub(super) fn nothing_installed(state: State) -> State {
    State {
        text: format!("{} Nothing was installed.", state.text),
        ..state
    }
}

states! {
    /// What the system said of `what`, a file or a command.
    pub(super) fn io(what: impl Display, error: impl Display) = "upgrade-io":
        "{what}: {error}.";
    pub(super) fn not_root() = "upgrade-not-root":
        "Run as root.";
    pub(super) fn not_an_archive(archive: &Path) = "upgrade-not-an-archive":
        "{} is not named like a release archive, garrison-<version>-<arch>.tar.gz.",
        archive.display();
    pub(super) fn other_architecture(name: &str, built: &str, host: &str)
        = "upgrade-other-architecture":
        "{name} is built for {built}, this host is {host}.";
    pub(super) fn older_archive(version: &str, running: &str) = "upgrade-older-archive":
        "{version} is older than the running {running}; go back with `garrison install \
         --rollback` instead.";
    pub(super) fn no_version(version: &str, running: &str) = "upgrade-no-version":
        "{version} or {running} is no semantic version.";
    pub(super) fn not_installed() = "upgrade-not-installed":
        "Run the installed release: {BASE}/current/bin/garrison upgrade <archive>.";
    pub(super) fn no_keys() = "upgrade-no-keys":
        "This release trusts no signing key yet, so it cannot check an archive. Check the archive \
         by hand (docs/operator/installation.md) and run its own installer.";
    pub(super) fn bad_key(line: &str) = "upgrade-bad-key":
        "{line:?} is not a minisign public key.";
    pub(super) fn not_a_signature() = "upgrade-not-a-signature":
        "The signature file is not a minisign signature.";
    pub(super) fn signature_mismatch() = "upgrade-signature-mismatch":
        "The archive does not match its signature, or no key this release trusts made it.";
    /// The signature's trusted comment names another release than the archive.
    pub(super) fn other_release(signed: &str, expected: &str) = "upgrade-other-release":
        "The signature is for {signed:?}, not for {expected:?}.";
    pub(super) fn no_tar() = "upgrade-no-tar":
        "tar is required.";
    /// `said`: what tar said.
    pub(super) fn unpack_failed(said: &str) = "upgrade-unpack-failed":
        "The archive cannot be unpacked: {said}.";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_of_an_upgrade_says_its_line() {
        let refused = |state| nothing_installed(state);
        crate::state::table(
            &[include_str!("states.rs")],
            &[
                refused(io(
                    "/root/garrison-0.2.0-x86_64.tar.gz.minisig",
                    "No such file or directory (os error 2)",
                )),
                refused(not_root()),
                refused(not_an_archive(Path::new("/root/release.tgz"))),
                refused(other_architecture(
                    "garrison-0.2.0-aarch64.tar.gz",
                    "aarch64",
                    "x86_64",
                )),
                refused(older_archive("0.1.2", "0.2.0")),
                refused(no_version("latest", "0.2.0")),
                refused(not_installed()),
                refused(no_keys()),
                refused(bad_key("not a key")),
                refused(not_a_signature()),
                refused(signature_mismatch()),
                refused(other_release(
                    "garrison 0.1.0 x86_64",
                    "garrison 0.2.0 x86_64",
                )),
                refused(no_tar()),
                refused(unpack_failed("gzip: stdin: not in gzip format")),
            ],
        );
    }
}
