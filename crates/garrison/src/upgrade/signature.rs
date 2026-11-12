//! Which release an archive claims to be, and whether a trusted key signed
//! exactly that claim.

use minisign_verify::{PublicKey, Signature};

/// The minisign public keys this release accepts for the next one. They are
/// compiled in: an archive is never trusted to name its own keys.
const TRUSTED: &str = include_str!("../../../../deploy/signing/keys.txt");

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Release {
    pub(super) version: String,
    pub(super) architecture: String,
}

impl Release {
    /// What the release build writes into the signature's trusted comment.
    pub(super) fn comment(&self) -> String {
        format!("garrison {} {}", self.version, self.architecture)
    }
}

/// The release a file name announces: `garrison-<version>-<arch>.tar.gz`.
pub(super) fn announced(file_name: &str) -> Option<Release> {
    let rest = file_name
        .strip_prefix("garrison-")?
        .strip_suffix(".tar.gz")?;
    let (version, architecture) = rest.rsplit_once('-')?;
    if version.is_empty() || !["x86_64", "aarch64"].contains(&architecture) {
        return None;
    }
    Some(Release {
        version: version.to_owned(),
        architecture: architecture.to_owned(),
    })
}

/// The compiled-in keys.
pub(super) fn trusted() -> Result<Vec<PublicKey>, String> {
    keys(TRUSTED)
}

/// One base64 public key per line; empty lines and `#` comments are skipped.
fn keys(text: &str) -> Result<Vec<PublicKey>, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            PublicKey::from_base64(line)
                .map_err(|_| format!("{line:?} is not a minisign public key."))
        })
        .collect()
}

/// `archive` must carry a signature by one of `keys`, in minisign's hashed
/// mode, and the signed comment must name exactly `release`: otherwise a
/// signature of an older release could be passed off for a newer name.
pub(super) fn check(
    keys: &[PublicKey],
    archive: &[u8],
    signature: &str,
    release: &Release,
) -> Result<(), String> {
    let signature = Signature::decode(signature)
        .map_err(|_| "The signature file is not a minisign signature.".to_owned())?;
    if !keys
        .iter()
        .any(|key| key.verify(archive, &signature, false).is_ok())
    {
        return Err(
            "The archive does not match its signature, or no key this release trusts made it."
                .into(),
        );
    }
    let expected = release.comment();
    if signature.trusted_comment() != expected {
        return Err(format!(
            "The signature is for {:?}, not for {expected:?}.",
            signature.trusted_comment()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCHIVE: &[u8] = include_bytes!("fixtures/archive");
    const KEY: &str = include_str!("fixtures/trusted.key.txt");

    fn release(version: &str) -> Release {
        Release {
            version: version.to_owned(),
            architecture: "x86_64".to_owned(),
        }
    }

    #[test]
    fn a_signature_by_a_trusted_key_for_this_release_passes() {
        let keys = keys(KEY).unwrap();
        check(
            &keys,
            ARCHIVE,
            include_str!("fixtures/good.minisig"),
            &release("0.2.0"),
        )
        .unwrap();
    }

    #[test]
    fn everything_else_is_refused() {
        let keys = keys(KEY).unwrap();
        let good = include_str!("fixtures/good.minisig");
        let mut changed = ARCHIVE.to_vec();
        changed[0] ^= 1;
        let mismatch =
            "The archive does not match its signature, or no key this release trusts made it.";
        assert_eq!(
            check(&keys, &changed, good, &release("0.2.0")).unwrap_err(),
            mismatch
        );
        let foreign = include_str!("fixtures/foreign.minisig");
        assert_eq!(
            check(&keys, ARCHIVE, foreign, &release("0.2.0")).unwrap_err(),
            mismatch
        );
        // minisign's legacy mode signs the file itself, not its hash.
        let legacy = include_str!("fixtures/legacy.minisig");
        assert_eq!(
            check(&keys, ARCHIVE, legacy, &release("0.2.0")).unwrap_err(),
            mismatch
        );
        assert_eq!(
            check(&[], ARCHIVE, good, &release("0.2.0")).unwrap_err(),
            mismatch
        );
        // A valid signature of 0.1.0 does not vouch for an archive named 0.2.0.
        let older = include_str!("fixtures/older.minisig");
        assert_eq!(
            check(&keys, ARCHIVE, older, &release("0.2.0")).unwrap_err(),
            "The signature is for \"garrison 0.1.0 x86_64\", not for \"garrison 0.2.0 x86_64\"."
        );
        assert_eq!(
            check(&keys, ARCHIVE, "no signature", &release("0.2.0")).unwrap_err(),
            "The signature file is not a minisign signature."
        );
    }

    #[test]
    fn the_compiled_in_keys_are_all_public_keys() {
        trusted().unwrap();
        assert_eq!(keys("# a comment\n\n").unwrap().len(), 0);
        assert!(keys("not a key").is_err());
    }

    /// Operators check a first installation with the key the README shows,
    /// so it must be one this release accepts for the next one, and the
    /// README must show every such key.
    #[test]
    fn the_readme_shows_exactly_the_compiled_in_keys() {
        let lines = |text: &'static str| -> Vec<&'static str> {
            text.lines()
                .map(str::trim)
                .filter(|line| PublicKey::from_base64(line).is_ok())
                .collect()
        };
        let compiled_in = lines(TRUSTED);
        assert_eq!(compiled_in.len(), trusted().unwrap().len());
        assert!(!compiled_in.is_empty(), "a release must trust a key");
        assert_eq!(lines(include_str!("../../../../README.md")), compiled_in);
    }

    #[test]
    fn random_names_announce_only_what_they_spell() {
        let mut noise = garrison_testing::noise::Noise::new(23);
        for _ in 0..20_000 {
            let name = format!(
                "{}{}{}",
                ["garrison-", "garrison", "x"][noise.below(3)],
                noise.text("0123456789.-_abx86", 20),
                [".tar.gz", "-x86_64.tar.gz", "-aarch64.tar.gz", ""][noise.below(4)]
            );
            if let Some(release) = announced(&name) {
                assert_eq!(
                    format!(
                        "garrison-{}-{}.tar.gz",
                        release.version, release.architecture
                    ),
                    name
                );
            }
        }
    }

    #[test]
    fn archive_names_announce_version_and_architecture() {
        assert_eq!(
            announced("garrison-0.1.0-dev.2-x86_64.tar.gz"),
            Some(Release {
                version: "0.1.0-dev.2".to_owned(),
                architecture: "x86_64".to_owned()
            })
        );
        assert_eq!(
            announced("garrison-1.0.0-aarch64.tar.gz").unwrap().version,
            "1.0.0"
        );
        for name in [
            "garrison-1.0.0-riscv64.tar.gz",
            "garrison--x86_64.tar.gz",
            "garrison-1.0.0-x86_64.tgz",
            "other-1.0.0-x86_64.tar.gz",
        ] {
            assert_eq!(announced(name), None, "{name}");
        }
    }
}
