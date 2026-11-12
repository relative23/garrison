#!/bin/sh
# Two archives of the current commit for testing `garrison upgrade`: both trust
# a throwaway minisign key and are signed with it, the second has the higher
# version. Never publish them: the key's secret half lies next to them.
#
#   [ARCH=x86_64] scripts/signed-releases.sh OUT-DIR
#
# Writes OUT-DIR/garrison-<version>-<arch>.tar.gz and .minisig for both
# versions, OUT-DIR/test.key and test.pub, and OUT-DIR/versions (two lines,
# older first). Needs what `cargo xtask release` needs, plus minisign.
set -eu

out=$(mkdir -p "$1" && cd "$1" && pwd)
arch=${ARCH:-x86_64}
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/var/tmp}/garrison-signed.XXXXXX")
cleanup() {
    git -C "$root" worktree remove --force "$work/tree" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

git -C "$root" worktree add -q --detach "$work/tree" HEAD
cd "$work/tree"
minisign -G -W -f -p "$out/test.pub" -s "$out/test.key" >/dev/null
# The throwaway key is the only one these builds trust.
tail -n 1 "$out/test.pub" > deploy/signing/keys.txt

version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)
case $version in
    *-*) suffix=.test ;;
    *) suffix=-test ;;
esac
: > "$out/versions"
for number in 1 2; do
    next=$version$suffix.$number
    sed -i "/^\[workspace.package\]/,/^\[/s/^version = \".*\"$/version = \"$next\"/" Cargo.toml
    cargo update --workspace --offline --quiet
    GARRISON_SIGNING_KEY=$out/test.key cargo xtask release "$arch" > "$work/release-$number.log" 2>&1 ||
        { tail -n 20 "$work/release-$number.log"; exit 1; }
    cp "dist/garrison-$next-$arch.tar.gz" "dist/garrison-$next-$arch.tar.gz.minisig" "$out/"
    echo "$next" >> "$out/versions"
done
echo "Signed test archives in $out:"
ls "$out"
