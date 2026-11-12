#!/bin/sh
# Install the older of two signed test archives, then check that `garrison
# upgrade` refuses every archive it must not install, changing nothing, and
# installs the newer one.
#
#   [DISTRO=debian-13] scripts/acceptance-upgrade.sh OUT-DIR
#
# OUT-DIR is what scripts/signed-releases.sh wrote. The host and its options:
# scripts/acceptance-lib.sh.
set -eu

out=$(cd "$1" && pwd)
arch=${ARCH:-x86_64}
older=$(sed -n 1p "$out/versions")
newer=$(sed -n 2p "$out/versions")
previous=$out/garrison-$older-$arch.tar.gz
release=$out/garrison-$newer-$arch.tar.gz
# shellcheck source=scripts/acceptance-lib.sh
. "$(dirname "$0")/acceptance-lib.sh"

start_host
install_previous
services previous

step "Preparing archives that garrison upgrade must refuse"
cases=$(mktemp -d "${TMPDIR:-/var/tmp}/garrison-upgrade.XXXXXX")
trap 'cleanup; rm -rf "$cases"' EXIT
# `name` is the container (acceptance-lib.sh); `file` the archive under test.
file=garrison-$newer-$arch.tar.gz
mkdir "$cases/changed" "$cases/comment" "$cases/foreign" "$cases/unsigned" "$cases/arch" "$cases/older"
# One byte changed after signing.
cp "$release" "$release.minisig" "$cases/changed/"
printf 'x' | dd of="$cases/changed/$file" bs=1 seek=100 conv=notrunc 2>/dev/null
# A valid signature of these bytes whose comment names the older release.
cp "$release" "$cases/comment/"
minisign -S -s "$out/test.key" -m "$cases/comment/$file" -t "garrison $older $arch" >/dev/null
# Signed by a key the installed release does not trust.
minisign -G -W -f -p "$cases/foreign.pub" -s "$cases/foreign.key" >/dev/null
cp "$release" "$cases/foreign/"
minisign -S -s "$cases/foreign.key" -m "$cases/foreign/$file" -t "garrison $newer $arch" >/dev/null
cp "$release" "$cases/unsigned/"
other=$(if [ "$arch" = x86_64 ]; then echo aarch64; else echo x86_64; fi)
cp "$release" "$cases/arch/garrison-$newer-$other.tar.gz"
cp "$release.minisig" "$cases/arch/garrison-$newer-$other.tar.gz.minisig"
cp "$previous" "$previous.minisig" "$cases/older/"
copy_in "$cases" /root/cases
copy_in "$release" "/root/$file"
copy_in "$release.minisig" "/root/$file.minisig"

current() { inside 'basename "$(readlink -f /opt/garrison/current)"'; }
# `garrison upgrade` must fail with `expected` in its output, keep the running
# release and leave no unpacked tree behind.
refused() {
    before=$(current)
    if inside "$2" > "$cases/output" 2>&1; then
        echo "FAIL  $1: it succeeded"
        cat "$cases/output"
        exit 1
    fi
    if ! grep -q -- "$3" "$cases/output"; then
        echo "FAIL  $1: expected \"$3\""
        cat "$cases/output"
        exit 1
    fi
    if [ "$(current)" != "$before" ] || inside 'ls /opt/garrison | grep -q "^upgrade\."'; then
        echo "FAIL  $1: something changed"
        exit 1
    fi
    echo "ok    $1"
}

step "Refusals change nothing"
upgrade=/opt/garrison/current/bin/garrison
refused "an archive changed after signing is refused" \
    "$upgrade upgrade /root/cases/changed/$file" "does not match its signature"
refused "a signature whose comment names another release is refused" \
    "$upgrade upgrade /root/cases/comment/$file" "The signature is for \"garrison $older $arch\""
refused "a key the release does not trust is refused" \
    "$upgrade upgrade /root/cases/foreign/$file" "no key this release trusts"
refused "an archive without a signature is refused" \
    "$upgrade upgrade /root/cases/unsigned/$file" "$file.minisig"
refused "an archive for another architecture is refused" \
    "$upgrade upgrade /root/cases/arch/garrison-$newer-$other.tar.gz" "is built for $other"
refused "the running version is not installed again" \
    "$upgrade upgrade /root/cases/older/garrison-$older-$arch.tar.gz" "is not newer than the running $older"
refused "only root upgrades" \
    "setpriv --reuid=65534 --regid=65534 --clear-groups $upgrade upgrade /root/$file" "Run as root."
refused "only an installed release upgrades" \
    "/root/release/bin/garrison upgrade /root/$file" "Run the installed release"

step "Upgrading with a valid signature"
installer "$upgrade upgrade /root/$file"
check "current points at the signed release" "test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$newer'"
check "the unpacked tree is gone" '! ls /opt/garrison | grep -q "^upgrade\."'
services upgraded
refused "the same release is not installed twice" \
    "/opt/garrison/current/bin/garrison upgrade /root/$file" "is not newer than the running $newer"

step "Accepted: garrison upgrade installs only what a trusted key signed for it"
