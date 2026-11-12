# shellcheck shell=sh
# A disposable virtual machine for the acceptance (HOST=vm): an official cloud
# image of the distribution, checked against the distribution's checksum list;
# a copy-on-write disk deleted afterwards; root over SSH with a key made for
# this run; networking through QEMU's user mode, which exposes nothing but one
# SSH port on 127.0.0.1. The guest gets 2 GiB in a systemd scope capped at 3 GiB.
#
# ARCH=aarch64 on an x86_64 host emulates an ARM machine: slow, but a real
# aarch64 kernel, so the units' sandboxing works (unlike qemu-user). It needs
# qemu-system-arm and qemu-efi-aarch64. Images are cached in VM_CACHE.
# shellcheck disable=SC2034

vm_cache=${VM_CACHE:-$HOME/.cache/garrison-vm}
vm_arch=${ARCH:-$(uname -m)}
vm_dir=

# The image of distribution $1 for $vm_arch, and the checksum list naming it.
vm_source() {
    case $vm_arch in
        x86_64) deb=amd64 ;;
        aarch64) deb=arm64 ;;
        *) echo "Unknown architecture $vm_arch" >&2; return 1 ;;
    esac
    case $1 in
        debian-12) vm_url=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-$deb.qcow2 ;;
        debian-13) vm_url=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-$deb.qcow2 ;;
        ubuntu-22.04) vm_url=https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-$deb.img ;;
        ubuntu-24.04) vm_url=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-$deb.img ;;
        ubuntu-26.04) vm_url=https://cloud-images.ubuntu.com/releases/resolute/release/ubuntu-26.04-server-cloudimg-$deb.img ;;
        almalinux-9 | almalinux-10)
            vm_url=https://repo.almalinux.org/almalinux/${1#almalinux-}/cloud/$vm_arch/images/AlmaLinux-${1#almalinux-}-GenericCloud-latest.$vm_arch.qcow2 ;;
        rocky-9 | rocky-10)
            vm_url=https://dl.rockylinux.org/pub/rocky/${1#rocky-}/images/$vm_arch/Rocky-${1#rocky-}-GenericCloud-Base.latest.$vm_arch.qcow2 ;;
        centos-stream-10)
            vm_url=https://cloud.centos.org/centos/10-stream/$vm_arch/images/CentOS-Stream-GenericCloud-10-latest.$vm_arch.qcow2 ;;
        # The image's name carries its release; the list beside it names it.
        amazonlinux-2023)
            case $vm_arch in
                aarch64) vm_url='https://cdn.amazonlinux.com/al2023/os-images/latest/kvm-arm64/al2023-kvm-*-arm64.xfs.gpt.qcow2' ;;
                *) vm_url='https://cdn.amazonlinux.com/al2023/os-images/latest/kvm/al2023-kvm-*-x86_64.xfs.gpt.qcow2' ;;
            esac ;;
        fedora-44) vm_url=https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/$vm_arch/images/Fedora-Cloud-Base-Generic-44-1.7.$vm_arch.qcow2 ;;
        opensuse-leap-16.0) vm_url=https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.$vm_arch-Cloud.qcow2 ;;
        *) echo "No virtual machine image for $1" >&2; return 1 ;;
    esac
    case $1 in
        debian-*) vm_sums=${vm_url%/*}/SHA512SUMS ;;
        ubuntu-*) vm_sums=${vm_url%/*}/SHA256SUMS ;;
        almalinux-* | centos-stream-*) vm_sums=${vm_url%/*}/CHECKSUM ;;
        amazonlinux-*) vm_sums=${vm_url%/*}/SHA256SUMS ;;
        rocky-*) vm_sums=$vm_url.CHECKSUM ;;
        fedora-44) vm_sums=${vm_url%/*}/Fedora-Cloud-44-1.7-$vm_arch-CHECKSUM ;;
        opensuse-*) vm_sums=$vm_url.sha256 ;;
    esac
}

# The digest list $1 names for file $2, in GNU (`hash  file`, `hash *file`)
# or BSD (`SHA256 (file) = hash`) form.
vm_digest() {
    awk -v file="$2" '
        $2 == file || $2 == "*" file { print $1; exit }
        $2 == "(" file ")" && $3 == "=" { print $4; exit }' "$1"
}

# The names in digest list $1, in either form.
vm_names() { awk '{ name = $2; gsub(/^[*(]|[)]$/, "", name); print name }' "$1"; }

# The cached image of $1, downloaded again when the list names another digest.
# A `*` in the image's name stands for its release, which the list names.
vm_fetch() {
    vm_source "$1" || return 1
    mkdir -p "$vm_cache/images"
    sums=$vm_cache/images/$1-$vm_arch.sums
    curl -fsSL --retry 3 -o "$sums" "$vm_sums" || { echo "Cannot fetch $vm_sums" >&2; return 1; }
    file=${vm_url##*/}
    case $file in
        *\**)
            pattern=$file
            # The pattern is a glob on purpose: its `*` is the release.
            # shellcheck disable=SC2254
            file=$(vm_names "$sums" | while read -r listed; do
                case $listed in $pattern) echo "$listed"; break ;; esac
            done)
            [ -n "$file" ] || { echo "$vm_sums names no image like $pattern" >&2; return 1; }
            vm_url=${vm_url%/*}/$file ;;
    esac
    vm_image=$vm_cache/images/$1-$vm_arch-$file
    mv "$sums" "$vm_image.sums"
    want=$(vm_digest "$vm_image.sums" "$file")
    case ${#want} in
        64) sum=sha256sum ;;
        128) sum=sha512sum ;;
        *) echo "$vm_sums names no digest for $file" >&2; return 1 ;;
    esac
    if [ ! -f "$vm_image" ] || [ "$($sum "$vm_image" | cut -d ' ' -f 1)" != "$want" ]; then
        echo "Downloading $file"
        curl -fsSL --retry 3 -o "$vm_image.part" "$vm_url" || { echo "Cannot fetch $vm_url" >&2; return 1; }
        if [ "$($sum "$vm_image.part" | cut -d ' ' -f 1)" != "$want" ]; then
            rm -f "$vm_image.part"
            echo "Checksum mismatch for $file" >&2
            return 1
        fi
        mv "$vm_image.part" "$vm_image"
    fi
}

# `sh -c` for the guest, with $1 quoted for the remote shell.
vm_quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

vm_ssh() {
    ssh -i "$vm_dir/key" -p "$vm_port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes -o ServerAliveInterval=15 \
        root@127.0.0.1 "$@"
}

vm_copy() {
    scp -q -r -i "$vm_dir/key" -P "$vm_port" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes "$1" "root@127.0.0.1:$2"
}

# Wait until the guest answers over SSH: minutes under KVM, much longer emulated.
vm_wait() {
    limit=$(if [ "$vm_arch" = "$(uname -m)" ]; then echo 300; else echo 2400; fi)
    waited=0
    until vm_ssh -n true 2>/dev/null; do
        if [ "$waited" -ge "$limit" ] || ! kill -0 "$(cat "$vm_dir/qemu.pid" 2>/dev/null)" 2>/dev/null; then
            echo "The virtual machine did not answer; console:" >&2
            tail -n 30 "$vm_dir/console.log" >&2
            return 1
        fi
        sleep 5
        waited=$((waited + 5))
    done
}

# Boot distribution $1 and wait until cloud-init has finished.
vm_boot() {
    vm_fetch "$1" || return 1
    vm_dir=$(mktemp -d "$vm_cache/run.XXXXXX")
    # The image's own format and size; the nested "format" entries name the
    # layers below. The disk gets 20 GiB but never less than the image, whose
    # last partition a smaller disk would cut off (Amazon Linux's image has 25).
    read -r format size <<SIZE
$(qemu-img info --output=json "$vm_image" | python3 -I -c 'import json, sys; info = json.load(sys.stdin); print(info["format"], info["virtual-size"])')
SIZE
    [ "$size" -ge 21474836480 ] || size=21474836480
    qemu-img create -q -f qcow2 -F "$format" -b "$vm_image" "$vm_dir/disk.qcow2" "$size"
    ssh-keygen -q -t ed25519 -N '' -C garrison-acceptance -f "$vm_dir/key"
    cat > "$vm_dir/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$vm_dir/key.pub")
EOF
    printf 'instance-id: garrison-%s\nlocal-hostname: acceptance\n' "$$" > "$vm_dir/meta-data"
    xorriso -as genisoimage -quiet -output "$vm_dir/seed.iso" -volid cidata -joliet -rock \
        "$vm_dir/user-data" "$vm_dir/meta-data" 2>/dev/null
    vm_port=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    case $vm_arch in
        x86_64) set -- qemu-system-x86_64 -machine q35,accel=kvm -cpu host ;;
        aarch64)
            cp /usr/share/AAVMF/AAVMF_VARS.fd "$vm_dir/vars.fd"
            # Emulated, `-cpu max` never got past the firmware's banner, not even
            # with pointer authentication, SVE and SME off; a Neoverse N1, the
            # core of Ampere Altra and Graviton2 servers, reaches the login
            # prompt in under 150 seconds.
            if [ "$(uname -m)" = aarch64 ]; then
                set -- qemu-system-aarch64 -machine virt,accel=kvm -cpu host
            else
                set -- qemu-system-aarch64 -machine virt,accel=tcg -cpu neoverse-n1
            fi
            set -- "$@" \
                -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.fd \
                -drive "if=pflash,format=raw,file=$vm_dir/vars.fd" ;;
    esac
    # The guest's memory plus QEMU's own, as a hard limit; nothing is swapped.
    # The firmware boots the disk only: from the cloud-init drive it would hang.
    systemd-run --user --scope --quiet -p MemoryMax=3G -p MemorySwapMax=0 "$@" \
        -smp 2 -m 2048 -display none -daemonize -pidfile "$vm_dir/qemu.pid" \
        -serial "file:$vm_dir/console.log" \
        -drive "file=$vm_dir/disk.qcow2,format=qcow2,if=none,id=disk" \
        -device virtio-blk-pci,drive=disk,bootindex=0 \
        -drive "file=$vm_dir/seed.iso,format=raw,if=none,id=seed,readonly=on" \
        -device virtio-blk-pci,drive=seed \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$vm_port-:22" -device virtio-net-pci,netdev=net0
    vm_wait || return 1
    vm_ssh -n 'cloud-init status --wait >/dev/null 2>&1 || true'
}

# Reboot the guest and wait until it answers again.
vm_reboot() {
    vm_ssh -n 'systemctl reboot' >/dev/null 2>&1 || true
    sleep 10
    vm_wait
}

vm_stop() {
    [ -n "$vm_dir" ] || return 0
    if [ -f "$vm_dir/qemu.pid" ]; then
        kill "$(cat "$vm_dir/qemu.pid")" 2>/dev/null || true
        sleep 2
    fi
    rm -rf "$vm_dir"
    vm_dir=
}
