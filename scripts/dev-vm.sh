#!/usr/bin/env bash
#
# Dev loop for the the lab Linux VM (linux-test-vm at <linux-test-ip>, reachable via
# the Proxmox host as a jump host). We build natively on the VM rather
# than cross-compiling from the Mac — see
# memory/feedback_avoid_crosscompile_thrash.md for why.
#
# Usage:
#     scripts/dev-vm.sh sync                  # rsync source to VM
#     scripts/dev-vm.sh build [BIN]           # sync + cargo build --release [--bin BIN]
#     scripts/dev-vm.sh run-daemon            # sync + build azvpnd + run it under sudo
#     scripts/dev-vm.sh ssh [ARGS...]         # ssh in (passes ARGS to ssh after the host)
#     scripts/dev-vm.sh exec CMD...           # run CMD on the VM (via debian user)
#
# SSH access: configured via `Host edr` in ~/.ssh/config (ProxyJump
# through Host lab-bastion). If those aliases aren't there yet, regenerate
# them — see the docs in memory/ for the layout.
#
# The VM (vmid 126 on the Proxmox host) is 1 vCPU / 4 GB RAM, plenty
# for `azvpnd`-only builds and tight for full-workspace.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VM_HOST="edr"
VM_DIR="/home/debian/azvpn"

usage() {
    sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

cmd="${1:-}"
[[ -z "$cmd" ]] && usage
shift || true

sync_source() {
    # macOS rsync is old enough that --info=stats1 isn't accepted; -a is
    # enough for our needs. Drop target/, dist/, nix result/, etc. —
    # those are massive and the VM has its own toolchain anyway.
    rsync -az \
        --exclude=target --exclude=dist --exclude=result --exclude=result-\* \
        --exclude=.direnv --exclude=.git \
        ./ "$VM_HOST:$VM_DIR/"
}

case "$cmd" in
    sync)
        sync_source
        echo "==> synced to $VM_HOST:$VM_DIR"
        ;;
    build)
        sync_source
        bin="${1:-}"
        bin_flag=""
        [[ -n "$bin" ]] && bin_flag="--bin $bin"
        ssh "$VM_HOST" "source ~/.cargo/env && cd $VM_DIR && cargo build --release $bin_flag 2>&1 | tail -20"
        ;;
    run-daemon)
        sync_source
        echo "==> building azvpnd"
        ssh "$VM_HOST" "source ~/.cargo/env && cd $VM_DIR && cargo build --release --bin azvpnd 2>&1 | tail -5"
        echo "==> running azvpnd under sudo (Ctrl-C to stop)"
        # `-t` forces a PTY so Ctrl-C from the local terminal propagates
        # all the way to the remote daemon process.
        ssh -t "$VM_HOST" "sudo $VM_DIR/target/release/azvpnd"
        ;;
    ssh)
        # Pass remaining args verbatim — supports `scripts/dev-vm.sh ssh
        # -L 7505:127.0.0.1:7505` for local mgmt-port tunneling, etc.
        exec ssh "$VM_HOST" "$@"
        ;;
    exec)
        [[ $# -eq 0 ]] && { echo "exec needs a command" >&2; exit 1; }
        ssh "$VM_HOST" "$@"
        ;;
    *)
        echo "unknown command: $cmd" >&2
        usage
        ;;
esac
