#!/usr/bin/env bash
# test-e2e.sh — run the privileged loop-device integration tests.
# Wraps the sudo + PATH + env-var dance so you don't have to remember it.

set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

# sbin paths must be visible for our `command -v` pre-flight (sgdisk,
# losetup, mkfs.fat live in /usr/sbin or /sbin on Debian).
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
if [[ -d "${HOME:-}/.cargo/bin" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi

red() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

# Pre-flight: every external tool the test will need.
missing=()
command -v veracrypt >/dev/null 2>&1 || missing+=("veracrypt")
command -v sgdisk    >/dev/null 2>&1 || missing+=("sgdisk")
command -v losetup   >/dev/null 2>&1 || missing+=("losetup")
command -v mount     >/dev/null 2>&1 || missing+=("mount")
command -v mkfs.fat  >/dev/null 2>&1 || command -v /usr/sbin/mkfs.fat >/dev/null 2>&1 || missing+=("mkfs.fat")
if [[ ${#missing[@]} -gt 0 ]]; then
    red "missing tools: ${missing[*]}"
    red 'run ./setup.sh first'
    exit 1
fi

# Locate cargo even if the user's login shell isn't /bin/bash.
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    CARGO="$HOME/.cargo/bin/cargo"
elif command -v cargo >/dev/null 2>&1; then
    CARGO=$(command -v cargo)
else
    red 'cargo not found. Install rust via https://rustup.rs/ and re-run.'
    exit 1
fi

# Build the workspace first so the unwrap binary exists when the cross-tool
# test looks for it.
"$CARGO" build --workspace

# sudo strips PATH; pass an explicit one that includes the user's cargo bin
# AND the standard sbin paths where sgdisk/mkfs.fat live on Debian.
exec sudo -E env \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$HOME/.cargo/bin" \
    DENC_ALLOW_LOOP=1 \
    "$CARGO" test --test losetup_e2e -- --ignored --nocapture --test-threads=1 "$@"
