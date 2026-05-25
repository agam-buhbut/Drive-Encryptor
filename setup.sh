#!/usr/bin/env bash
# setup.sh — one-shot bootstrap for DriveEncryptor v0.1 on Debian/Ubuntu.
# Installs every prerequisite, builds the workspace, runs unit tests.
# Idempotent: safe to re-run.

set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

# Ensure sbin paths (where sgdisk, losetup, mkfs.fat live on Debian) are on
# PATH for our `command -v` checks. Also pick up cargo from the invoking
# user's home, even if we were sudo'd.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
if [[ -d "${HOME:-}/.cargo/bin" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi
if [[ -n "${SUDO_USER:-}" ]] && command -v getent >/dev/null 2>&1; then
    invoking_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [[ -d "${invoking_home:-/nonexistent}/.cargo/bin" ]]; then
        export PATH="$invoking_home/.cargo/bin:$PATH"
    fi
fi

green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
note()  { printf '  %s\n' "$*"; }

require_sudo() {
    if ! command -v sudo >/dev/null 2>&1; then
        red "sudo is required but not installed."
        exit 1
    fi
}

green '== DriveEncryptor v0.1 setup =='

# ---------- 1. cargo ----------
if ! command -v cargo >/dev/null 2>&1; then
    if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        red 'cargo not found. Install rust via https://rustup.rs/ and re-run.'
        exit 1
    fi
fi
note "cargo:    $(command -v cargo)  ($(cargo --version))"

# ---------- 2. sgdisk (gdisk package) ----------
if ! command -v sgdisk >/dev/null 2>&1; then
    require_sudo
    green '>> Installing gdisk (provides sgdisk)...'
    sudo apt-get install -y gdisk
fi
note "sgdisk:   $(command -v sgdisk)"

# ---------- 2b. Tauri build dependencies (for the v0.3 GUI) ----------
# Anything that's already installed is a no-op for apt.
TAURI_DEPS=(
    pkg-config
    libwebkit2gtk-4.1-dev
    libayatana-appindicator3-dev
    librsvg2-dev
    libsoup-3.0-dev
    zenity         # native passphrase dialog used by the GUI
)
need_tauri=0
for dep in "${TAURI_DEPS[@]}"; do
    if ! dpkg -s "$dep" >/dev/null 2>&1; then
        need_tauri=1
        break
    fi
done
if [[ "$need_tauri" -eq 1 ]]; then
    require_sudo
    green '>> Installing Tauri build dependencies...'
    sudo apt-get install -y "${TAURI_DEPS[@]}"
fi
note "tauri deps: ${TAURI_DEPS[*]}"

# ---------- 3. veracrypt ----------
install_veracrypt_via_apt() {
    if ! apt-cache show veracrypt >/dev/null 2>&1; then return 1; fi
    require_sudo
    sudo apt-get install -y veracrypt
}

enable_contrib_repo() {
    require_sudo
    if grep -qE '^deb .* contrib' /etc/apt/sources.list 2>/dev/null \
       || grep -hqE '^deb .* contrib' /etc/apt/sources.list.d/*.list 2>/dev/null; then
        return 0  # already enabled
    fi
    note 'Enabling contrib repo (one-time, edits /etc/apt/sources.list)...'
    sudo cp /etc/apt/sources.list "/etc/apt/sources.list.bak.$(date +%s)"
    sudo sed -i -E 's/^(deb .*) (main)([[:space:]]|$)/\1 \2 contrib\3/' /etc/apt/sources.list
    sudo apt-get update
}

download_veracrypt_deb() {
    require_sudo
    # Hardcoded latest stable release. If launchpad URLs ever change, the
    # script will exit cleanly and the user can install manually.
    local version='1.26.24'
    local debian_codename
    debian_codename=$(. /etc/os-release && echo "${VERSION_ID:-12}")
    local arch
    arch=$(dpkg --print-architecture)
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" RETURN

    # Try Debian-<our version>, then fall back to Debian-12.
    for codename_try in "$debian_codename" "12"; do
        local url="https://launchpad.net/veracrypt/trunk/${version}/+download/veracrypt-console-${version}-Debian-${codename_try}-${arch}.deb"
        local deb="$tmpdir/veracrypt-console.deb"
        note "Trying $url"
        if curl --fail --silent --show-error --location -o "$deb" "$url"; then
            sudo apt-get install -y "$deb"
            return 0
        fi
    done
    return 1
}

if ! command -v veracrypt >/dev/null 2>&1; then
    green '>> Installing VeraCrypt...'
    if install_veracrypt_via_apt; then
        :
    elif enable_contrib_repo && install_veracrypt_via_apt; then
        :
    elif command -v curl >/dev/null 2>&1 && download_veracrypt_deb; then
        :
    else
        red 'Could not auto-install VeraCrypt. Install it manually:'
        red '  1. Download the "Console" .deb from https://veracrypt.fr/en/Downloads.html'
        red '  2. sudo apt-get install -y ./veracrypt-console-*.deb'
        red '  3. Re-run ./setup.sh'
        exit 1
    fi
fi
note "veracrypt: $(command -v veracrypt)  ($(veracrypt --version 2>&1 | head -1))"

# ---------- 4. build + unit tests ----------
green '>> Building workspace (CLI + core + GUI)...'
cargo build --workspace

green '>> Running unprivileged tests...'
cargo test --workspace

green '== Setup complete =='
echo
echo "Next steps:"
echo "  CLI smoke:           sudo target/debug/drive-encryptor list"
echo "  GUI dev mode:        cargo run -p drive-encryptor-gui"
echo "  Privileged e2e:      ./test-e2e.sh"
