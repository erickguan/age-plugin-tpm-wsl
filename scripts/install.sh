#!/bin/sh
# Install release binaries for the current WSL user; create no TPM keys.
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
plugin_dir="$HOME/.local/lib/age-plugin-tpm-wsl"
config_dir="$HOME/.config/age-plugin-tpm-wsl"
command_dir="$HOME/.local/bin"
windows_local=$(powershell.exe -NoProfile -NonInteractive -Command '[Console]::Write($env:LOCALAPPDATA)' | tr --delete '\r')
helper_dir="$(wslpath -u "$windows_local")/age-plugin-tpm-wsl"
helper_path="$helper_dir/age-tpm-wsl-helper.exe"
cd "$project_root"
cargo build --locked --release --bin age-plugin-tpm-wsl
sh scripts/build-windows.sh --release
install --directory --mode=700 "$plugin_dir" "$config_dir" "$command_dir"
mkdir --parents "$helper_dir"
# The installation directory is also the first component of the PQ custody root.
# Prepare its owner-only/SYSTEM DACL before the helper acquires storage beneath it.
acl_script=$(wslpath -w "$project_root/scripts/set-windows-installation-acl.ps1")
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$acl_script"
install --mode=700 target/release/age-plugin-tpm-wsl "$plugin_dir/age-plugin-tpm-wsl"
install --mode=700 target/x86_64-pc-windows-gnu/release/age-tpm-wsl-helper.exe "$helper_path"
# Helper paths are plain data; the launcher reads them without evaluating shell code.
printf '%s\n' "$helper_path" > "$config_dir/helper-path"
chmod 600 "$config_dir/helper-path"
install --mode=700 scripts/installed-launcher.sh "$command_dir/age-plugin-tpm-wsl"
# Tagged recipients use age's fixed tagpq discovery name. Both names invoke
# the same launcher and compiled plugin; there is no separate plugin binary.
ln --symbolic --force age-plugin-tpm-wsl "$command_dir/age-plugin-tagpq"
printf 'Installed plugin: %s\nInstalled helper: %s\n' "$command_dir/age-plugin-tpm-wsl" "$helper_path"
