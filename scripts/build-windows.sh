#!/bin/sh
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PATH="$project_root/target/windows-toolchain/usr/bin:$PATH"
chmod u+x "$project_root/scripts/windows-linker.sh"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$project_root/scripts/windows-linker.sh"
# Compile AWS-LC's target C sources with the same isolated MinGW wrapper.
export CC_x86_64_pc_windows_gnu="$project_root/scripts/windows-linker.sh"
export AR_x86_64_pc_windows_gnu="$project_root/target/windows-toolchain/usr/bin/x86_64-w64-mingw32-ar"
# cc-rs must not reuse a global Rust cache wrapper for this C compiler script.
export RUSTC_WRAPPER=
cd "$project_root"
cargo build --locked --package age-tpm-wsl-helper --target x86_64-pc-windows-gnu "$@"
cargo clippy --locked --package age-tpm-wsl-helper --target x86_64-pc-windows-gnu "$@" -- --deny warnings
