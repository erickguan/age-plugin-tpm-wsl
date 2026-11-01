#!/bin/sh
# Extract Ubuntu cross-compiler packages into ignored local build storage.
# Requires apt package metadata; does not change system packages.
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
toolchain_root="$project_root/target/windows-toolchain"
mkdir --parents "$toolchain_root/packages"
cd "$toolchain_root/packages"
apt-get download gcc-mingw-w64-x86-64-posix gcc-mingw-w64-x86-64-posix-runtime gcc-mingw-w64-base binutils-mingw-w64-x86-64 mingw-w64-x86-64-dev mingw-w64-common
for package in ./*.deb; do
    dpkg-deb --extract "$package" "$toolchain_root"
done
rustup target add x86_64-pc-windows-gnu
"$toolchain_root/usr/bin/x86_64-w64-mingw32-gcc-posix" --version
