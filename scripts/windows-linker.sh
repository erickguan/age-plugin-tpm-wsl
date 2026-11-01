#!/bin/sh
# Keep cross-compiler environment out of Cargo's Linux build-script links.
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
toolchain_root="$project_root/target/windows-toolchain"
export PATH="$toolchain_root/usr/bin:$PATH"
export GCC_EXEC_PREFIX="$toolchain_root/usr/lib/gcc/"
exec "$toolchain_root/usr/bin/x86_64-w64-mingw32-gcc-posix" \
    -B "$toolchain_root/usr/x86_64-w64-mingw32/lib/" \
    -L "$toolchain_root/usr/x86_64-w64-mingw32/lib" "$@"
