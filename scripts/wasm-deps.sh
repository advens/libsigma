#!/bin/sh
# Fetch, verify, and build the wasm32-wasip1 toolchain and dependencies.
# Usage: wasm-deps.sh <dest>
#
# <dest>/wasi-sdk          wasi-sdk (clang, wasm-ld, sysroot)
# <dest>/wasmtime/wasmtime test runner (absent on hosts without a pin)
# <dest>/include, lib      PCRE2 (8-bit, no JIT) and libfastjson, static
# <dest>/share/licenses    notices for the code linked into wasm32 output
# <dest>/.pins             written last; make rebuilds when the pins change
#
# Every download is checked against the sha256 below before it is
# extracted. A mismatch stops the build. WASM_DL overrides the download
# cache (default <dest>/dl).
set -eu

WASI_SDK_VER=34
WASI_SDK_REL=34.0
WASMTIME_VER=49.0.5
PCRE2_VER=10.49
PCRE2_SHA256=929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae
LIBFASTJSON_VER=1.2304.0
LIBFASTJSON_SHA256=ef30d1e57a18ec770f90056aaac77300270c6203bbe476f4181cc83a2d5dc80c
# The wasi-libc commit wasi-sdk 34 builds its sysroot from. The release
# tarball carries no license files; these are the ones that apply to the
# libc code linked into every module.
WASI_LIBC_COMMIT=2e6fb9d8ee0cdf9e431fbcabe8af3115de000a13
WASI_LIBC_NOTICES="LICENSE:2711a8b5a5cdfef0e639f96c1aca12ae23d7d64a02d0507f1bdf14d2b27bbc3a
LICENSE-MIT:23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3
libc-top-half/musl/COPYRIGHT:b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b
libc-bottom-half/cloudlibc/LICENSE:c8b789cf5a746611e6300a0cc7750dbf92b61912a709d04e639245f7290656d0"

usage() {
    echo "usage: $0 <dest>" >&2
    exit 2
}

die() {
    echo "wasm-deps: $*" >&2
    exit 1
}

[ "$#" -eq 1 ] || usage
mkdir -p "$1"
DEST=$(cd "$1" && pwd)
DL=${WASM_DL:-$DEST/dl}
JOBS=${JOBS:-4}
MAKE=${MAKE:-make}
mkdir -p "$DL"

case "$(uname -s)-$(uname -m)" in
Darwin-arm64)
    sdk_host=arm64-macos
    sdk_sha=9c59398106b417f8f14913380fdf0097a8cc0ff4af9eb3ce0065a859e88d49e9
    wt_host=aarch64-macos
    wt_sha=38c8a1b43a04a67f2d953498e470117aaf46ba155e1a7e3158aa7f87259bd750
    ;;
Darwin-x86_64)
    sdk_host=x86_64-macos
    sdk_sha=87d27fa8adc68dee59bfbf2e22a6d34ef717c34d6bf1d8af2a56fc929d9ce0eb
    wt_host=
    wt_sha=
    ;;
Linux-x86_64)
    sdk_host=x86_64-linux
    sdk_sha=b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4
    wt_host=x86_64-linux
    wt_sha=101b181779afec556ac2cc6639a7ee3661de20c17f7948e0b290f63e9da9bdce
    ;;
Linux-aarch64 | Linux-arm64)
    sdk_host=arm64-linux
    sdk_sha=f7e243dff54d60bcc576e94d6166b69f410f2500ae4a9ceef34315be10e77971
    wt_host=aarch64-linux
    wt_sha=55fa95b10e07167cc681593c06928199ac19306e2226e23652c62ac9e278c201
    ;;
*)
    die "no wasi-sdk pin for $(uname -s)-$(uname -m)"
    ;;
esac

PINS="wasi-sdk=$WASI_SDK_REL/$sdk_sha wasmtime=$WASMTIME_VER/${wt_sha:-none}"
PINS="$PINS pcre2=$PCRE2_VER/$PCRE2_SHA256 libfastjson=$LIBFASTJSON_VER/$LIBFASTJSON_SHA256"
PINS="$PINS wasi-libc=$WASI_LIBC_COMMIT"
if [ -f "$DEST/.pins" ] && [ "$(cat "$DEST/.pins")" = "$PINS" ]; then
    exit 0
fi

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# fetch <url> <sha256> <file>: reuse a cached file whose hash matches,
# otherwise download to .part, verify, then rename.
fetch() {
    out=$DL/$3
    if [ -f "$out" ] && [ "$(sha256_of "$out")" = "$2" ]; then
        return 0
    fi
    rm -f "$out" "$out.part"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$out.part" "$1" || die "download failed: $1"
    got=$(sha256_of "$out.part")
    if [ "$got" != "$2" ]; then
        rm -f "$out.part"
        die "sha256 mismatch for $3: expected $2, got $got"
    fi
    mv "$out.part" "$out"
}

WORK=$(mktemp -d "$DEST/.work.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
rm -f "$DEST/.pins"

# wasi-sdk
sdk_tgz=wasi-sdk-$WASI_SDK_REL-$sdk_host.tar.gz
fetch "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-$WASI_SDK_VER/$sdk_tgz" \
    "$sdk_sha" "$sdk_tgz"
mkdir "$WORK/sdk"
tar -xzf "$DL/$sdk_tgz" -C "$WORK/sdk"
rm -rf "${DEST:?}/wasi-sdk"
mv "$WORK/sdk/wasi-sdk-$WASI_SDK_REL-$sdk_host" "$DEST/wasi-sdk"
SDK=$DEST/wasi-sdk

# wasmtime
rm -rf "${DEST:?}/wasmtime"
if [ -n "$wt_host" ]; then
    wt_txz=wasmtime-v$WASMTIME_VER-$wt_host.tar.xz
    fetch "https://github.com/bytecodealliance/wasmtime/releases/download/v$WASMTIME_VER/$wt_txz" \
        "$wt_sha" "$wt_txz"
    mkdir "$WORK/wt"
    tar -xJf "$DL/$wt_txz" -C "$WORK/wt"
    mkdir -p "$DEST/wasmtime"
    mv "$WORK/wt/wasmtime-v$WASMTIME_VER-$wt_host/wasmtime" "$DEST/wasmtime/wasmtime"
else
    echo "wasm-deps: no wasmtime pin for this host; pass WASMTIME= to make wasm-test" >&2
fi

# clang runs any wasm-opt found in PATH when it links. Configure and
# CMake link test programs, so turn it off for them as well.
WCC="$SDK/bin/clang --target=wasm32-wasip1 --sysroot=$SDK/share/wasi-sysroot"
rm -rf "${DEST:?}/include" "${DEST:?}/lib" "${DEST:?}/share/licenses"
LIC=$DEST/share/licenses
mkdir -p "$LIC/pcre2" "$LIC/libfastjson" "$LIC/wasi-libc"

# PCRE2: 8-bit only. JIT does not exist on wasm32; the interpreter runs.
pcre2_tgz=pcre2-$PCRE2_VER.tar.gz
fetch "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$PCRE2_VER/$pcre2_tgz" \
    "$PCRE2_SHA256" "$pcre2_tgz"
tar -xzf "$DL/$pcre2_tgz" -C "$WORK"
cmake -S "$WORK/pcre2-$PCRE2_VER" -B "$WORK/pcre2-build" \
    -DCMAKE_TOOLCHAIN_FILE="$SDK/share/cmake/wasi-sdk-p1.cmake" \
    -DWASI_SDK_PREFIX="$SDK" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXE_LINKER_FLAGS=--no-wasm-opt \
    -DCMAKE_INSTALL_PREFIX="$DEST" \
    -DBUILD_SHARED_LIBS=OFF \
    -DPCRE2_BUILD_PCRE2_8=ON -DPCRE2_BUILD_PCRE2_16=OFF -DPCRE2_BUILD_PCRE2_32=OFF \
    -DPCRE2_SUPPORT_JIT=OFF -DPCRE2_SUPPORT_UNICODE=ON \
    -DPCRE2_BUILD_PCRE2GREP=OFF -DPCRE2_BUILD_TESTS=OFF \
    >"$WORK/pcre2-configure.log" 2>&1 \
    || { tail -30 "$WORK/pcre2-configure.log" >&2; die "pcre2 configure failed"; }
cmake --build "$WORK/pcre2-build" -j "$JOBS" >"$WORK/pcre2-build.log" 2>&1 \
    || { tail -30 "$WORK/pcre2-build.log" >&2; die "pcre2 build failed"; }
cmake --install "$WORK/pcre2-build" >/dev/null
cp "$WORK/pcre2-$PCRE2_VER/LICENCE.md" "$LIC/pcre2/LICENCE.md"

# libfastjson. Its config.sub predates wasip1; the compiler carries the
# real target, the host triple only selects cross-compilation.
lfj_tgz=libfastjson-$LIBFASTJSON_VER.tar.gz
fetch "https://download.rsyslog.com/libfastjson/$lfj_tgz" "$LIBFASTJSON_SHA256" "$lfj_tgz"
tar -xzf "$DL/$lfj_tgz" -C "$WORK"
(
    cd "$WORK/libfastjson-$LIBFASTJSON_VER"
    CC=$WCC AR=$SDK/bin/llvm-ar RANLIB=$SDK/bin/llvm-ranlib \
        CFLAGS=-O2 LDFLAGS=--no-wasm-opt \
        ./configure --host=wasm32-unknown-none --disable-shared --enable-static \
        --prefix="$DEST" >"$WORK/lfj-configure.log" 2>&1 \
        || { tail -30 "$WORK/lfj-configure.log" >&2; exit 1; }
    "$MAKE" -j"$JOBS" >"$WORK/lfj-build.log" 2>&1 \
        || { tail -30 "$WORK/lfj-build.log" >&2; exit 1; }
    "$MAKE" install >/dev/null 2>&1
) || die "libfastjson build failed"
cp "$WORK/libfastjson-$LIBFASTJSON_VER/COPYING" "$LIC/libfastjson/COPYING"

# wasi-libc notices, one pinned file each.
printf '%s\n' "$WASI_LIBC_NOTICES" | while IFS=: read -r path sha; do
    name=$(printf '%s' "$path" | tr / -)
    fetch "https://raw.githubusercontent.com/WebAssembly/wasi-libc/$WASI_LIBC_COMMIT/$path" \
        "$sha" "wasi-libc-$name"
    cp "$DL/wasi-libc-$name" "$LIC/wasi-libc/$name"
done

for f in lib/libpcre2-8.a lib/libfastjson.a include/pcre2.h include/libfastjson/json.h \
    share/licenses/pcre2/LICENCE.md share/licenses/libfastjson/COPYING \
    share/licenses/wasi-libc/LICENSE-MIT; do
    [ -f "$DEST/$f" ] || die "missing after build: $f"
done

printf '%s\n' "$PINS" >"$DEST/.pins"
echo "wasm-deps: ready in $DEST"
