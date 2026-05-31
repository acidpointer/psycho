#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version-tag>" >&2
    exit 2
fi

VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RELEASE_DIR="$WORKSPACE_DIR/.release"
TARGET="i686-pc-windows-gnu"

LOADER_DLL="dinput8.dll"
CORE_DLL="psycho_engine_fixes.dll"
HELPER_DLL="psycho_engine_fixes_helper.dll"
CONFIG_FILE="psycho_engine_fixes.toml"

LOADER_PATH="$WORKSPACE_DIR/target/$TARGET/release/$LOADER_DLL"
CORE_PATH="$WORKSPACE_DIR/target/$TARGET/release/$CORE_DLL"
HELPER_PATH="$WORKSPACE_DIR/target/$TARGET/release/$HELPER_DLL"
CONFIG_PATH="$WORKSPACE_DIR/psycho-engine-fixes/config/$CONFIG_FILE"

AIO_ARCHIVE="psycho-engine-fixes-$VERSION-aio.zip"
HELPER_ARCHIVE="psycho-engine-fixes-helper-$VERSION.zip"
LOADER_ARCHIVE="psycho-loader-$VERSION.zip"
CORE_ARCHIVE="psycho-engine-fixes-$VERSION.zip"
CONFIG_ARCHIVE="psycho-engine-fixes-config-$VERSION.zip"

echo "Building GitHub release artifacts ($TARGET, $VERSION)..."
cargo build --release --target "$TARGET" -p psycho-loader -p psycho-engine-fixes -p psycho-engine-fixes-helper

for path in "$LOADER_PATH" "$CORE_PATH" "$HELPER_PATH" "$CONFIG_PATH"; do
    if [[ ! -f "$path" ]]; then
        echo "ERROR: missing release input: $path" >&2
        exit 1
    fi
done

mkdir -p "$RELEASE_DIR"
rm -f \
    "$RELEASE_DIR/$AIO_ARCHIVE" \
    "$RELEASE_DIR/$HELPER_ARCHIVE" \
    "$RELEASE_DIR/$LOADER_ARCHIVE" \
    "$RELEASE_DIR/$CORE_ARCHIVE" \
    "$RELEASE_DIR/$CONFIG_ARCHIVE"

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

pack_dir() {
    local source_dir="$1"
    local archive_name="$2"

    (cd "$source_dir" && zip -qr "$RELEASE_DIR/$archive_name" .)
}

# All-in-one core install: early loader + core DLL + config.
# The xNVSE helper stays separate because it is optional.
mkdir -p "$STAGING/aio/mods"
cp "$LOADER_PATH" "$STAGING/aio/$LOADER_DLL"
cp "$CORE_PATH" "$STAGING/aio/mods/$CORE_DLL"
cp "$CONFIG_PATH" "$STAGING/aio/mods/$CONFIG_FILE"
pack_dir "$STAGING/aio" "$AIO_ARCHIVE"

# xNVSE helper only.
mkdir -p "$STAGING/helper/Data/NVSE/plugins"
cp "$HELPER_PATH" "$STAGING/helper/Data/NVSE/plugins/$HELPER_DLL"
pack_dir "$STAGING/helper" "$HELPER_ARCHIVE"

# Separate components for manual users and mod managers.
mkdir -p "$STAGING/loader"
cp "$LOADER_PATH" "$STAGING/loader/$LOADER_DLL"
pack_dir "$STAGING/loader" "$LOADER_ARCHIVE"

mkdir -p "$STAGING/core/mods"
cp "$CORE_PATH" "$STAGING/core/mods/$CORE_DLL"
pack_dir "$STAGING/core" "$CORE_ARCHIVE"

mkdir -p "$STAGING/config/mods"
cp "$CONFIG_PATH" "$STAGING/config/mods/$CONFIG_FILE"
pack_dir "$STAGING/config" "$CONFIG_ARCHIVE"

echo "Release artifacts:"
for archive in \
    "$AIO_ARCHIVE" \
    "$HELPER_ARCHIVE" \
    "$LOADER_ARCHIVE" \
    "$CORE_ARCHIVE" \
    "$CONFIG_ARCHIVE"; do
    size="$(du -h "$RELEASE_DIR/$archive" | cut -f1)"
    echo "  $RELEASE_DIR/$archive ($size)"
done

