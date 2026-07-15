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
OMV_DLL="omv.dll"
CONFIG_FILE="psycho_engine_fixes.toml"
OMV_CONFIG_FILE="omv.toml"

LOADER_PATH="$WORKSPACE_DIR/target/$TARGET/release/$LOADER_DLL"
CORE_PATH="$WORKSPACE_DIR/target/$TARGET/release/$CORE_DLL"
HELPER_PATH="$WORKSPACE_DIR/target/$TARGET/release/$HELPER_DLL"
OMV_PATH="$WORKSPACE_DIR/target/$TARGET/release/$OMV_DLL"
CONFIG_PATH="$WORKSPACE_DIR/psycho-engine-fixes/config/$CONFIG_FILE"
OMV_CONFIG_PATH="$WORKSPACE_DIR/omv/config/$OMV_CONFIG_FILE"
OMV_SHADER_SOURCE_DIR="$WORKSPACE_DIR/omv/shaders/runtime"

CORE_ARCHIVE="psycho-engine-fixes-$VERSION.zip"
HELPER_ARCHIVE="psycho-engine-fixes-nvse-helper-$VERSION.zip"
OMV_ARCHIVE="omv-nvse-$VERSION.zip"

echo "Building GitHub release artifacts ($TARGET, $VERSION)..."
cargo build --release --target "$TARGET" -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv

for path in "$LOADER_PATH" "$CORE_PATH" "$HELPER_PATH" "$OMV_PATH" "$CONFIG_PATH" "$OMV_CONFIG_PATH"; do
    if [[ ! -f "$path" ]]; then
        echo "ERROR: missing release input: $path" >&2
        exit 1
    fi
done
if [[ ! -d "$OMV_SHADER_SOURCE_DIR" ]]; then
    echo "ERROR: missing release input directory: $OMV_SHADER_SOURCE_DIR" >&2
    exit 1
fi

bash "$SCRIPT_DIR/verify_syringe_pe.sh" "$LOADER_PATH"

mkdir -p "$RELEASE_DIR"
rm -f \
    "$RELEASE_DIR/$CORE_ARCHIVE" \
    "$RELEASE_DIR/$HELPER_ARCHIVE" \
    "$RELEASE_DIR/$OMV_ARCHIVE"

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

pack_dir() {
    local source_dir="$1"
    local archive_name="$2"

    (cd "$source_dir" && zip -qr "$RELEASE_DIR/$archive_name" .)
}

# Core game-root layout: early loader, engine-fixes DLL, and configuration.
mkdir -p "$STAGING/core/syringe"
cp "$LOADER_PATH" "$STAGING/core/$LOADER_DLL"
cp "$CORE_PATH" "$STAGING/core/syringe/$CORE_DLL"
cp "$CONFIG_PATH" "$STAGING/core/syringe/$CONFIG_FILE"
pack_dir "$STAGING/core" "$CORE_ARCHIVE"

# Optional xNVSE helper, packaged as a conventional Data-directory mod.
mkdir -p "$STAGING/helper/Data/NVSE/plugins"
cp "$HELPER_PATH" "$STAGING/helper/Data/NVSE/plugins/$HELPER_DLL"
pack_dir "$STAGING/helper" "$HELPER_ARCHIVE"

# OMV xNVSE plugin, configuration, and loose runtime shaders.
mkdir -p "$STAGING/omv/Data/NVSE/plugins/omv/shaders"
cp "$OMV_PATH" "$STAGING/omv/Data/NVSE/plugins/$OMV_DLL"
cp "$OMV_CONFIG_PATH" "$STAGING/omv/Data/NVSE/plugins/omv/$OMV_CONFIG_FILE"
find "$OMV_SHADER_SOURCE_DIR" \
    -maxdepth 1 \
    -type f \
    \( -iname '*.hlsl' -o -iname '*.pso' -o -iname '*.cso' -o -iname '*.toml' \) \
    -exec cp '{}' "$STAGING/omv/Data/NVSE/plugins/omv/shaders/" \;
pack_dir "$STAGING/omv" "$OMV_ARCHIVE"

echo "Release archives:"
for archive in "$CORE_ARCHIVE" "$HELPER_ARCHIVE" "$OMV_ARCHIVE"; do
    size="$(du -h "$RELEASE_DIR/$archive" | cut -f1)"
    echo "  $RELEASE_DIR/$archive ($size)"
done
