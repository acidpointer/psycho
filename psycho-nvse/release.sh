#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="$WORKSPACE_DIR/.release"
TARGET="i686-pc-windows-gnu"
DLL_NAME="psycho_nvse.dll"
ARCHIVE_DLL="psycho-nvse.zip"
ARCHIVE_CFG="psycho-nvse-config.zip"

echo "Building release ($TARGET)..."
cargo build --release --target "$TARGET" --manifest-path "$SCRIPT_DIR/Cargo.toml"

DLL_PATH="$WORKSPACE_DIR/target/$TARGET/release/$DLL_NAME"
if [ ! -f "$DLL_PATH" ]; then
    echo "ERROR: $DLL_PATH not found"
    exit 1
fi

CONFIG_PATH="$SCRIPT_DIR/config/psycho-nvse.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "ERROR: $CONFIG_PATH not found"
    exit 1
fi

mkdir -p "$RELEASE_DIR"

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

# -- DLL archive --
mkdir -p "$STAGING/dll/NVSE/plugins"
cp "$DLL_PATH" "$STAGING/dll/NVSE/plugins/$DLL_NAME"

rm -f "$RELEASE_DIR/$ARCHIVE_DLL"
(cd "$STAGING/dll" && zip -r "$RELEASE_DIR/$ARCHIVE_DLL" NVSE/)

# -- Config archive --
mkdir -p "$STAGING/cfg/NVSE/plugins"
cp "$CONFIG_PATH" "$STAGING/cfg/NVSE/plugins/psycho-nvse.toml"

rm -f "$RELEASE_DIR/$ARCHIVE_CFG"
(cd "$STAGING/cfg" && zip -r "$RELEASE_DIR/$ARCHIVE_CFG" NVSE/)

SIZE_DLL=$(du -h "$RELEASE_DIR/$ARCHIVE_DLL" | cut -f1)
SIZE_CFG=$(du -h "$RELEASE_DIR/$ARCHIVE_CFG" | cut -f1)
echo "Done:"
echo "  $RELEASE_DIR/$ARCHIVE_DLL ($SIZE_DLL)"
echo "  $RELEASE_DIR/$ARCHIVE_CFG ($SIZE_CFG)"
