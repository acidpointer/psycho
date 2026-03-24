#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="$WORKSPACE_DIR/.release"
TARGET="i686-pc-windows-gnu"
DLL_NAME="psycho_nvse.dll"
ARCHIVE_NAME="psycho-nvse.zip"

echo "Building release ($TARGET)..."
cargo build --release --target "$TARGET" --manifest-path "$SCRIPT_DIR/Cargo.toml"

DLL_PATH="$WORKSPACE_DIR/target/$TARGET/release/$DLL_NAME"
if [ ! -f "$DLL_PATH" ]; then
    echo "ERROR: $DLL_PATH not found"
    exit 1
fi

mkdir -p "$RELEASE_DIR"

ARCHIVE_PATH="$RELEASE_DIR/$ARCHIVE_NAME"
if [ -f "$ARCHIVE_PATH" ]; then
    echo "Archive already exists, replacing: $ARCHIVE_PATH"
    rm "$ARCHIVE_PATH"
fi

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$STAGING/NVSE/plugins"
cp "$DLL_PATH" "$STAGING/NVSE/plugins/$DLL_NAME"

(cd "$STAGING" && zip -r "$ARCHIVE_PATH" NVSE/)

SIZE=$(du -h "$ARCHIVE_PATH" | cut -f1)
echo "Done: $ARCHIVE_PATH ($SIZE)"
