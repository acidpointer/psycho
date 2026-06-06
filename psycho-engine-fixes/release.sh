#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="$WORKSPACE_DIR/.release"
TARGET="i686-pc-windows-gnu"
LOADER_DLL="dinput8.dll"
CORE_DLL="psycho_engine_fixes.dll"
HELPER_DLL="psycho_engine_fixes_helper.dll"
GRAPHICS_DLL="psycho_graphics.dll"
ARCHIVE_DLL="psycho-engine-fixes.zip"
ARCHIVE_CFG="psycho-engine-fixes-config.zip"

echo "Building release ($TARGET)..."
cargo build --release --target "$TARGET" -p psycho-loader -p psycho-engine-fixes -p psycho-engine-fixes-helper -p psycho-graphics

LOADER_PATH="$WORKSPACE_DIR/target/$TARGET/release/$LOADER_DLL"
CORE_PATH="$WORKSPACE_DIR/target/$TARGET/release/$CORE_DLL"
HELPER_PATH="$WORKSPACE_DIR/target/$TARGET/release/$HELPER_DLL"
GRAPHICS_PATH="$WORKSPACE_DIR/target/$TARGET/release/$GRAPHICS_DLL"
GRAPHICS_SHADER_SRC_DIR="$WORKSPACE_DIR/psycho-graphics/shaders"
for path in "$LOADER_PATH" "$CORE_PATH" "$HELPER_PATH" "$GRAPHICS_PATH"; do
    if [ ! -f "$path" ]; then
        echo "ERROR: $path not found"
        exit 1
    fi
done

CONFIG_PATH="$SCRIPT_DIR/config/psycho_engine_fixes.toml"
GRAPHICS_CONFIG_PATH="$WORKSPACE_DIR/psycho-graphics/config/psycho_graphics.toml"
for path in "$CONFIG_PATH" "$GRAPHICS_CONFIG_PATH"; do
    if [ ! -f "$path" ]; then
        echo "ERROR: $path not found"
        exit 1
    fi
done
if [ ! -d "$GRAPHICS_SHADER_SRC_DIR" ]; then
    echo "ERROR: $GRAPHICS_SHADER_SRC_DIR not found"
    exit 1
fi

mkdir -p "$RELEASE_DIR"

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

# -- DLL archive --
mkdir -p "$STAGING/dll/mods/psycho_shaders" "$STAGING/dll/Data/NVSE/plugins"
cp "$LOADER_PATH" "$STAGING/dll/$LOADER_DLL"
cp "$CORE_PATH" "$STAGING/dll/mods/$CORE_DLL"
cp "$CONFIG_PATH" "$STAGING/dll/mods/psycho_engine_fixes.toml"
cp "$GRAPHICS_PATH" "$STAGING/dll/mods/$GRAPHICS_DLL"
cp "$GRAPHICS_CONFIG_PATH" "$STAGING/dll/mods/psycho_graphics.toml"
cp "$HELPER_PATH" "$STAGING/dll/Data/NVSE/plugins/$HELPER_DLL"
find "$GRAPHICS_SHADER_SRC_DIR" \
    -maxdepth 1 \
    -type f \
    \( -iname '*.hlsl' -o -iname '*.pso' -o -iname '*.cso' -o -iname '*.toml' \) \
    -exec cp '{}' "$STAGING/dll/mods/psycho_shaders/" \;

rm -f "$RELEASE_DIR/$ARCHIVE_DLL"
(cd "$STAGING/dll" && zip -r "$RELEASE_DIR/$ARCHIVE_DLL" "$LOADER_DLL" mods/ Data/)

# -- Config archive --
mkdir -p "$STAGING/cfg/mods/psycho_shaders"
cp "$CONFIG_PATH" "$STAGING/cfg/mods/psycho_engine_fixes.toml"
cp "$GRAPHICS_CONFIG_PATH" "$STAGING/cfg/mods/psycho_graphics.toml"
find "$GRAPHICS_SHADER_SRC_DIR" \
    -maxdepth 1 \
    -type f \
    \( -iname '*.hlsl' -o -iname '*.pso' -o -iname '*.cso' -o -iname '*.toml' \) \
    -exec cp '{}' "$STAGING/cfg/mods/psycho_shaders/" \;

rm -f "$RELEASE_DIR/$ARCHIVE_CFG"
(cd "$STAGING/cfg" && zip -r "$RELEASE_DIR/$ARCHIVE_CFG" mods/)

SIZE_DLL=$(du -h "$RELEASE_DIR/$ARCHIVE_DLL" | cut -f1)
SIZE_CFG=$(du -h "$RELEASE_DIR/$ARCHIVE_CFG" | cut -f1)
echo "Done:"
echo "  $RELEASE_DIR/$ARCHIVE_DLL ($SIZE_DLL)"
echo "  $RELEASE_DIR/$ARCHIVE_CFG ($SIZE_CFG)"
