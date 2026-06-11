#!/usr/bin/env bash
set -euo pipefail

####################
## EDIT THIS VAR  ##

TARGET_DIR="/data/storage0/Games/FalloutNV_TTW"


### DO NOT EDIT LINES BELOW ###

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(dirname "$SCRIPT")"

TARGET="i686-pc-windows-gnu"
BUILD_TYPE="${BUILD_TYPE:-release}"

LOADER_DLL="dinput8.dll"
CORE_DLL="psycho_engine_fixes.dll"
HELPER_DLL="psycho_engine_fixes_helper.dll"
GRAPHICS_DLL="psycho_graphics.dll"
ENGINE_CFGNAME="psycho_engine_fixes.toml"
GRAPHICS_CFGNAME="psycho_graphics.toml"

BIN_DIR="$DIR/target/$TARGET/$BUILD_TYPE"
LOADER_BIN="$BIN_DIR/$LOADER_DLL"
CORE_BIN="$BIN_DIR/$CORE_DLL"
HELPER_BIN="$BIN_DIR/$HELPER_DLL"
GRAPHICS_BIN="$BIN_DIR/$GRAPHICS_DLL"
ENGINE_CFG="$DIR/psycho-engine-fixes/config/$ENGINE_CFGNAME"
GRAPHICS_CFG="$DIR/psycho-graphics/config/$GRAPHICS_CFGNAME"
GRAPHICS_SHADER_SRC_DIR="$DIR/psycho-graphics/shaders"
EMBEDDED_SHADER_STALE_FILES=(
    "00_fast_ao.hlsl"
    "00_fast_ao.toml"
    "02_contact_ao.hlsl"
    "02_contact_ao.toml"
    "07_blooming_hdr_lite.hlsl"
    "07_blooming_hdr_lite.toml"
    "09_sunshafts_lite.hlsl"
    "09_sunshafts_lite.toml"
)

GAME_ROOT="$TARGET_DIR/FalloutNV"
GAME_MODS_DIR="$GAME_ROOT/mods"
SHADER_DIR="$GAME_MODS_DIR/psycho_shaders"

# Keep the xNVSE plugin path compatible with the old psycho-nvse installer.
NVSE_PLUGIN_DIR="$TARGET_DIR/mods/psycho_nvse/nvse/plugins"

LOADER_PATH="$GAME_ROOT/$LOADER_DLL"
CORE_PATH="$GAME_MODS_DIR/$CORE_DLL"
HELPER_PATH="$NVSE_PLUGIN_DIR/$HELPER_DLL"
GRAPHICS_PATH="$GAME_MODS_DIR/$GRAPHICS_DLL"
ENGINE_CFG_PATH="$GAME_MODS_DIR/$ENGINE_CFGNAME"
GRAPHICS_CFG_PATH="$GAME_MODS_DIR/$GRAPHICS_CFGNAME"

function build_rust() {
    cd "$DIR"

    local profile_args=()
    if [[ "$BUILD_TYPE" = "release" ]]; then
        profile_args+=(--release)
    fi

    cargo build \
        --target "$TARGET" \
        "${profile_args[@]}" \
        -p psycho-loader \
        -p psycho-engine-fixes \
        -p psycho-engine-fixes-helper \
        -p psycho-graphics

    if [[ "$BUILD_TYPE" = "release" ]]; then
        echo "!!!RELEASE MODE BUILD!!!"
    fi
}

function require_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "Missing build artifact: $path" >&2
        exit 1
    fi
}

function remove_if_exists() {
    local path="$1"
    if [[ -f "$path" ]]; then
        rm -f "$path"
        echo "Removed stale file: $path"
    fi
}

function install_files() {
    require_file "$LOADER_BIN"
    require_file "$CORE_BIN"
    require_file "$HELPER_BIN"
    require_file "$GRAPHICS_BIN"
    require_file "$ENGINE_CFG"
    require_file "$GRAPHICS_CFG"

    mkdir -p "$GAME_MODS_DIR"
    mkdir -p "$SHADER_DIR"
    mkdir -p "$NVSE_PLUGIN_DIR"

    cp "$LOADER_BIN" "$LOADER_PATH"
    cp "$CORE_BIN" "$CORE_PATH"
    cp "$HELPER_BIN" "$HELPER_PATH"
    cp "$GRAPHICS_BIN" "$GRAPHICS_PATH"
    cp "$ENGINE_CFG" "$ENGINE_CFG_PATH"
    cp "$GRAPHICS_CFG" "$GRAPHICS_CFG_PATH"

    for stale_shader in "${EMBEDDED_SHADER_STALE_FILES[@]}"; do
        remove_if_exists "$SHADER_DIR/$stale_shader"
    done

    if [[ -d "$GRAPHICS_SHADER_SRC_DIR" ]]; then
        find "$GRAPHICS_SHADER_SRC_DIR" \
            -maxdepth 1 \
            -type f \
            \( -iname '*.hlsl' -o -iname '*.pso' -o -iname '*.cso' -o -iname '*.toml' \) \
            -exec cp '{}' "$SHADER_DIR/" \;
    fi
}

function remove_legacy_files() {
    remove_if_exists "$NVSE_PLUGIN_DIR/psycho-nvse.toml"
    remove_if_exists "$NVSE_PLUGIN_DIR/psycho.toml"
    remove_if_exists "$NVSE_PLUGIN_DIR/psycho_nvse.dll"

    remove_if_exists "$GAME_ROOT/Data/NVSE/Plugins/psycho-nvse.toml"
    remove_if_exists "$GAME_ROOT/Data/NVSE/Plugins/psycho.toml"
    remove_if_exists "$GAME_ROOT/Data/NVSE/Plugins/psycho_nvse_helper.dll"
    remove_if_exists "$GAME_ROOT/Data/NVSE/Plugins/psycho_engine_fixes_helper.dll"

    remove_if_exists "$GAME_MODS_DIR/psycho.toml"
    remove_if_exists "$GAME_MODS_DIR/psycho.dll"
}

build_rust
install_files
remove_legacy_files

echo "'$LOADER_DLL' copied to '$LOADER_PATH'"
echo "'$CORE_DLL' copied to '$CORE_PATH'"
echo "'$HELPER_DLL' copied to '$HELPER_PATH'"
echo "'$GRAPHICS_DLL' copied to '$GRAPHICS_PATH'"
echo "Engine config copied to '$ENGINE_CFG_PATH'"
echo "Graphics config copied to '$GRAPHICS_CFG_PATH'"
echo "Shader directory ready at '$SHADER_DIR'"
echo "Build type: $BUILD_TYPE"
echo "Target:     $TARGET"
