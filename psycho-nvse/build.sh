#!/usr/bin/env bash

####################
## EDIT THIS VAR  ##

TARGET_DIR="/data/storage0/Games/FalloutNV_TTW"


### DO NOT EDIT LINES BELOW ###

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(dirname "$SCRIPT")"

TARGET="i686-pc-windows-gnu"
DLLNAME="psycho_nvse.dll"
CFGNAME="psycho-nvse.toml"
BUILD_TYPE="release"

BIN="$DIR/../target/$TARGET/$BUILD_TYPE/$DLLNAME"
CFG="$DIR/config/$CFGNAME"

PLUGIN_DIR="$TARGET_DIR/mods/psycho_nvse/nvse/plugins"

DLL_PATH="$PLUGIN_DIR/$DLLNAME"
CFG_PATH="$PLUGIN_DIR/$CFGNAME"

function build_rust () {
    cd $DIR
    mkdir -p "$PLUGIN_DIR"

    if [[ "$BUILD_TYPE" = "release" ]]; then
        cargo build --target $TARGET --release
        echo "!!!RELEASE MODE BUILD!!!"
    else 
        cargo build --target $TARGET
    fi


    if [[ -f "$BIN" ]]; then
        mv "$BIN" "$DLL_PATH" 2> /dev/null
        cp "$CFG" "$CFG_PATH"
        
        if [[ -f "$DLL_PATH" ]]; then
            echo -e "'$DLLNAME' copied to '$DLL_PATH'\nBuild type: $BUILD_TYPE\nTarget:     $TARGET"
        fi
    fi
}

build_rust
