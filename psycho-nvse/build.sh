#!/usr/bin/env bash

####################
## EDIT THIS VAR  ##

TARGET_DIR="/data/storage0/Games/FalloutNV_TTW/FalloutNV"



### DO NOT EDIT LINES BELOW ###

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(dirname "$SCRIPT")"

TARGET="i686-pc-windows-gnu"
DLLNAME="psycho_nvse.dll"
BUILD_TYPE="release"
BIN="$DIR/../target/$TARGET/$BUILD_TYPE/$DLLNAME"
PLUGIN_DIR="$TARGET_DIR/Data/NVSE/plugins"
TARGET_PATH="$PLUGIN_DIR/$DLLNAME"

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
        mv "$BIN" "$TARGET_PATH"
        
        if [[ -f "$TARGET_PATH" ]]; then
            echo -e "'$DLLNAME' copied to '$TARGET_PATH'\nBuild type: $BUILD_TYPE\nTarget: $TARGET"
        fi
    fi
}

build_rust
