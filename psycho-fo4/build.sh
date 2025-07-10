#!/usr/bin/env bash

####################
## EDIT THIS VAR  ##

TARGET_DIR="/media/storage0/Games/Fallout4"



### DO NOT EDIT LINES BELOW ###

export SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
export DIR="$(dirname "$SCRIPT")"

TARGET="x86_64-pc-windows-msvc"
DLLNAME="psycho.dll"
BUILD_TYPE="release"
BIN="$DIR/target/$TARGET/$BUILD_TYPE/$DLLNAME"
PLUGIN_DIR="$TARGET_DIR/Data/F4SE/Plugins/"
TARGET_PATH="$PLUGIN_DIR/$DLLNAME"

function build_rust () {
    mkdir -p "$PLUGIN_DIR"

    if [[ "$BUILD_TYPE" = "release" ]]; then
        cargo xwin build --target $TARGET --release
        echo "!!!RELEASE MODE BUILD!!!"
    else 
        cargo xwin build --target $TARGET
    fi


    if [[ -f "$BIN" ]]; then
        mv "$BIN" "$TARGET_PATH"
        
        if [[ -f "$TARGET_PATH" ]]; then
            echo -e "'$DLLNAME' copied to '$TARGET_PATH'\nBuild type: $BUILD_TYPE\nTarget: $TARGET"
        fi
    fi
}

build_rust
