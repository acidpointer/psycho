#!/usr/bin/env bash

####################
## EDIT THIS VAR  ##

TARGET_DIR="/data/storage0/Games/FalloutNV_TTW/FalloutNV"
LOGFILE="psycho-nvse-latest.log"
CRASHFILE="CrashLogger.log"

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(dirname "$SCRIPT")"

LOGPATH="$TARGET_DIR/$LOGFILE"
CRASHPATH="$TARGET_DIR/$CRASHFILE"

if [[ -f "$TARGET_DIR/$LOGFILE" ]]; then
    ln -s "$LOGPATH" "$DIR/$LOGFILE"
fi


if [[ -f "$TARGET_DIR/$CRASHFILE" ]]; then
    ln -s "$CRASHPATH" "$DIR/$CRASHFILE"
fi