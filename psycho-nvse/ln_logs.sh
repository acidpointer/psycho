#!/usr/bin/env bash

####################
## EDIT THIS VAR  ##

TARGET_DIR="/data/storage0/Games/FalloutNV_TTW/FalloutNV"
LOGFILE="psycho-nvse-latest.log"


SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(dirname "$SCRIPT")"

LOGPATH="$TARGET_DIR/$LOGFILE"

if [[ -f "$TARGET_DIR/$LOGFILE" ]]; then
    ln -s "$LOGPATH" "$DIR/$LOGFILE"
fi