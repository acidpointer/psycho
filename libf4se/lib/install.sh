#!/usr/bin/env bash

export SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
export DIR="$(dirname "$SCRIPT")"


function msg () {
    echo -e "$0"
}

F4SE_VERSION="v0.6.23"

msg "Fetching F4SE $F4SE_VERSION"

#0.6.23

cd "$DIR"

git clone --depth 1 https://github.com/ianpatt/common $DIR/common
git clone --depth 1 --branch $F4SE_VERSION https://github.com/ianpatt/f4se $DIR/f4se
