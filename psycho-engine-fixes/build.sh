#!/usr/bin/env bash
set -euo pipefail

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(dirname "$SCRIPT")"

"$DIR/../build_fnv.sh"
