#!/usr/bin/env bash
# Run the supported validation ladder for one or more crates.
#
# Usage:
#   check.sh <crate> [<crate> ...] [--build]
#
# This script does not install or package anything.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
TARGET="i686-pc-windows-gnu"
build=0
crates=()

for arg in "$@"; do
    case "$arg" in
        --build) build=1 ;;
        -h|--help)
            echo "usage: check.sh <crate> [<crate> ...] [--build]" >&2
            exit 0
            ;;
        *) crates+=("$arg") ;;
    esac
done

if [[ ${#crates[@]} -eq 0 ]]; then
    echo "usage: check.sh <crate> [<crate> ...] [--build]" >&2
    exit 2
fi

cd "$ROOT"

fmt_args=()
for crate in "${crates[@]}"; do
    fmt_args+=(-p "$crate")
done

echo "== rustfmt =="
cargo fmt "${fmt_args[@]}" -- --check

for crate in "${crates[@]}"; do
    echo "== test $crate =="
    cargo test --target "$TARGET" -p "$crate"
done

if [[ "$build" -eq 1 ]]; then
    for crate in "${crates[@]}"; do
        echo "== release build $crate =="
        cargo build --release --target "$TARGET" -p "$crate"
    done
fi

echo "== diff check =="
git diff --check

echo "validation complete"
