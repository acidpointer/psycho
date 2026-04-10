#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="i686-pc-windows-gnu"

echo "Testing for: ($TARGET)..."
cargo test --target "$TARGET" --manifest-path "$SCRIPT_DIR/Cargo.toml"