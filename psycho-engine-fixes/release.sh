#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${1:-local}"

# Keep local packaging identical to the release workflow. The core archive is
# ready for extraction into the game root; the optional helper and OMV are
# separate conventional NVSE mod archives.
exec bash "$WORKSPACE_DIR/.github/scripts/package_release.sh" "$VERSION"
