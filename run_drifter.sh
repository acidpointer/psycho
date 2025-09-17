#!/bin/bash
set -e

echo "🚀 Building and running drifter..."

# Build drifter for Windows
echo "Building drifter..."
export CC_x86_64_pc_windows_gnu="x86_64-w64-mingw32-gcc"
export CXX_x86_64_pc_windows_gnu="x86_64-w64-mingw32-g++"
export AR_x86_64_pc_windows_gnu="x86_64-w64-mingw32-ar"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="x86_64-w64-mingw32-gcc"

cargo build --target x86_64-pc-windows-gnu -p drifter

# Setup Wine
export WINEPREFIX="$PWD/.wine_psycho"
export WINEDEBUG="-all"

if [ ! -d "$WINEPREFIX" ]; then
    echo "Setting up Wine..."
    wineboot --init >/dev/null 2>&1
fi

# Run drifter with Wine
echo "Running drifter..."
cd drifter
WINEDEBUG="-all" wine "../target/x86_64-pc-windows-gnu/debug/drifter.exe"

echo "✅ Done! Check drifter_report.json for results."