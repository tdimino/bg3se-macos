#!/bin/bash
#
# BG3SE-macOS Steam Launcher
#
# This creates a wrapper that Steam will use to launch BG3 with our dylib injected.
#
# How it works:
# 1. We create a temporary wrapper script
# 2. We set Steam launch options to use our wrapper
# 3. Steam launches the game through our wrapper, which sets DYLD_INSERT_LIBRARIES
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DYLIB="${PROJECT_ROOT}/build/lib/libbg3se.dylib"

BG3_STEAM_ID="1086940"
BG3_APP="/Users/tomdimino/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app"

# Verify dylib exists
if [[ ! -f "$DYLIB" ]]; then
    echo "Error: libbg3se.dylib not found. Build it first with ./scripts/build.sh"
    exit 1
fi

echo "=========================================="
echo "BG3SE-macOS Steam Launcher"
echo "=========================================="
echo ""
echo "To use BG3SE with Steam, you need to set launch options:"
echo ""
echo "1. Open Steam"
echo "2. Right-click Baldur's Gate 3 → Properties"
echo "3. In 'Launch Options', paste this EXACTLY:"
echo ""
echo "   DYLD_INSERT_LIBRARIES=\"${DYLIB}\" %command%"
echo ""
echo "4. Click OK and launch the game normally from Steam"
echo ""
echo "=========================================="
echo ""
echo "Alternative: Launch directly (may have Steam API issues):"
echo ""

# Clean up old logs
rm -f /tmp/bg3se_loaded.txt /tmp/bg3se_macos.log

read -p "Launch BG3 directly now? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Launching via Steam protocol..."

    # Set the environment and use open to launch via Steam
    # This tells Steam to launch the app, which should pick up launch options
    open "steam://run/${BG3_STEAM_ID}"

    echo ""
    echo "Game launching via Steam..."
    echo "Check /tmp/bg3se_macos.log after the game starts"
    echo ""
    echo "NOTE: Make sure you've set the launch options in Steam first!"
fi
