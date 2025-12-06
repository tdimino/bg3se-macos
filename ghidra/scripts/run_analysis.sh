#!/bin/bash
# Wrapper script for Ghidra headless analysis
#
# Usage: ./run_analysis.sh <postscript.py> [additional args...]
# Example: ./run_analysis.sh find_modifierlist_offsets.py
#
# For already-analyzed projects, uses -noanalysis to skip re-analysis.
# Use -analyze flag to force re-analysis with optimized settings.
#
# Monitor progress: tail -f /tmp/ghidra_progress.log

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POSTSCRIPT="$1"
FORCE_ANALYZE=""

if [ -z "$POSTSCRIPT" ]; then
    echo "Usage: $0 <postscript.py> [options]"
    echo ""
    echo "Options:"
    echo "  -analyze    Force re-analysis (default: skip if already analyzed)"
    echo ""
    echo "Available scripts:"
    ls -1 "$SCRIPT_DIR"/*.py 2>/dev/null | xargs -n1 basename | grep -v "^_" | grep -v "utils" | sort
    echo ""
    echo "Example: $0 find_modifierlist_offsets.py"
    exit 1
fi

shift  # Remove first arg

# Check for -analyze flag
for arg in "$@"; do
    if [ "$arg" = "-analyze" ]; then
        FORCE_ANALYZE="yes"
        shift
        break
    fi
done

# Clear progress log
> /tmp/ghidra_progress.log

echo "=============================================="
echo "Ghidra Headless Script Runner"
echo "=============================================="
echo "Script: $POSTSCRIPT"
echo "Progress: tail -f /tmp/ghidra_progress.log"

if [ -n "$FORCE_ANALYZE" ]; then
    echo "Mode: Re-analyze with optimized settings"
    echo ""

    JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
      ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
      -process BG3_arm64_thin \
      -scriptPath "$SCRIPT_DIR" \
      -preScript optimize_analysis.py \
      -postScript "$POSTSCRIPT" \
      "$@" \
      2>&1 | tee /tmp/ghidra_output.log
else
    echo "Mode: Read-only (use -analyze to re-analyze)"
    echo ""

    # Use -noanalysis for read-only script execution
    JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
      ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
      -process BG3_arm64_thin \
      -noanalysis \
      -scriptPath "$SCRIPT_DIR" \
      -postScript "$POSTSCRIPT" \
      "$@" \
      2>&1 | tee /tmp/ghidra_output.log
fi

echo ""
echo "=============================================="
echo "Complete"
echo "Output: /tmp/ghidra_output.log"
echo "Progress: /tmp/ghidra_progress.log"
echo "=============================================="
