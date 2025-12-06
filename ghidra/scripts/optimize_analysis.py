# Ghidra Prescript: Optimize analysis for large ARM64 binaries
# Run BEFORE main analysis with: -preScript optimize_analysis.py
#
# This script disables slow analyzers that aren't needed for our component discovery.
# Full analysis of BG3 (1GB+) can take hours; this reduces it to minutes.
#
# NOTE: For already-analyzed projects, use -readOnly flag to skip re-analysis.

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Program
import time

# Progress tracking - initialize log file
PROGRESS_FILE = "/tmp/ghidra_progress.log"

def progress(msg, pct=None):
    """Log progress to file and console."""
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    if pct is not None:
        line += " (%d%%)" % pct
        try:
            monitor.setMaximum(100)
            monitor.setProgress(int(pct))
        except:
            pass
    try:
        monitor.setMessage(str(msg))
    except:
        pass
    print(line)
    with open(PROGRESS_FILE, "a") as f:
        f.write(line + "\n")

# Clear progress log at start (prescript runs first)
with open(PROGRESS_FILE, "w") as f:
    f.write("[%s] === Ghidra Analysis Started ===\n" % time.strftime("%H:%M:%S"))

progress("Checking analysis state", 0)

# Check if program is already analyzed by looking at function count
func_count = currentProgram.getFunctionManager().getFunctionCount()
if func_count > 100000:
    progress("Program already analyzed (%d functions), skipping optimizer" % func_count, 100)
    print("  Tip: Use -readOnly flag for read-only scripts on analyzed projects")
else:
    progress("Optimizing Ghidra Analysis Settings", 10)

    # Disable slow analyzers that we don't need
    slow_analyzers = [
        "ARM Constant Reference Analyzer",  # Very slow on large binaries
        "Decompiler Parameter ID",          # Slow, not needed for refs
        "Stack",                            # Slow stack analysis
        "Decompiler Switch Analysis",       # Slow
        "Non-Returning Functions - Discovered", # Can be slow
        "Embedded Media",                   # Not needed
        "GCC Exception Handlers",           # Not needed for our use
        "Windows x86 Thread Environment Block (TEB) Analyzer", # Windows only
        "Windows x86 PE Exception Handling", # Windows only
    ]

    # Enable only what we need
    needed_analyzers = [
        "ASCII Strings",                    # Find strings
        "Reference",                        # Find XREFs (critical!)
        "Function Start Search",            # Find functions
        "Subroutine References",            # Find call targets
        "Data Reference",                   # Find data refs
        "Entry Point",                      # Basic entry analysis
    ]

    progress("Disabling slow analyzers", 25)
    disabled_count = 0
    for analyzer in slow_analyzers:
        try:
            setAnalysisOption(currentProgram, analyzer, "false")
            print("  - Disabled: {}".format(analyzer))
            disabled_count += 1
        except:
            pass  # Analyzer might not exist

    progress("Disabled %d slow analyzers" % disabled_count, 50)

    progress("Enabling needed analyzers", 60)
    enabled_count = 0
    for analyzer in needed_analyzers:
        try:
            setAnalysisOption(currentProgram, analyzer, "true")
            print("  + Enabled: {}".format(analyzer))
            enabled_count += 1
        except:
            pass  # Analyzer might not exist

    progress("Enabled %d needed analyzers" % enabled_count, 75)
    progress("Optimization complete, starting analysis...", 80)
