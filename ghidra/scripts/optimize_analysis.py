# Ghidra Prescript: Optimize analysis for large ARM64 binaries
# Run BEFORE main analysis with: -preScript optimize_analysis.py
#
# This script disables slow analyzers that aren't needed for our component discovery.
# Full analysis of BG3 (1GB+) can take hours; this reduces it to minutes.

from ghidra.app.script import GhidraScript

print("=" * 60)
print("Optimizing Ghidra Analysis Settings")
print("=" * 60)

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

print("\nDisabling slow analyzers:")
for analyzer in slow_analyzers:
    try:
        setAnalysisOption(currentProgram, analyzer, "false")
        print("  - Disabled: {}".format(analyzer))
    except:
        pass  # Analyzer might not exist

print("\nEnsuring needed analyzers are enabled:")
for analyzer in needed_analyzers:
    try:
        setAnalysisOption(currentProgram, analyzer, "true")
        print("  + Enabled: {}".format(analyzer))
    except:
        pass  # Analyzer might not exist

print("\n" + "=" * 60)
print("Analysis optimization complete")
print("Run main script with -postScript to use these settings")
print("=" * 60)
