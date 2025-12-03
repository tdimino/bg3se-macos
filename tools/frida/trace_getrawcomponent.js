/**
 * BG3SE-macOS - Frida Script to Find GetRawComponent
 *
 * Strategy: Hook EntityStorageContainer::TryGet and trace callers
 * to identify GetRawComponent or equivalent dispatcher function.
 *
 * Usage:
 *   frida -n "Baldur's Gate 3" -l trace_getrawcomponent.js
 */

'use strict';

// Known addresses from Ghidra analysis (with ASLR slide applied at runtime)
const KNOWN_OFFSETS = {
    // EntityStorageContainer::TryGet - small wrapper that accesses storage
    EntityStorageContainer_TryGet: 0x10636b27c - 0x100000000,  // Remove assumed base
    EntityStorageContainer_TryGet_const: 0x10636b310 - 0x100000000,

    // EntityStorageData functions
    EntityStoragePurgeAll: 0x10636d368 - 0x100000000,
    EntityStorageData_dtor: 0x10636c868 - 0x100000000,
};

// State
let bg3Module = null;
let slideOffset = 0;
let callTraces = new Map();  // Track unique call stacks
let componentAccesses = [];

function log(msg) {
    console.log(`[BG3SE-Trace] ${msg}`);
}

function findBG3Module() {
    const modules = Process.enumerateModules();

    for (const mod of modules) {
        if (mod.path.includes("Baldur's Gate 3.app/Contents/MacOS")) {
            log(`Found BG3 module: ${mod.name}`);
            log(`  Base: ${mod.base}`);
            log(`  Size: ${mod.size}`);
            return mod;
        }
    }

    log("ERROR: Could not find BG3 main module");
    return null;
}

function calculateSlide(module) {
    // The Ghidra addresses assume base 0x100000000
    // Real base varies due to ASLR
    const ghidraBase = ptr("0x100000000");
    const realBase = module.base;
    return realBase.sub(ghidraBase);
}

function resolveAddress(ghidraAddr) {
    return ptr(ghidraAddr).add(slideOffset);
}

function formatBacktrace(context) {
    const bt = Thread.backtrace(context, Backtracer.ACCURATE);
    const lines = [];

    for (let i = 0; i < Math.min(bt.length, 15); i++) {
        const addr = bt[i];
        const sym = DebugSymbol.fromAddress(addr);

        // Calculate offset from module base
        const offset = addr.sub(bg3Module.base);
        const ghidraAddr = ptr("0x100000000").add(offset);

        if (sym && sym.name) {
            lines.push(`  [${i}] ${ghidraAddr} (${sym.name})`);
        } else {
            lines.push(`  [${i}] ${ghidraAddr}`);
        }
    }

    return lines.join('\n');
}

function hookTryGet() {
    const tryGetOffset = KNOWN_OFFSETS.EntityStorageContainer_TryGet;
    const tryGetAddr = resolveAddress(tryGetOffset + 0x100000000);

    log(`Hooking EntityStorageContainer::TryGet at ${tryGetAddr}`);
    log(`  (Ghidra address: 0x${(tryGetOffset + 0x100000000).toString(16)})`);

    Interceptor.attach(tryGetAddr, {
        onEnter: function(args) {
            // TryGet signature: TryGet(EntityHandle handle)
            // this = EntityStorageContainer*
            // x0 = this
            // x1 = EntityHandle (64-bit)

            this.containerPtr = args[0];
            this.entityHandle = args[1];

            // Get backtrace to find caller
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);

            if (bt.length > 1) {
                // The immediate caller is what we're looking for
                const callerAddr = bt[1];
                const callerOffset = callerAddr.sub(bg3Module.base);
                const ghidraCallerAddr = ptr("0x100000000").add(callerOffset);

                // Track unique callers
                const callerKey = ghidraCallerAddr.toString();
                if (!callTraces.has(callerKey)) {
                    callTraces.set(callerKey, {
                        addr: ghidraCallerAddr,
                        count: 0,
                        fullTrace: formatBacktrace(this.context)
                    });

                    log(`\n=== NEW CALLER of TryGet ===`);
                    log(`Caller: ${ghidraCallerAddr}`);
                    log(`EntityHandle: ${this.entityHandle}`);
                    log(`Full backtrace:\n${formatBacktrace(this.context)}`);
                }

                callTraces.get(callerKey).count++;
            }
        },
        onLeave: function(retval) {
            // retval is EntityStorageData* or null
            if (!retval.isNull()) {
                const callerKey = Array.from(callTraces.keys()).pop();
                if (callerKey) {
                    const info = callTraces.get(callerKey);
                    // log(`TryGet returned: ${retval} (caller: ${info.addr})`);
                }
            }
        }
    });

    log("TryGet hook installed");
}

function hookTryGetConst() {
    const tryGetConstOffset = KNOWN_OFFSETS.EntityStorageContainer_TryGet_const;
    const tryGetConstAddr = resolveAddress(tryGetConstOffset + 0x100000000);

    log(`Hooking EntityStorageContainer::TryGet (const) at ${tryGetConstAddr}`);

    Interceptor.attach(tryGetConstAddr, {
        onEnter: function(args) {
            this.containerPtr = args[0];
            this.entityHandle = args[1];

            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);

            if (bt.length > 1) {
                const callerAddr = bt[1];
                const callerOffset = callerAddr.sub(bg3Module.base);
                const ghidraCallerAddr = ptr("0x100000000").add(callerOffset);

                const callerKey = "const_" + ghidraCallerAddr.toString();
                if (!callTraces.has(callerKey)) {
                    callTraces.set(callerKey, {
                        addr: ghidraCallerAddr,
                        count: 0,
                        isConst: true,
                        fullTrace: formatBacktrace(this.context)
                    });

                    log(`\n=== NEW CALLER of TryGet (const) ===`);
                    log(`Caller: ${ghidraCallerAddr}`);
                    log(`EntityHandle: ${this.entityHandle}`);
                    log(`Full backtrace:\n${formatBacktrace(this.context)}`);
                }

                callTraces.get(callerKey).count++;
            }
        }
    });

    log("TryGet (const) hook installed");
}

// Try to find GetRawComponent by looking for functions that:
// 1. Take 5 parameters (world, handle, typeIndex, size, isProxy)
// 2. Call TryGet internally
function analyzeCallers() {
    log("\n=== CALLER ANALYSIS ===");
    log(`Total unique callers found: ${callTraces.size}`);

    // Sort by call count
    const sorted = Array.from(callTraces.entries())
        .sort((a, b) => b[1].count - a[1].count);

    log("\nTop callers of TryGet (most frequent first):");
    for (const [key, info] of sorted.slice(0, 20)) {
        const constMark = info.isConst ? " (const)" : "";
        log(`  ${info.addr}${constMark}: ${info.count} calls`);
    }

    log("\n=== POTENTIAL GetRawComponent CANDIDATES ===");
    log("Look for callers that appear frequently during gameplay.");
    log("GetRawComponent should be called whenever ANY component is accessed.");
    log("");
    log("Next steps:");
    log("1. Note the top caller addresses");
    log("2. Examine them in Ghidra");
    log("3. Look for one that takes (world, handle, uint16, size, bool)");
}

// Dump all discoveries
function dumpCallers() {
    log("\n========================================");
    log("COMPLETE CALLER DUMP");
    log("========================================\n");

    for (const [key, info] of callTraces.entries()) {
        log(`--- ${info.addr} (${info.count} calls) ---`);
        log(info.fullTrace);
        log("");
    }
}

// Save results to file
function saveResults() {
    const output = {
        timestamp: new Date().toISOString(),
        moduleBase: bg3Module.base.toString(),
        slide: slideOffset.toString(),
        callers: []
    };

    for (const [key, info] of callTraces.entries()) {
        output.callers.push({
            ghidraAddress: info.addr.toString(),
            callCount: info.count,
            isConst: info.isConst || false
        });
    }

    const json = JSON.stringify(output, null, 2);
    const file = new File('/tmp/bg3se_tryget_callers.json', 'w');
    file.write(json);
    file.close();

    log(`Results saved to /tmp/bg3se_tryget_callers.json`);
}

// Main
function main() {
    log("========================================");
    log("BG3SE GetRawComponent Tracer");
    log("========================================");
    log("");

    bg3Module = findBG3Module();
    if (!bg3Module) {
        return;
    }

    slideOffset = calculateSlide(bg3Module);
    log(`ASLR slide: ${slideOffset}`);
    log("");

    // Install hooks
    try {
        hookTryGet();
        hookTryGetConst();
    } catch (e) {
        log(`ERROR installing hooks: ${e}`);
        return;
    }

    log("");
    log("========================================");
    log("INSTRUCTIONS");
    log("========================================");
    log("1. Play the game - access characters, items, open inventory");
    log("2. Each unique caller of TryGet will be logged");
    log("3. Run these commands in Frida REPL:");
    log("   analyzeCallers()  - Show caller statistics");
    log("   dumpCallers()     - Show full backtraces");
    log("   saveResults()     - Save to JSON file");
    log("");
    log("The most frequent caller is likely GetRawComponent!");
    log("========================================");
}

// Export functions for REPL
globalThis.analyzeCallers = analyzeCallers;
globalThis.dumpCallers = dumpCallers;
globalThis.saveResults = saveResults;

// Run
main();
