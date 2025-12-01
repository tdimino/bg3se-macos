/**
 * BG3SE-macOS - Frida Component Discovery Script
 *
 * This script discovers component type indices at runtime by:
 * 1. Finding GetRawComponent function
 * 2. Hooking component registration
 * 3. Observing component access patterns
 *
 * Usage:
 *   frida -n "Baldur's Gate 3" -l discover_components.js
 *
 * Or attach with script loading:
 *   frida -n "Baldur's Gate 3" --runtime=v8 -l discover_components.js
 */

'use strict';

// Configuration
const CONFIG = {
    // Log verbosity
    verbose: true,
    logFile: '/tmp/bg3se_component_discovery.json',

    // Component discovery
    maxComponents: 2048,

    // Known component names to watch for
    watchComponents: [
        'eoc::HealthComponent',
        'eoc::StatsComponent',
        'eoc::ArmorComponent',
        'eoc::BaseHpComponent',
        'ls::TransformComponent',
        'ls::LevelComponent',
    ]
};

// Discovery state
const discoveredComponents = new Map();  // index -> {name, size, count}
const componentAccesses = new Map();     // name -> {index, size, accessCount}
let getRawComponentAddr = null;
let registerComponentAddr = null;

// Logging
function log(msg) {
    console.log(`[BG3SE] ${msg}`);
}

function logVerbose(msg) {
    if (CONFIG.verbose) {
        console.log(`[BG3SE:V] ${msg}`);
    }
}

// Find module base
function findBG3Module() {
    const modules = Process.enumerateModules();

    for (const mod of modules) {
        if (mod.name.includes('Baldur') || mod.name === 'bg3' || mod.name === 'bg3.exe') {
            log(`Found BG3 module: ${mod.name} at ${mod.base}`);
            return mod;
        }
    }

    // On macOS, look for the main executable
    for (const mod of modules) {
        if (mod.path.includes('Baldur\'s Gate 3.app')) {
            log(`Found BG3 module: ${mod.name} at ${mod.base}`);
            return mod;
        }
    }

    log('WARNING: Could not find BG3 main module');
    return null;
}

// Pattern scanning utilities
function scanForPattern(module, pattern, name) {
    log(`Scanning for ${name} pattern: ${pattern}`);

    const results = Memory.scanSync(module.base, module.size, pattern);

    if (results.length === 0) {
        log(`  No matches found for ${name}`);
        return null;
    }

    log(`  Found ${results.length} matches for ${name}`);
    for (let i = 0; i < Math.min(5, results.length); i++) {
        log(`    [${i}] ${results[i].address}`);
    }

    return results.length === 1 ? results[0].address : results;
}

// GetRawComponent discovery via pattern
function discoverGetRawComponent(module) {
    log('Attempting to discover GetRawComponent...');

    // ARM64 pattern for GetRawComponent
    // This function:
    // - Takes x0=EntityWorld*, x1=EntityHandle (64-bit), w2=typeIndex (16-bit), x3=size, w4=isProxy
    // - Returns pointer in x0
    //
    // Look for prologue patterns common to this function

    // Pattern 1: Check for IsOneFrame (type & 0x8000)
    // ARM64: TST W2, #0x8000 or similar
    const patterns = [
        // Pattern for checking one-frame bit: AND followed by comparison
        'E0 03 ?? AA ?? ?? ?? 94',  // MOV X0, Xn; BL <function>

        // EntityStorage access pattern
        '?? ?? ?? F9 ?? ?? ?? B4',  // LDR; CBZ pattern
    ];

    // For now, log that we need manual discovery
    log('GetRawComponent automatic pattern discovery not implemented');
    log('Please provide the address manually or use the strategies below:');
    log('');
    log('Strategy 1: Hook EntityStorageData::GetComponent and trace callers');
    log('Strategy 2: Break on entity access and trace back');
    log('Strategy 3: Search for functions taking (handle, uint16_t, size_t, bool)');

    return null;
}

// Hook GetRawComponent to observe component accesses
function hookGetRawComponent(addr) {
    if (!addr) {
        log('Cannot hook GetRawComponent: address not set');
        return;
    }

    getRawComponentAddr = addr;
    log(`Hooking GetRawComponent at ${addr}`);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.entityWorld = args[0];
            this.entityHandle = args[1].toString();
            this.typeIndex = args[2].toInt32() & 0xFFFF;
            this.componentSize = args[3].toInt32();
            this.isProxy = args[4].toInt32() !== 0;
        },
        onLeave: function(retval) {
            if (retval.isNull()) return;

            // Record the access
            const info = discoveredComponents.get(this.typeIndex);
            if (info) {
                info.count++;
                info.size = this.componentSize;
            } else {
                discoveredComponents.set(this.typeIndex, {
                    name: `unknown_${this.typeIndex}`,
                    size: this.componentSize,
                    count: 1,
                    isProxy: this.isProxy
                });
            }

            logVerbose(`GetRawComponent: typeIndex=${this.typeIndex}, size=${this.componentSize}, isProxy=${this.isProxy}`);
        }
    });

    log('GetRawComponent hooked successfully');
}

// Look for component string references
function findComponentStrings(module) {
    log('Searching for component string references...');

    const componentStrings = {};
    const searchPatterns = [
        'eoc::',
        'ls::',
        'esv::',
        'ecl::',
    ];

    for (const prefix of searchPatterns) {
        // Search for namespace prefix in memory
        const pattern = prefix.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');

        try {
            const results = Memory.scanSync(module.base, module.size, pattern);
            log(`  Found ${results.length} '${prefix}' strings`);

            for (const result of results.slice(0, 20)) {  // Limit to first 20
                try {
                    const str = result.address.readUtf8String();
                    if (str && str.includes('Component')) {
                        componentStrings[result.address.toString()] = str.split('\0')[0];
                        logVerbose(`    ${result.address}: ${str.split('\0')[0]}`);
                    }
                } catch (e) {
                    // Invalid string, skip
                }
            }
        } catch (e) {
            log(`  Error scanning for '${prefix}': ${e}`);
        }
    }

    return componentStrings;
}

// Hook component registration (if we can find it)
function discoverComponentRegistration(module) {
    log('Attempting to discover component registration...');

    // Component registration typically:
    // 1. Takes a string name
    // 2. Returns or sets a uint16_t index
    // 3. Is called during static initialization
    //
    // Look for functions that reference component name strings

    log('Component registration discovery not yet implemented');
    log('Consider hooking static initializers or constructor sections');

    return null;
}

// Save discoveries to file
function saveDiscoveries() {
    const output = {
        timestamp: new Date().toISOString(),
        getRawComponentAddr: getRawComponentAddr ? getRawComponentAddr.toString() : null,
        components: []
    };

    discoveredComponents.forEach((info, index) => {
        output.components.push({
            index: index,
            name: info.name,
            size: info.size,
            accessCount: info.count,
            isProxy: info.isProxy
        });
    });

    // Sort by access count
    output.components.sort((a, b) => b.accessCount - a.accessCount);

    const json = JSON.stringify(output, null, 2);

    // Write to file
    const file = new File(CONFIG.logFile, 'w');
    file.write(json);
    file.close();

    log(`Saved discoveries to ${CONFIG.logFile}`);
    log(`Total components discovered: ${output.components.length}`);
}

// Dump current discoveries
function dumpDiscoveries() {
    log('=== Component Discovery Status ===');
    log(`GetRawComponent: ${getRawComponentAddr || 'NOT FOUND'}`);
    log(`Components discovered: ${discoveredComponents.size}`);

    const sorted = Array.from(discoveredComponents.entries())
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 20);

    log('Top 20 accessed components:');
    for (const [index, info] of sorted) {
        log(`  [${index}] ${info.name}: size=${info.size}, accesses=${info.count}`);
    }
}

// Manual address input functions
function setGetRawComponent(addrStr) {
    const addr = ptr(addrStr);
    hookGetRawComponent(addr);
}

function setComponentIndex(name, index, size) {
    discoveredComponents.set(index, {
        name: name,
        size: size || 0,
        count: 0,
        isProxy: false
    });
    log(`Registered: ${name} -> index=${index}`);
}

// Main entry point
function main() {
    log('=== BG3SE Component Discovery Script ===');
    log(`Platform: ${Process.platform}`);
    log(`Architecture: ${Process.arch}`);

    const module = findBG3Module();
    if (!module) {
        log('ERROR: Could not find BG3 module');
        return;
    }

    log(`Module base: ${module.base}`);
    log(`Module size: ${module.size}`);

    // Attempt automatic discovery
    const componentStrings = findComponentStrings(module);
    log(`Found ${Object.keys(componentStrings).length} component strings`);

    // Try to discover GetRawComponent
    discoverGetRawComponent(module);

    // Try to discover registration
    discoverComponentRegistration(module);

    log('');
    log('=== Manual Discovery Commands ===');
    log('setGetRawComponent("0x123456") - Set GetRawComponent address');
    log('setComponentIndex("eoc::HealthComponent", 42, 64) - Register component');
    log('dumpDiscoveries() - Show current discoveries');
    log('saveDiscoveries() - Save to file');
    log('');
}

// Export functions for interactive use
global.setGetRawComponent = setGetRawComponent;
global.setComponentIndex = setComponentIndex;
global.dumpDiscoveries = dumpDiscoveries;
global.saveDiscoveries = saveDiscoveries;

// Run main
main();
