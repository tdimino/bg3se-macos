/**
 * capture_singletons.js - Capture singleton pointers via Frida
 *
 * Usage:
 *   frida -U -n "Baldur's Gate 3" -l capture_singletons.js
 *
 * Or attach to process:
 *   frida -p $(pgrep -f "Baldur") -l capture_singletons.js
 */

const MODULE_NAME = "Baldur's Gate 3";

// Known function addresses (add module base at runtime)
const TARGETS = {
    // AiGrid constructor - arg[1] is PhysicsScene*
    AiGrid_ctor: {
        offset: 0x10116fd20,
        description: "AiGrid constructor",
        onEnter: function(args) {
            console.log("[AiGrid] PhysicsScene*: " + args[1]);
            send({type: "singleton", name: "PhysicsScene", addr: args[1].toString()});
        }
    },

    // GetSpellPrototype - useful for tracing spell lookups
    GetSpellPrototype: {
        offset: 0x10346e740,
        description: "GetSpellPrototype (via SpellCastWrapper)",
        onEnter: function(args) {
            // First arg is spell name as FixedString
            const spellFs = args[0].toInt32();
            console.log("[GetSpellPrototype] FixedString: " + spellFs);
        },
        onLeave: function(retval) {
            console.log("[GetSpellPrototype] returned: " + retval);
        }
    },

    // SpellPrototype::Init - trace prototype population
    SpellPrototype_Init: {
        offset: 0x101f72754,
        description: "SpellPrototype::Init",
        onEnter: function(args) {
            console.log("[SpellPrototype::Init] this=" + args[0] + " spell_fs_ptr=" + args[1]);
            // Read the FixedString value from the pointer
            const fsVal = args[1].readU32();
            console.log("  FixedString value: " + fsVal);
        }
    },

    // IsInCombat - already captured for EntityWorld, but useful for verification
    IsInCombat: {
        offset: 0x10124f92c,
        description: "LEGACY_IsInCombat",
        onEnter: function(args) {
            console.log("[IsInCombat] EntityWorld*: " + args[0]);
            send({type: "singleton", name: "EntityWorld", addr: args[0].toString()});
        }
    }
};

function hookTarget(name, config) {
    const base = Module.getBaseAddress(MODULE_NAME);
    if (!base) {
        console.log("[-] Could not find module: " + MODULE_NAME);
        return false;
    }

    const addr = base.add(config.offset);
    console.log("[+] Hooking " + name + " at " + addr + " (" + config.description + ")");

    try {
        Interceptor.attach(addr, {
            onEnter: config.onEnter || function(args) {},
            onLeave: config.onLeave || function(retval) {}
        });
        return true;
    } catch (e) {
        console.log("[-] Failed to hook " + name + ": " + e);
        return false;
    }
}

// Main
console.log("\n=== BG3SE Singleton Capture ===");
console.log("Module: " + MODULE_NAME);

const base = Module.getBaseAddress(MODULE_NAME);
if (base) {
    console.log("Base: " + base);
    console.log("");

    let hooked = 0;
    for (const [name, config] of Object.entries(TARGETS)) {
        if (hookTarget(name, config)) {
            hooked++;
        }
    }

    console.log("\n[+] Hooked " + hooked + "/" + Object.keys(TARGETS).length + " targets");
    console.log("[*] Waiting for calls... (Ctrl+C to exit)");
} else {
    console.log("[-] Module not found. Make sure the game is running.");
}
