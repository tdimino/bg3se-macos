/**
 * capture_physics.js - Capture PhysicsScene pointer for Issue #37
 *
 * Usage:
 *   frida -U -n "Baldur's Gate 3" -l capture_physics.js
 *
 * The PhysicsScene is passed to the AiGrid constructor.
 * When you load a save or enter a new area, this will capture the pointer.
 */

const MODULE_NAME = "Baldur's Gate 3";

// AiGrid constructor receives PhysicsScene* as second argument
const AIGRID_CTOR_OFFSET = 0x10116fd20;

// Store captured values
var capturedPhysicsScene = null;

function main() {
    console.log("\n=== PhysicsScene Capture (Issue #37) ===\n");

    const base = Module.getBaseAddress(MODULE_NAME);
    if (!base) {
        console.log("[-] Could not find module. Is the game running?");
        return;
    }

    console.log("[*] Module base: " + base);

    const aiGridCtor = base.add(AIGRID_CTOR_OFFSET);
    console.log("[*] AiGrid::AiGrid at: " + aiGridCtor);

    Interceptor.attach(aiGridCtor, {
        onEnter: function(args) {
            const thisPtr = args[0];
            const physicsScene = args[1];

            if (physicsScene && !physicsScene.isNull()) {
                console.log("\n[+] AiGrid constructor called!");
                console.log("    this = " + thisPtr);
                console.log("    PhysicsScene* = " + physicsScene);

                if (!capturedPhysicsScene || !capturedPhysicsScene.equals(physicsScene)) {
                    capturedPhysicsScene = physicsScene;
                    console.log("\n    >>> NEW PhysicsScene captured! <<<");
                    console.log("    Offset from base: 0x" + physicsScene.sub(base).toString(16));

                    // Send to handler
                    send({
                        type: "physics_scene",
                        address: physicsScene.toString(),
                        offset: physicsScene.sub(base).toString(16)
                    });
                }
            }
        }
    });

    console.log("\n[*] Hook installed. Load a save or change areas to trigger.");
    console.log("[*] Press Ctrl+C to exit.\n");
}

// Message handler for bidirectional communication
recv('query', function(message) {
    if (message.type === 'get_physics_scene') {
        send({
            type: 'physics_scene_result',
            captured: capturedPhysicsScene ? capturedPhysicsScene.toString() : null
        });
    }
});

main();
