/**
 * Frida script to capture FeatManager pointer during gameplay.
 * Run with: frida -U -n "Baldur's Gate 3" -l capture_featmanager_live.js
 *
 * Hooks GetFeats to capture the real FeatManager pointer.
 */

// Offsets (from Ghidra)
const OFFSET_GETFEATS = 0x01b752b4;  // FeatManager::GetFeats

// FeatManager structure offsets
const FEATMANAGER_COUNT_OFFSET = 0x7C;
const FEATMANAGER_ARRAY_OFFSET = 0x80;
const FEAT_SIZE = 0x128;  // 296 bytes per feat
const FEAT_GUID_OFFSET = 0x08;  // GUID at +0x08 (after VMT)

// Find main binary base (look for "Baldur's Gate 3" or the main executable)
var mainModule = null;
Process.enumerateModules().forEach(function(mod) {
    if (mod.name.indexOf("Baldur") !== -1 && mod.name.indexOf(".dylib") === -1) {
        mainModule = mod;
    }
});

if (!mainModule) {
    // Fallback: find largest module (usually the main binary)
    var largest = null;
    Process.enumerateModules().forEach(function(mod) {
        if (!largest || mod.size > largest.size) {
            largest = mod;
        }
    });
    mainModule = largest;
}

console.log("[*] Main module: " + mainModule.name + " @ " + mainModule.base + " (size: " + mainModule.size + ")");

var getFeatsAddr = mainModule.base.add(OFFSET_GETFEATS);
console.log("[*] GetFeats at: " + getFeatsAddr);

var capturedFeatManager = null;

Interceptor.attach(getFeatsAddr, {
    onEnter: function(args) {
        // x0 = output buffer, x1 = FeatManager*
        var featMgr = args[1];

        if (featMgr && !featMgr.isNull()) {
            console.log("\n[+] GetFeats called with FeatManager: " + featMgr);

            // Read count and array
            var count = featMgr.add(FEATMANAGER_COUNT_OFFSET).readU32();
            var array = featMgr.add(FEATMANAGER_ARRAY_OFFSET).readPointer();

            console.log("[+] FeatManager structure:");
            console.log("    count@+0x7C = " + count);
            console.log("    array@+0x80 = " + array);

            if (count > 0 && count < 1000 && !array.isNull()) {
                capturedFeatManager = featMgr;
                console.log("[+] Valid FeatManager captured!");

                // Dump first 3 feats
                console.log("\n[+] First 3 feats:");
                for (var i = 0; i < Math.min(3, count); i++) {
                    var featPtr = array.add(i * FEAT_SIZE);
                    var guidPtr = featPtr.add(FEAT_GUID_OFFSET);

                    // Read GUID bytes
                    var guidBytes = guidPtr.readByteArray(16);
                    var guidHex = hexdump(guidBytes, {header: false, ansi: false}).split('\n')[0];

                    console.log("    Feat[" + i + "] @ " + featPtr + " GUID: " + guidHex);
                }

                // Write pointer to file for BG3SE to read
                // Format: Line 1 = FeatManager ptr, Line 2 = count, Line 3 = array ptr
                var outputPath = "/tmp/bg3se_featmanager.txt";
                var file = new File(outputPath, "w");
                file.write(featMgr.toString() + "\n");  // e.g., "0x600012345678"
                file.write(count.toString() + "\n");     // e.g., "37"
                file.write(array.toString() + "\n");     // e.g., "0x600098765432"
                file.close();
                console.log("\n[+] Wrote FeatManager info to " + outputPath);
                console.log("[+] In BG3SE console, run: Ext.StaticData.LoadFridaCapture()");
                console.log("[+] Then: Ext.StaticData.GetAll('Feat') will return real data");
            }
        }
    }
    // No onLeave - let function execute normally
});

console.log("\n[*] Hook installed. Click on feats in respec to trigger capture.");
console.log("[*] Press Ctrl+C to detach.\n");
