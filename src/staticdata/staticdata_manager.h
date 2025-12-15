/**
 * staticdata_manager.h - StaticData Manager for BG3SE-macOS
 *
 * Provides access to the game's static data managers for immutable game data:
 * Feats, Races, Backgrounds, Origins, Gods, Classes, and related types.
 *
 * Architecture:
 *   Unlike Windows BG3SE which uses eoc__gGuidResourceManager,
 *   macOS BG3 uses the ImmutableDataHeadmaster TypeContext pattern.
 *   Managers are captured via hooks on accessor functions and stored
 *   in a local registry for Lua access.
 *
 * Discovery (Dec 2025):
 *   - FeatManager accessed via Context.field_0x130
 *   - FeatManager::GetFeats at 0x101b752b4 (x1 = FeatManager*)
 *   - FeatManager structure: +0x7C = count, +0x80 = array ptr
 *   - Each Feat is 0x128 bytes
 */

#ifndef STATICDATA_MANAGER_H
#define STATICDATA_MANAGER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Static Data Types
// ============================================================================

/**
 * Enumeration of supported static data types.
 * Matches Windows BG3SE ExtResourceManagerType where applicable.
 */
typedef enum {
    STATICDATA_FEAT = 0,
    STATICDATA_RACE,
    STATICDATA_BACKGROUND,
    STATICDATA_ORIGIN,
    STATICDATA_GOD,
    STATICDATA_CLASS,
    STATICDATA_PROGRESSION,
    STATICDATA_ACTION_RESOURCE,
    STATICDATA_FEAT_DESCRIPTION,
    STATICDATA_COUNT  // Number of types
} StaticDataType;

/**
 * Static data entry (opaque pointer).
 * Actual structure varies by type (Feat, Race, etc.)
 */
typedef void* StaticDataPtr;

/**
 * GUID structure (16 bytes).
 */
typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t  data4[8];
} StaticDataGuid;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the static data manager.
 * Sets up hooks to capture manager pointers.
 *
 * @param main_binary_base Base address of the main game binary
 * @return true if initialization successful
 */
bool staticdata_manager_init(void *main_binary_base);

/**
 * Check if the static data system is ready.
 * Managers are captured lazily via hooks, so this checks if at least
 * one manager has been captured.
 *
 * @return true if at least one manager is available
 */
bool staticdata_manager_ready(void);

/**
 * Get the name of a static data type.
 *
 * @param type Static data type enum
 * @return Type name string (e.g., "Feat", "Race")
 */
const char* staticdata_type_name(StaticDataType type);

/**
 * Parse a type name to enum value.
 *
 * @param name Type name string
 * @return StaticDataType enum, or -1 if not found
 */
int staticdata_type_from_name(const char* name);

// ============================================================================
// Manager Access
// ============================================================================

/**
 * Check if a specific manager type is available.
 *
 * @param type Static data type
 * @return true if the manager has been captured
 */
bool staticdata_has_manager(StaticDataType type);

/**
 * Get the raw manager pointer for a type.
 *
 * @param type Static data type
 * @return Manager pointer, or NULL if not available
 */
void* staticdata_get_manager(StaticDataType type);

/**
 * Force capture of a manager by calling a known accessor function.
 * Used to eagerly populate the manager registry.
 *
 * @param type Static data type to capture
 * @return true if manager was captured
 */
bool staticdata_capture_manager(StaticDataType type);

// ============================================================================
// Data Access
// ============================================================================

/**
 * Get the count of entries for a static data type.
 *
 * @param type Static data type
 * @return Number of entries, or -1 on error
 */
int staticdata_get_count(StaticDataType type);

/**
 * Get a static data entry by index.
 *
 * @param type Static data type
 * @param index Entry index (0 to count-1)
 * @return Entry pointer, or NULL if out of bounds
 */
StaticDataPtr staticdata_get_by_index(StaticDataType type, int index);

/**
 * Get a static data entry by GUID.
 *
 * @param type Static data type
 * @param guid GUID to look up
 * @return Entry pointer, or NULL if not found
 */
StaticDataPtr staticdata_get_by_guid(StaticDataType type, const StaticDataGuid* guid);

/**
 * Get a static data entry by GUID string.
 *
 * @param type Static data type
 * @param guid_str GUID string (e.g., "e7ab823e-32b2-49f8-b7b3-7f9c2d4c1f5e")
 * @return Entry pointer, or NULL if not found
 */
StaticDataPtr staticdata_get_by_guid_string(StaticDataType type, const char* guid_str);

// ============================================================================
// Entry Property Access
// ============================================================================

/**
 * Get the GUID of a static data entry.
 *
 * @param type Static data type
 * @param entry Entry pointer
 * @param out_guid Output GUID structure
 * @return true if successful
 */
bool staticdata_get_guid(StaticDataType type, StaticDataPtr entry, StaticDataGuid* out_guid);

/**
 * Get the GUID of a static data entry as a string.
 *
 * @param type Static data type
 * @param entry Entry pointer
 * @param out_buf Output buffer for GUID string
 * @param buf_size Size of output buffer (should be >= 37)
 * @return true if successful
 */
bool staticdata_get_guid_string(StaticDataType type, StaticDataPtr entry, char* out_buf, size_t buf_size);

/**
 * Get the name of a static data entry.
 *
 * @param type Static data type
 * @param entry Entry pointer
 * @return Name string, or NULL if not available
 */
const char* staticdata_get_name(StaticDataType type, StaticDataPtr entry);

/**
 * Get the display name of a static data entry.
 *
 * @param type Static data type
 * @param entry Entry pointer
 * @return Display name (localized), or NULL if not available
 */
const char* staticdata_get_display_name(StaticDataType type, StaticDataPtr entry);

// ============================================================================
// Frida Capture Integration
// ============================================================================

/**
 * Load captured manager pointers from Frida capture file.
 * The Frida script (tools/frida/capture_featmanager_live.js) writes
 * manager pointers to /tmp/bg3se_featmanager.txt when triggered.
 *
 * Call this after running the Frida script and triggering feat selection.
 *
 * @return true if capture file was loaded successfully
 */
bool staticdata_load_frida_capture(void);

/**
 * Check if Frida capture is available (file exists).
 *
 * @return true if capture file exists
 */
bool staticdata_frida_capture_available(void);

// ============================================================================
// Debugging
// ============================================================================

/**
 * Try to capture managers via TypeContext traversal.
 * Alternative to hook-based capture, useful for debugging.
 * Also loads Frida capture if available.
 */
void staticdata_try_typecontext_capture(void);

/**
 * Dump static data manager status to log.
 */
void staticdata_dump_status(void);

/**
 * Dump all entries of a type to log.
 *
 * @param type Static data type to dump
 * @param max_entries Maximum entries to dump (-1 for all)
 */
void staticdata_dump_entries(StaticDataType type, int max_entries);

/**
 * Probe a manager for structure discovery.
 *
 * @param type Static data type to probe
 * @param probe_range Byte range to probe
 */
void staticdata_probe_manager(StaticDataType type, int probe_range);

#endif // STATICDATA_MANAGER_H
