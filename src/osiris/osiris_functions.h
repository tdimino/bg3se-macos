/**
 * BG3SE-macOS - Osiris Function Cache
 *
 * Caches Osiris function metadata (name, ID, arity, type) for fast lookup.
 * Supports both enumeration at init time and dynamic caching from events.
 */

#ifndef BG3SE_OSIRIS_FUNCTIONS_H
#define BG3SE_OSIRIS_FUNCTIONS_H

#include <stdint.h>
#include "osiris_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Configuration
// ============================================================================

#define MAX_CACHED_FUNCTIONS 4096
#define FUNC_HASH_SIZE 8192
#define FUNC_NAME_HASH_SIZE 8192
#define MAX_SEEN_FUNC_IDS 256

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the function cache system.
 * Must be called before using any other function cache operations.
 */
void osi_func_cache_init(void);

/**
 * Set the runtime pointers needed for function enumeration.
 * These come from dlsym on libOsiris.dylib.
 *
 * @param pFunctionData Pointer to pFunctionData function
 * @param ppOsiFunctionMan Pointer to global OsiFunctionMan pointer
 */
void osi_func_cache_set_runtime(pFunctionDataFn pFunctionData, void **ppOsiFunctionMan);

/**
 * Set the known events table for static event name lookups.
 * This is a null-terminated array of KnownEvent.
 */
void osi_func_cache_set_known_events(KnownEvent *events);

// ============================================================================
// Enumeration
// ============================================================================

/**
 * Enumerate all Osiris functions by probing ID ranges.
 * Call this after runtime pointers are set and game is initialized.
 */
void osi_func_enumerate(void);

/**
 * Walk the Osiris name index (CSearchIndex in COsiFunctionMan) and cache every
 * function by name — including databases (DB_*), which the id-probe in
 * osi_func_enumerate() cannot see. Call once the story/save is loaded so
 * Osi.DB_*:Get() can resolve. Idempotent; read-only.
 */
void osi_func_enumerate_by_name(void);

/**
 * Database registry (databases have OsiFunctionId==0 and cannot be id-cached).
 * osi_db_register: name -> COsiFunctionData* (returns 1 if newly added).
 * osi_db_lookup: returns the COsiFunctionData* for a DB name, or NULL.
 */
int   osi_db_register(const char *name, void *def);
void *osi_db_lookup(const char *name);
int   osi_db_count(void);

// ============================================================================
// Caching
// ============================================================================

/**
 * Cache a function with known metadata.
 * Used when we observe function calls and already know the details.
 */
void osi_func_cache(const char *name, uint32_t funcId, uint8_t arity, uint8_t type);

/**
 * Try to cache a function by probing its ID.
 * Uses pFunctionData to get metadata if available.
 * @return 1 if successfully cached, 0 otherwise
 */
int osi_func_cache_by_id(uint32_t funcId);

/**
 * Try to cache a function from an observed event.
 * Only caches if not already in cache.
 */
void osi_func_cache_from_event(uint32_t funcId);

// ============================================================================
// Lookup
// ============================================================================

/**
 * Get function name from function ID.
 * @return Function name, or NULL if not found
 */
const char *osi_func_get_name(uint32_t funcId);

/**
 * Look up function ID by name.
 * @return Function ID, or INVALID_FUNCTION_ID if not found
 */
uint32_t osi_func_lookup_id(const char *name);

/**
 * Get function info (arity and type) by name.
 * @return 1 on success, 0 if not found
 */
int osi_func_get_info(const char *name, uint8_t *out_arity, uint8_t *out_type);

/**
 * Get the encoded OsirisFunctionHandle for a function by name.
 * @return Encoded handle, or 0 if not found/not yet computed
 */
uint32_t osi_func_get_handle(const char *name);

/**
 * Set the encoded handle for a cached function.
 */
void osi_func_cache_set_handle(uint32_t funcId, uint32_t handle);

/**
 * Probe and dump OsiFunctionDef layout for the first N cached functions.
 * Writes hex dumps to log for offset discovery/validation.
 */
void osi_func_probe_layout(int count);

/**
 * Probe a function by name and print detailed info to console.
 * Shows cached arity/type/handle, known table match, and re-probes
 * the pointer chain (Signature→ParamList→Size) for live offset validation.
 * @param name Function name to probe
 * @param out Function pointer for console output (must not be NULL)
 */
void osi_func_probe_info(const char *name, void (*out)(const char *fmt, ...));

/**
 * Update a known event's function ID when discovered at runtime.
 * This fixes placeholder entries (funcId=0) in the known events table.
 */
void osi_func_update_known_event_id(const char *name, uint32_t funcId);

// ============================================================================
// Statistics
// ============================================================================

/**
 * Get the number of cached functions.
 */
int osi_func_get_cache_count(void);

/**
 * Track a seen function ID (for analysis/debugging).
 */
void osi_func_track_seen(uint32_t funcId, uint8_t arity);

/**
 * Get the count of unique function IDs seen.
 */
int osi_func_get_seen_count(void);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_OSIRIS_FUNCTIONS_H
