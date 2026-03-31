/**
 * BG3SE-macOS - Game Binary Version Detection
 *
 * Detects the BG3 game binary version and compares against the version
 * that our hardcoded addresses were extracted from. When mismatched,
 * address-dependent features are disabled to prevent crashes from
 * shifted offsets (Issue #73).
 */

#ifndef VERSION_DETECT_H
#define VERSION_DETECT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The game version our addresses were verified against.
 * All TypeId addresses, singleton pointers, and function offsets
 * in generated_typeids.h and component_typeid.c are for this version.
 */
#define BG3_KNOWN_VERSION "4.1.1.6995620"

/**
 * Detect the game binary version.
 * Reads CFBundleShortVersionString from BG3's Info.plist.
 * Falls back to scanning the binary for version patterns.
 *
 * @param app_bundle_path Path to the .app bundle (or NULL for auto-detect)
 * @return true if version was detected (check version_detect_get_version())
 */
bool version_detect_init(const char *app_bundle_path);

/**
 * Get the detected game version string.
 * Returns NULL if version_detect_init() hasn't been called or failed.
 */
const char *version_detect_get_version(void);

/**
 * Check if the detected version matches our known-good version.
 * Returns true if versions match or if detection failed (optimistic).
 */
bool version_detect_matches(void);

/**
 * Check if address-dependent features should be enabled.
 * Returns false when a version mismatch is confirmed, meaning
 * TypeId addresses, singleton pointers, etc. are likely wrong.
 */
bool version_detect_addresses_safe(void);

#ifdef __cplusplus
}
#endif

#endif // VERSION_DETECT_H
