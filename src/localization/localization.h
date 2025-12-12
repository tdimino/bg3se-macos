/**
 * localization.h - Localization System for BG3SE-macOS
 *
 * Provides access to the game's TranslatedStringRepository for reading
 * localized game text.
 *
 * Architecture:
 *   ls::TranslatedStringRepository::m_ptr (global) -> Repository instance
 *   Repository contains HashMap<RuntimeStringHandle, StringView> for text lookup
 *
 * Localization handles are FixedString indices in the format:
 *   "h12345678g1234g4567g8901g123456789012"
 */

#ifndef LOCALIZATION_H
#define LOCALIZATION_H

#include <stdbool.h>
#include <stdint.h>

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the localization system.
 * Must be called after the game binary is loaded.
 *
 * @param main_binary_base Base address of the main game binary
 */
void localization_init(void *main_binary_base);

/**
 * Check if the localization system is ready.
 *
 * @return true if TranslatedStringRepository is accessible
 */
bool localization_ready(void);

// ============================================================================
// String Access
// ============================================================================

/**
 * Get a translated string by its handle.
 *
 * @param handle Localization handle string (e.g., "h12345678g1234g4567g8901g123456789012")
 * @param fallback Optional fallback text if handle not found (can be NULL)
 * @return Translated text, fallback if not found, or empty string if both fail
 */
const char* localization_get(const char *handle, const char *fallback);

/**
 * Update a translated string at runtime (session-only, not persisted).
 *
 * @param handle Localization handle string
 * @param value New translated text
 * @return true if successful, false on error
 */
bool localization_set(const char *handle, const char *value);

// ============================================================================
// Language Info
// ============================================================================

/**
 * Get the current game language.
 *
 * @return Language name (e.g., "English", "French", "German"), or "Unknown"
 */
const char* localization_get_language(void);

// ============================================================================
// Debugging
// ============================================================================

/**
 * Get the raw TranslatedStringRepository pointer (for debugging).
 *
 * @return Pointer to repository, or NULL if not ready
 */
void* localization_get_raw(void);

/**
 * Dump localization system info to log.
 */
void localization_dump_info(void);

#endif // LOCALIZATION_H
