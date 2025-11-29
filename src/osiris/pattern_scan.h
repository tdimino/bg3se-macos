/**
 * BG3SE-macOS - Pattern Scanning Utilities
 *
 * Byte pattern matching for finding functions in memory.
 * Supports Ghidra/IDA style patterns like "48 8D 05 ?? ?? ?? ?? E8"
 */

#ifndef BG3SE_PATTERN_SCAN_H
#define BG3SE_PATTERN_SCAN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Pattern Structure
// ============================================================================

typedef struct {
    unsigned char *bytes;   // Pattern bytes to match
    unsigned char *mask;    // Mask: 0xFF = must match, 0x00 = wildcard
    size_t length;          // Pattern length
} BytePattern;

// ============================================================================
// Function Pattern (for fallback symbol resolution)
// ============================================================================

typedef struct {
    const char *name;           // Function name (for logging)
    const char *symbol;         // Mangled symbol name for dlsym
    const char *pattern;        // Unique byte pattern (body, not prologue)
    int pattern_offset;         // Offset from function start where pattern appears
} FunctionPattern;

// ============================================================================
// Pattern Parsing
// ============================================================================

/**
 * Parse a pattern string into a BytePattern structure.
 * Format: "48 8D 05 ?? ?? ?? ?? E8" where ?? = wildcard byte
 * Returns NULL on parse error. Caller must free with free_pattern().
 */
BytePattern *parse_pattern(const char *pattern_str);

/**
 * Free a BytePattern allocated by parse_pattern()
 */
void free_pattern(BytePattern *pat);

// ============================================================================
// Pattern Scanning
// ============================================================================

/**
 * Scan memory for a byte pattern.
 * Returns pointer to first match, or NULL if not found.
 */
void *find_pattern(const void *start, size_t size, const BytePattern *pattern);

/**
 * Convenience function: parse pattern string and scan in one call.
 * Returns pointer to first match, or NULL if not found.
 */
void *find_pattern_str(const void *start, size_t size, const char *pattern_str);

// ============================================================================
// Mach-O Helpers
// ============================================================================

/**
 * Get the __TEXT,__text section bounds from a loaded Mach-O image.
 * This is where code resides in the binary.
 * Returns 1 on success, 0 on failure.
 */
int get_macho_text_section(const char *image_name, void **start, size_t *size);

/**
 * Debug helper: Log a pattern scan result
 */
void log_pattern_scan(const char *name, const char *pattern, void *result);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_PATTERN_SCAN_H
