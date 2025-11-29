/**
 * BG3SE-macOS - Pattern Scanning Implementation
 */

#include "pattern_scan.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

// ============================================================================
// Pattern Parsing
// ============================================================================

BytePattern *parse_pattern(const char *pattern_str) {
    if (!pattern_str || !*pattern_str) return NULL;

    // First pass: count bytes
    size_t count = 0;
    const char *p = pattern_str;
    while (*p) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        // Check for wildcard or hex byte
        if (p[0] == '?' && p[1] == '?') {
            count++;
            p += 2;
        } else if ((p[0] >= '0' && p[0] <= '9') ||
                   (p[0] >= 'A' && p[0] <= 'F') ||
                   (p[0] >= 'a' && p[0] <= 'f')) {
            if ((p[1] >= '0' && p[1] <= '9') ||
                (p[1] >= 'A' && p[1] <= 'F') ||
                (p[1] >= 'a' && p[1] <= 'f')) {
                count++;
                p += 2;
            } else {
                return NULL;  // Invalid hex
            }
        } else if (*p) {
            return NULL;  // Invalid character
        }
    }

    if (count == 0) return NULL;

    // Allocate pattern structure
    BytePattern *pat = (BytePattern *)malloc(sizeof(BytePattern));
    if (!pat) return NULL;

    pat->bytes = (unsigned char *)malloc(count);
    pat->mask = (unsigned char *)malloc(count);
    pat->length = count;

    if (!pat->bytes || !pat->mask) {
        free(pat->bytes);
        free(pat->mask);
        free(pat);
        return NULL;
    }

    // Second pass: fill bytes and mask
    p = pattern_str;
    size_t i = 0;
    while (*p && i < count) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        if (p[0] == '?' && p[1] == '?') {
            pat->bytes[i] = 0x00;
            pat->mask[i] = 0x00;  // Wildcard
            p += 2;
            i++;
        } else {
            // Parse hex byte
            unsigned int byte = 0;
            sscanf(p, "%2x", &byte);
            pat->bytes[i] = (unsigned char)byte;
            pat->mask[i] = 0xFF;  // Must match
            p += 2;
            i++;
        }
    }

    return pat;
}

void free_pattern(BytePattern *pat) {
    if (pat) {
        free(pat->bytes);
        free(pat->mask);
        free(pat);
    }
}

// ============================================================================
// Pattern Scanning
// ============================================================================

void *find_pattern(const void *start, size_t size, const BytePattern *pattern) {
    if (!start || !pattern || size < pattern->length) return NULL;

    const unsigned char *base = (const unsigned char *)start;
    size_t scan_size = size - pattern->length + 1;

    for (size_t i = 0; i < scan_size; i++) {
        int found = 1;
        for (size_t j = 0; j < pattern->length; j++) {
            // Check if byte matches or is wildcard (mask == 0)
            if (pattern->mask[j] != 0x00 && base[i + j] != pattern->bytes[j]) {
                found = 0;
                break;
            }
        }
        if (found) {
            return (void *)&base[i];
        }
    }

    return NULL;
}

void *find_pattern_str(const void *start, size_t size, const char *pattern_str) {
    BytePattern *pat = parse_pattern(pattern_str);
    if (!pat) return NULL;

    void *result = find_pattern(start, size, pat);
    free_pattern(pat);
    return result;
}

// ============================================================================
// Mach-O Helpers
// ============================================================================

int get_macho_text_section(const char *image_name, void **start, size_t *size) {
    if (!start || !size) return 0;
    *start = NULL;
    *size = 0;

    // Find the image by name
    uint32_t image_count = _dyld_image_count();
    const struct mach_header_64 *header = NULL;
    intptr_t slide = 0;

    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, image_name)) {
            header = (const struct mach_header_64 *)_dyld_get_image_header(i);
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    if (!header) {
        return 0;  // Image not found
    }

    // Make sure it's a 64-bit Mach-O
    if (header->magic != MH_MAGIC_64) {
        return 0;
    }

    // Walk load commands to find __TEXT segment, then __text section
    const uint8_t *ptr = (const uint8_t *)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)ptr;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)ptr;

            if (strcmp(seg->segname, "__TEXT") == 0) {
                // Found __TEXT segment - now find __text section
                const struct section_64 *sections = (const struct section_64 *)(ptr + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sections[j].sectname, "__text") == 0) {
                        *start = (void *)(sections[j].addr + slide);
                        *size = sections[j].size;
                        return 1;
                    }
                }
                // If no __text section, use whole __TEXT segment
                *start = (void *)(seg->vmaddr + slide);
                *size = seg->vmsize;
                return 1;
            }
        }

        ptr += lc->cmdsize;
    }

    return 0;
}

void log_pattern_scan(const char *name, const char *pattern, void *result) {
    if (result) {
        log_message("[PatternScan] %s found at %p (pattern: %s)", name, result, pattern);
    } else {
        log_message("[PatternScan] %s NOT FOUND (pattern: %s)", name, pattern);
    }
}
