/*
 * Stub implementation of the fixed_string.h surface used by
 * src/entity/component_property.c. See stub_fixed_string.h for why.
 */

#include "stub_fixed_string.h"
#include "../../src/strings/fixed_string.h"

static const StubFixedStringEntry *g_entries = NULL;
static size_t g_count = 0;
static unsigned g_calls = 0;

void stub_fixed_string_set_table(const StubFixedStringEntry *entries, size_t count) {
    g_entries = entries;
    g_count = count;
    g_calls = 0;
}

unsigned stub_fixed_string_resolve_calls(void) {
    return g_calls;
}

const char *fixed_string_resolve(uint32_t index) {
    g_calls++;
    /* Mirrors the real resolver's contract: NULL for the null index and for
     * anything the table does not hold. */
    if (index == FS_NULL_INDEX) return NULL;
    for (size_t i = 0; i < g_count; i++) {
        if (g_entries[i].index == index) return g_entries[i].str;
    }
    return NULL;
}

bool fixed_string_is_valid(uint32_t index) { return index != FS_NULL_INDEX; }
bool fixed_string_is_ready(void) { return g_count > 0; }
bool fixed_string_intern_ready(void) { return false; }
uint32_t fixed_string_intern(const char *str, int len) {
    (void)str; (void)len;
    return FS_NULL_INDEX;
}
