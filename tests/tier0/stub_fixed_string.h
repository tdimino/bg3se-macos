/*
 * Tier 0 test seam for FixedString resolution.
 *
 * The component read path (src/entity/component_property.c) turns a 4-byte
 * GlobalStringTable index into a string via fixed_string_resolve(). Tier 0 has
 * no game process and therefore no string table, so this stub stands in for the
 * real resolver and serves a tiny table the test controls. That keeps the
 * DECISION under test — index -> resolve attempt -> string, or the documented
 * fallback when it does not resolve — while the table lookup itself (which needs
 * the live game) stays out of scope.
 */

#ifndef BG3SE_TEST_STUB_FIXED_STRING_H
#define BG3SE_TEST_STUB_FIXED_STRING_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t index;
    const char *str;
} StubFixedStringEntry;

/* Install the table the stubbed resolver answers from. Pass count 0 to make
 * every index unresolvable (models a string table that is not up yet). */
void stub_fixed_string_set_table(const StubFixedStringEntry *entries, size_t count);

/* Number of fixed_string_resolve() calls since the last set_table(). */
unsigned stub_fixed_string_resolve_calls(void);

#endif /* BG3SE_TEST_STUB_FIXED_STRING_H */
