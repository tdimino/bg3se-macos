/**
 * Every component property must fit inside its layout's recorded size.
 *
 * A property past the end reads the neighbouring component's bytes as if they
 * were the field (WeaponComponent read 0x40 past its 0x50 bytes). The runtime
 * now refuses such reads (component_property_read_in_bounds); this sweep keeps
 * the tables from adding new ones. Widths come from component_field_type_width,
 * the same function the reader uses.
 *
 * KNOWN_OVERRUNS pins the current backlog; it may only go down.
 */

#include "test_harness.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wunused-variable"
#endif
#include "component_offsets.h"
#include "generated_property_defs.h"
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include <stdio.h>
#include <string.h>

#define KNOWN_OVERRUNS 0  /* 52 reachable before these layouts were corrected */

static int count_overruns(const ComponentLayoutDef *layout, int print) {
    int n = 0;
    if (!layout || layout->componentSize == 0) return 0;
    for (int i = 0; i < layout->propertyCount; i++) {
        const ComponentPropertyDef *p = &layout->properties[i];
        size_t w = component_field_type_width(p);
        if ((size_t)p->offset > layout->componentSize ||
            w > (size_t)layout->componentSize - p->offset) {
            if (print) {
                printf("    overrun: %s.%s [0x%x, 0x%zx) > size 0x%x\n",
                       layout->componentName, p->name, p->offset,
                       (size_t)p->offset + w, layout->componentSize);
            }
            n++;
        }
    }
    return n;
}

static int shadowed_by_hand_layout(const ComponentLayoutDef *gen) {
    for (int i = 0; g_AllComponentLayouts[i] != NULL; i++) {
        if (strcmp(g_AllComponentLayouts[i]->componentName, gen->componentName) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Mirrors component_property_init: a generated layout whose name already has
 * a hand-written layout is never registered, so it is never read. */
static int sweep(int print) {
    int total = 0;
    for (int i = 0; g_AllComponentLayouts[i] != NULL; i++) {
        total += count_overruns(g_AllComponentLayouts[i], print);
    }
    for (int i = 0; i < GENERATED_COMPONENT_COUNT; i++) {
        const ComponentLayoutDef *gen = g_GeneratedComponentLayouts[i];
        if (gen && !shadowed_by_hand_layout(gen)) {
            total += count_overruns(gen, print);
        }
    }
    return total;
}

TEST(component_properties_stay_inside_their_component) {
    int n = sweep(0);
    if (n > KNOWN_OVERRUNS) {
        sweep(1);
    }
    ASSERT_TRUE(n <= KNOWN_OVERRUNS);
}

TEST(overrun_pin_is_not_loose) {
    /* A pin above reality would let new overruns in unnoticed. */
    ASSERT_TRUE(sweep(0) == KNOWN_OVERRUNS);
}

TEST(weapon_component_fits_after_its_fix) {
    ASSERT_TRUE(count_overruns(&g_WeaponComponent_Layout, 1) == 0);
}

void register_component_bounds_tests(void);
void register_component_bounds_tests(void) {
    RUN_TEST(component_properties_stay_inside_their_component);
    RUN_TEST(overrun_pin_is_not_loose);
    RUN_TEST(weapon_component_fits_after_its_fix);
}
