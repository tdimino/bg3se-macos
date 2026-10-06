/*
 * Tier 0 tests for the untyped string write path in src/stats/stats_manager.c
 * (stats_set_string, behind StatsObject:SetRawAttribute and SetProperty).
 *
 * That path does not know what kind of value an attribute holds, so it may
 * add a new string to RPGStats.FixedStrings only for an attribute whose value
 * list is FixedString or StatusIDs. For any other attribute, or one whose type
 * cannot be resolved, a string not already in the pool is refused: the slot
 * and the pool stay as they were.
 *
 * The fixture is a fake RPGStats in process memory, reached through the
 * stubbed offset table (stub_stats_deps.c). Offsets mirror the private
 * #defines in stats_manager.c:
 *   RPGStats +0x000  ModifierValueLists CNamedElementManager (value-list registry)
 *   RPGStats +0x060  ModifierLists      CNamedElementManager
 *   RPGStats +0x348  FixedStrings       buf / cap @+0x08 / size @+0x0C
 *   CNamedElementManager: buf @+0x08, cap @+0x10, size @+0x14
 *   Modifier: EnumerationIndex @+0x00, Name @+0x0C;  value list: Name @+0x00
 *   stats::Object: IndexedProperties.begin/end @+0x08/+0x10, ModifierListIndex @+0xe4
 */

#include "test_harness.h"
#include "stats_manager.h"
#include "fixed_string.h"

#include <stdint.h>

extern void *g_stub_rpgstats_m_ptr;

#define CNEM_BUF   0x08
#define CNEM_CAP   0x10
#define CNEM_SIZE  0x14

#define RPGSTATS_VALUE_LISTS     0x000
#define RPGSTATS_MODIFIER_LISTS  0x060
#define RPGSTATS_FIXEDSTRINGS    0x348

#define MODIFIER_ENUM_INDEX  0x00
#define MODIFIER_NAME        0x0C

#define OBJECT_PROPS_BEGIN   0x08
#define OBJECT_PROPS_END     0x10
#define OBJECT_ML_INDEX      0xe4

#define SENTINEL       0x5a5a5a5a
#define POOL_CAPACITY  16
#define NEW_STRING     "BrandNewString"

enum { ATTR_CONDITIONS, ATTR_UNRESOLVED, ATTR_FIXEDSTRING, ATTR_STATUSIDS, ATTR_COUNT };

static const char *const k_attr_names[ATTR_COUNT] = {
    "ConditionsAttr", "UnresolvedAttr", "FixedStringAttr", "StatusIDsAttr",
};
// Value-list index per attribute; UnresolvedAttr points past the registry.
static const int32_t k_attr_types[ATTR_COUNT] = { 0, 99, 1, 2 };
static const char *const k_value_lists[] = { "Conditions", "FixedString", "StatusIDs" };
#define VALUE_LIST_COUNT 3

static uint8_t  g_rpgstats[0x400];
static uint8_t  g_modifier_list[0x40];
static void    *g_modifier_lists_buf[1];
static uint8_t  g_modifiers[ATTR_COUNT][0x20];
static void    *g_attrs_buf[ATTR_COUNT];
static uint8_t  g_value_lists[VALUE_LIST_COUNT][0x40];
static void    *g_value_lists_buf[VALUE_LIST_COUNT];
static uint32_t g_pool[POOL_CAPACITY];
static uint8_t  g_object[0x100];
static int32_t  g_props[ATTR_COUNT];

#define AT(base, off, type) (*(type *)((uint8_t *)(base) + (off)))

static uint32_t pool_size(void) {
    return AT(g_rpgstats, RPGSTATS_FIXEDSTRINGS + 0x0C, uint32_t);
}

static void setup(void) {
    memset(g_rpgstats, 0, sizeof(g_rpgstats));
    memset(g_modifier_list, 0, sizeof(g_modifier_list));
    memset(g_modifiers, 0, sizeof(g_modifiers));
    memset(g_value_lists, 0, sizeof(g_value_lists));
    memset(g_pool, 0, sizeof(g_pool));
    memset(g_object, 0, sizeof(g_object));

    // Value-list registry: Conditions, FixedString, StatusIDs
    for (int i = 0; i < VALUE_LIST_COUNT; i++) {
        AT(g_value_lists[i], 0x00, uint32_t) = fixed_string_intern(k_value_lists[i], -1);
        g_value_lists_buf[i] = g_value_lists[i];
    }
    AT(g_rpgstats, RPGSTATS_VALUE_LISTS + CNEM_BUF, void *) = g_value_lists_buf;
    AT(g_rpgstats, RPGSTATS_VALUE_LISTS + CNEM_CAP, uint32_t) = VALUE_LIST_COUNT;
    AT(g_rpgstats, RPGSTATS_VALUE_LISTS + CNEM_SIZE, uint32_t) = VALUE_LIST_COUNT;

    // One ModifierList holding one Modifier per attribute
    for (int i = 0; i < ATTR_COUNT; i++) {
        AT(g_modifiers[i], MODIFIER_ENUM_INDEX, int32_t) = k_attr_types[i];
        AT(g_modifiers[i], MODIFIER_NAME, uint32_t) = fixed_string_intern(k_attr_names[i], -1);
        g_attrs_buf[i] = g_modifiers[i];
    }
    AT(g_modifier_list, CNEM_BUF, void *) = g_attrs_buf;
    AT(g_modifier_list, CNEM_SIZE, uint32_t) = ATTR_COUNT;
    g_modifier_lists_buf[0] = g_modifier_list;
    AT(g_rpgstats, RPGSTATS_MODIFIER_LISTS + CNEM_BUF, void *) = g_modifier_lists_buf;
    AT(g_rpgstats, RPGSTATS_MODIFIER_LISTS + CNEM_SIZE, uint32_t) = 1;

    // FixedStrings pool: { null, "Existing" }
    g_pool[0] = fixed_string_intern("", -1);
    g_pool[1] = fixed_string_intern("Existing", -1);
    AT(g_rpgstats, RPGSTATS_FIXEDSTRINGS, void *) = g_pool;
    AT(g_rpgstats, RPGSTATS_FIXEDSTRINGS + 0x08, uint32_t) = POOL_CAPACITY;
    AT(g_rpgstats, RPGSTATS_FIXEDSTRINGS + 0x0C, uint32_t) = 2;

    // A stats object of ModifierList 0 with every slot set to a sentinel
    for (int i = 0; i < ATTR_COUNT; i++) g_props[i] = SENTINEL;
    AT(g_object, OBJECT_PROPS_BEGIN, void *) = g_props;
    AT(g_object, OBJECT_PROPS_END, void *) = g_props + ATTR_COUNT;
    AT(g_object, OBJECT_ML_INDEX, int32_t) = 0;

    g_stub_rpgstats_m_ptr = g_rpgstats;
    stats_manager_init((void *)0x1);   // m_ptr via the stubbed offset table
}

// A new string is refused, and the attribute is still writable with a string
// already in the pool -- so the refusal is the type rule, not a broken fixture.
static void assert_refuses_new_string(int attr) {
    setup();
    ASSERT_TRUE(stats_manager_ready());

    ASSERT_FALSE(stats_set_raw_attribute(g_object, k_attr_names[attr], NEW_STRING));
    ASSERT_EQ(g_props[attr], SENTINEL);
    ASSERT_EQ(pool_size(), 2);

    ASSERT_TRUE(stats_set_raw_attribute(g_object, k_attr_names[attr], "Existing"));
    ASSERT_EQ(g_props[attr], 1);
    ASSERT_EQ(pool_size(), 2);
}

static void assert_interns_new_string(int attr) {
    setup();
    ASSERT_TRUE(stats_manager_ready());

    ASSERT_TRUE(stats_set_raw_attribute(g_object, k_attr_names[attr], NEW_STRING));
    ASSERT_EQ(pool_size(), 3);
    ASSERT_EQ(g_props[attr], 2);
    ASSERT_STR_EQ(fixed_string_resolve(g_pool[2]), NEW_STRING);
}

TEST(conditions_attribute_refuses_new_string) {
    assert_refuses_new_string(ATTR_CONDITIONS);
}

TEST(unresolvable_attribute_refuses_new_string) {
    assert_refuses_new_string(ATTR_UNRESOLVED);
}

TEST(fixedstring_attribute_interns_new_string) {
    assert_interns_new_string(ATTR_FIXEDSTRING);
}

TEST(statusids_attribute_interns_new_string) {
    assert_interns_new_string(ATTR_STATUSIDS);
}

void register_stats_set_string_tests(void) {
    printf("Stats untyped string writes:\n");
    RUN_TEST(conditions_attribute_refuses_new_string);
    RUN_TEST(unresolvable_attribute_refuses_new_string);
    RUN_TEST(fixedstring_attribute_interns_new_string);
    RUN_TEST(statusids_attribute_interns_new_string);
}
