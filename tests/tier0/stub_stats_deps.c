/*
 * Stub implementations of stats_manager.c's external dependencies for Tier 0.
 *
 * The GlobalStringTable is a small in-process table: fixed_string_intern adds
 * a string and returns its index, fixed_string_resolve reads it back. The
 * offset table resolves RPGStats::m_ptr to g_stub_rpgstats_m_ptr, which a
 * test points at a fake RPGStats before calling stats_manager_init. Every
 * other dependency is inert.
 */

#include "fixed_string.h"
#include "offset_table.h"
#include "version_detect.h"
#include "game_state.h"
#include "prototype_managers.h"

#include <stdio.h>
#include <string.h>

void *g_stub_rpgstats_m_ptr = NULL;

// ---------------------------------------------------------------------------
// GlobalStringTable
// ---------------------------------------------------------------------------

#define STUB_GST_MAX 64

static char g_gst[STUB_GST_MAX][64];
static uint32_t g_gst_count = 0;

void fixed_string_init(void *main_binary_base) { (void)main_binary_base; }
bool fixed_string_is_ready(void) { return true; }
bool fixed_string_intern_ready(void) { return true; }

const char *fixed_string_resolve(uint32_t index) {
    return index < g_gst_count ? g_gst[index] : NULL;
}

uint32_t fixed_string_intern(const char *str, int len) {
    (void)len;
    if (!str) return FS_NULL_INDEX;
    for (uint32_t i = 0; i < g_gst_count; i++) {
        if (strcmp(g_gst[i], str) == 0) return i;
    }
    if (g_gst_count >= STUB_GST_MAX) return FS_NULL_INDEX;
    snprintf(g_gst[g_gst_count], sizeof(g_gst[0]), "%s", str);
    return g_gst_count++;
}

// ---------------------------------------------------------------------------
// Offset table: RPGStats::m_ptr only
// ---------------------------------------------------------------------------

static const VersionOffsets g_stub_offsets = { .rpgstats_ptr = 1 };

const VersionOffsets *offset_table_get(void) { return &g_stub_offsets; }

void *offset_table_resolve(uintptr_t offset) {
    return offset == g_stub_offsets.rpgstats_ptr ? (void *)&g_stub_rpgstats_m_ptr : NULL;
}

void *offset_table_game_fn(GameFunctionId id) { (void)id; return NULL; }

// ---------------------------------------------------------------------------
// Inert
// ---------------------------------------------------------------------------

const char *version_detect_get_version(void) { return "tier0"; }
bool version_detect_matches(void) { return false; }

ServerGameState game_state_get_current(void) { return (ServerGameState)0; }
const char *game_state_get_name(ServerGameState state) { (void)state; return "tier0"; }

bool prototype_managers_ready(void) { return false; }
bool sync_stat_prototype(StatsObjectPtr obj, const char *name, const char *type) {
    (void)obj; (void)name; (void)type;
    return false;
}
