/*
 * BG3SE-macOS Enum Registry Implementation
 */

#include "enum_registry.h"
#include <lauxlib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Global registry
static EnumTypeInfo g_EnumTypes[ENUM_MAX_TYPES];
static int g_EnumTypeCount = 0;
static bool g_Initialized = false;

// ============================================================================
// Registry Implementation
// ============================================================================

void enum_registry_init(void) {
    if (g_Initialized) return;

    memset(g_EnumTypes, 0, sizeof(g_EnumTypes));
    g_EnumTypeCount = 0;
    g_Initialized = true;
}

int enum_registry_add_type(const char *name, bool is_bitfield) {
    if (!g_Initialized || !name) return -1;
    if (g_EnumTypeCount >= ENUM_MAX_TYPES) return -1;

    // Check for duplicate
    for (int i = 0; i < g_EnumTypeCount; i++) {
        if (g_EnumTypes[i].name && strcmp(g_EnumTypes[i].name, name) == 0) {
            return -1;  // Already exists
        }
    }

    int idx = g_EnumTypeCount++;
    EnumTypeInfo *info = &g_EnumTypes[idx];

    info->name = strdup(name);
    info->value_count = 0;
    info->registry_index = idx;
    info->is_bitfield = is_bitfield;
    info->allowed_flags = 0;

    return idx;
}

bool enum_registry_add_value(int type_index, const char *label, uint64_t value) {
    if (!g_Initialized) return false;
    if (type_index < 0 || type_index >= g_EnumTypeCount) return false;
    if (!label) return false;

    EnumTypeInfo *info = &g_EnumTypes[type_index];
    if (info->value_count >= ENUM_MAX_VALUES) return false;

    // Check for duplicate label
    for (int i = 0; i < info->value_count; i++) {
        if (info->values[i].label && strcmp(info->values[i].label, label) == 0) {
            return false;  // Label already exists
        }
    }

    int idx = info->value_count++;
    info->values[idx].label = strdup(label);
    info->values[idx].value = value;

    // Update allowed_flags for bitfields
    if (info->is_bitfield) {
        info->allowed_flags |= value;
    }

    return true;
}

EnumTypeInfo* enum_registry_get(int type_index) {
    if (!g_Initialized) return NULL;
    if (type_index < 0 || type_index >= g_EnumTypeCount) return NULL;
    return &g_EnumTypes[type_index];
}

EnumTypeInfo* enum_registry_find_by_name(const char *name) {
    if (!g_Initialized || !name) return NULL;

    for (int i = 0; i < g_EnumTypeCount; i++) {
        if (g_EnumTypes[i].name && strcmp(g_EnumTypes[i].name, name) == 0) {
            return &g_EnumTypes[i];
        }
    }
    return NULL;
}

int enum_registry_get_count(void) {
    return g_Initialized ? g_EnumTypeCount : 0;
}

const char* enum_find_label(int type_index, uint64_t value) {
    EnumTypeInfo *info = enum_registry_get(type_index);
    if (!info) return NULL;

    // For enums, do exact match
    // For bitfields with single bits, also do exact match
    for (int i = 0; i < info->value_count; i++) {
        if (info->values[i].value == value) {
            return info->values[i].label;
        }
    }
    return NULL;
}

int64_t enum_find_value(int type_index, const char *label) {
    EnumTypeInfo *info = enum_registry_get(type_index);
    if (!info || !label) return -1;

    for (int i = 0; i < info->value_count; i++) {
        if (info->values[i].label && strcmp(info->values[i].label, label) == 0) {
            return (int64_t)info->values[i].value;
        }
    }
    return -1;
}

// ============================================================================
// Lua Userdata Helpers
// ============================================================================

void enum_push(lua_State *L, uint64_t value, int type_index) {
    EnumUserdata *ud = (EnumUserdata*)lua_newuserdata(L, sizeof(EnumUserdata));
    ud->value = value;
    ud->type_index = (int16_t)type_index;
    ud->_padding = 0;
    ud->_reserved = 0;
    luaL_getmetatable(L, ENUM_METATABLE);
    lua_setmetatable(L, -2);
}

void bitfield_push(lua_State *L, uint64_t value, int type_index) {
    BitfieldUserdata *ud = (BitfieldUserdata*)lua_newuserdata(L, sizeof(BitfieldUserdata));
    ud->value = value;
    ud->type_index = (int16_t)type_index;
    ud->_padding = 0;
    ud->_reserved = 0;
    luaL_getmetatable(L, BITFIELD_METATABLE);
    lua_setmetatable(L, -2);
}
