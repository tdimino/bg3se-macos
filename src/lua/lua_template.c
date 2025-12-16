/**
 * lua_template.c - Lua bindings for Ext.Template API
 *
 * Provides Lua access to game object templates.
 *
 * API Surface:
 *   Ext.Template.Get(guid)              - Cascading search for template
 *   Ext.Template.GetRootTemplate(guid)  - Search GlobalTemplateBank
 *   Ext.Template.GetAllRootTemplates()  - Get all templates from GlobalTemplateBank
 *   Ext.Template.GetCount()             - Get template count
 *   Ext.Template.GetType(template)      - Get template type name
 *   Ext.Template.LoadFridaCapture()     - Load Frida capture file
 *   Ext.Template.DumpStatus()           - Debug: dump manager status
 */

#include "lua_template.h"
#include "../template/template_manager.h"
#include "../core/logging.h"
#include <lauxlib.h>
#include <string.h>
#include <stdlib.h>

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Push a template object to Lua as a table with properties.
 */
static int push_template_to_lua(lua_State* L, GameObjectTemplate* tmpl) {
    if (!tmpl) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);

    // Add pointer address (for debugging)
    lua_pushlightuserdata(L, tmpl);
    lua_setfield(L, -2, "_ptr");

    // Add GUID
    char guid_str[40];
    if (template_get_guid_string(tmpl, guid_str, sizeof(guid_str))) {
        lua_pushstring(L, guid_str);
        lua_setfield(L, -2, "Guid");
    }

    // Add FixedString IDs
    uint32_t id_fs = template_get_id_fs(tmpl);
    if (id_fs) {
        lua_pushinteger(L, id_fs);
        lua_setfield(L, -2, "TemplateId");
    }

    uint32_t name_fs = template_get_name_fs(tmpl);
    if (name_fs) {
        lua_pushinteger(L, name_fs);
        lua_setfield(L, -2, "NameId");
    }

    // Add type
    TemplateType type = template_get_type(tmpl);
    lua_pushstring(L, template_type_to_string(type));
    lua_setfield(L, -2, "Type");

    return 1;
}

// ============================================================================
// Lua API Functions
// ============================================================================

/**
 * Ext.Template.Get(guid)
 * Cascading search for a template by GUID string.
 * Searches: LocalCache -> Cache -> Local -> GlobalBank
 */
static int lua_template_get(lua_State* L) {
    const char* guid_str = luaL_checkstring(L, 1);

    GameObjectTemplate* tmpl = template_get(guid_str);
    return push_template_to_lua(L, tmpl);
}

/**
 * Ext.Template.GetRootTemplate(guid)
 * Get a template from GlobalTemplateBank only.
 */
static int lua_template_get_root(lua_State* L) {
    const char* guid_str = luaL_checkstring(L, 1);

    GameObjectTemplate* tmpl = template_get_by_guid(TEMPLATE_MANAGER_GLOBAL_BANK, guid_str);
    return push_template_to_lua(L, tmpl);
}

/**
 * Ext.Template.GetCacheTemplate(guid)
 * Get a template from CacheTemplateManager only.
 */
static int lua_template_get_cache(lua_State* L) {
    const char* guid_str = luaL_checkstring(L, 1);

    GameObjectTemplate* tmpl = template_get_by_guid(TEMPLATE_MANAGER_CACHE, guid_str);
    return push_template_to_lua(L, tmpl);
}

/**
 * Ext.Template.GetAllRootTemplates()
 * Returns an array of all templates in GlobalTemplateBank.
 */
static int lua_template_get_all_root(lua_State* L) {
    int count = template_get_count(TEMPLATE_MANAGER_GLOBAL_BANK);
    if (count < 0) {
        lua_newtable(L);  // Return empty table if not available
        return 1;
    }

    lua_createtable(L, count, 0);

    for (int i = 0; i < count; i++) {
        GameObjectTemplate* tmpl = template_get_by_index(TEMPLATE_MANAGER_GLOBAL_BANK, i);
        if (tmpl) {
            push_template_to_lua(L, tmpl);
            lua_rawseti(L, -2, i + 1);
        }
    }

    return 1;
}

/**
 * Ext.Template.GetAllCacheTemplates()
 * Returns an array of all templates in CacheTemplateManager.
 */
static int lua_template_get_all_cache(lua_State* L) {
    int count = template_get_count(TEMPLATE_MANAGER_CACHE);
    if (count < 0) {
        lua_newtable(L);
        return 1;
    }

    lua_createtable(L, count, 0);

    for (int i = 0; i < count; i++) {
        GameObjectTemplate* tmpl = template_get_by_index(TEMPLATE_MANAGER_CACHE, i);
        if (tmpl) {
            push_template_to_lua(L, tmpl);
            lua_rawseti(L, -2, i + 1);
        }
    }

    return 1;
}

/**
 * Ext.Template.GetCount([managerType])
 * Get template count from a manager.
 * @param managerType (optional) "Root", "Cache", "Local", "LocalCache"
 */
static int lua_template_get_count(lua_State* L) {
    TemplateManagerType mgr_type = TEMPLATE_MANAGER_GLOBAL_BANK;

    if (lua_gettop(L) >= 1 && lua_isstring(L, 1)) {
        const char* type_str = lua_tostring(L, 1);
        if (strcasecmp(type_str, "Root") == 0 || strcasecmp(type_str, "Global") == 0) {
            mgr_type = TEMPLATE_MANAGER_GLOBAL_BANK;
        } else if (strcasecmp(type_str, "Cache") == 0) {
            mgr_type = TEMPLATE_MANAGER_CACHE;
        } else if (strcasecmp(type_str, "Local") == 0) {
            mgr_type = TEMPLATE_MANAGER_LOCAL;
        } else if (strcasecmp(type_str, "LocalCache") == 0) {
            mgr_type = TEMPLATE_MANAGER_LOCAL_CACHE;
        }
    }

    int count = template_get_count(mgr_type);
    lua_pushinteger(L, count);
    return 1;
}

/**
 * Ext.Template.GetType(template)
 * Get the type of a template object.
 */
static int lua_template_get_type(lua_State* L) {
    // Check if first arg is a table with _ptr field
    if (!lua_istable(L, 1)) {
        return luaL_error(L, "Expected template object");
    }

    lua_getfield(L, 1, "_ptr");
    if (!lua_islightuserdata(L, -1)) {
        return luaL_error(L, "Template object has no _ptr");
    }

    GameObjectTemplate* tmpl = lua_touserdata(L, -1);
    lua_pop(L, 1);

    TemplateType type = template_get_type(tmpl);
    lua_pushstring(L, template_type_to_string(type));
    return 1;
}

/**
 * Ext.Template.IsReady()
 * Check if template manager is initialized and has data.
 */
static int lua_template_is_ready(lua_State* L) {
    lua_pushboolean(L, template_manager_ready());
    return 1;
}

/**
 * Ext.Template.LoadFridaCapture()
 * Load captured template manager pointers from Frida output.
 */
static int lua_template_load_frida(lua_State* L) {
    bool success = template_load_frida_capture();
    lua_pushboolean(L, success);
    return 1;
}

/**
 * Ext.Template.HasFridaCapture()
 * Check if Frida capture files exist.
 */
static int lua_template_has_frida(lua_State* L) {
    lua_pushboolean(L, template_frida_capture_available());
    return 1;
}

/**
 * Ext.Template.DumpStatus()
 * Debug function to dump manager status to log.
 */
static int lua_template_dump_status(lua_State* L) {
    template_dump_status();
    return 0;
}

/**
 * Ext.Template.DumpEntries([managerType], [maxEntries])
 * Debug function to dump template entries.
 */
static int lua_template_dump_entries(lua_State* L) {
    TemplateManagerType mgr_type = TEMPLATE_MANAGER_GLOBAL_BANK;
    int max_entries = 10;

    if (lua_gettop(L) >= 1 && lua_isstring(L, 1)) {
        const char* type_str = lua_tostring(L, 1);
        if (strcasecmp(type_str, "Root") == 0 || strcasecmp(type_str, "Global") == 0) {
            mgr_type = TEMPLATE_MANAGER_GLOBAL_BANK;
        } else if (strcasecmp(type_str, "Cache") == 0) {
            mgr_type = TEMPLATE_MANAGER_CACHE;
        }
    }

    if (lua_gettop(L) >= 2 && lua_isnumber(L, 2)) {
        max_entries = lua_tointeger(L, 2);
    }

    template_dump_entries(mgr_type, max_entries);
    return 0;
}

// ============================================================================
// Registration
// ============================================================================

static const struct luaL_Reg template_functions[] = {
    {"Get",                  lua_template_get},
    {"GetRootTemplate",      lua_template_get_root},
    {"GetCacheTemplate",     lua_template_get_cache},
    {"GetAllRootTemplates",  lua_template_get_all_root},
    {"GetAllCacheTemplates", lua_template_get_all_cache},
    {"GetCount",             lua_template_get_count},
    {"GetType",              lua_template_get_type},
    {"IsReady",              lua_template_is_ready},
    {"LoadFridaCapture",     lua_template_load_frida},
    {"HasFridaCapture",      lua_template_has_frida},
    {"DumpStatus",           lua_template_dump_status},
    {"DumpEntries",          lua_template_dump_entries},
    {NULL, NULL}
};

void lua_template_register(lua_State* L, int ext_table_index) {
    // Convert to absolute index before pushing new values
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Template table
    lua_newtable(L);

    // Register functions
    for (const struct luaL_Reg* func = template_functions; func->name; func++) {
        lua_pushcfunction(L, func->func);
        lua_setfield(L, -2, func->name);
    }

    // Set Ext.Template
    lua_setfield(L, ext_table_index, "Template");

    log_message("[Lua] Registered Ext.Template API");
}
