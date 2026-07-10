/**
 * BG3SE-macOS - Ext.Mod Lua Bindings Implementation
 *
 * Provides mod information and query functions.
 *
 * Issue #6: NetChannel API dependency
 */

#include "lua_mod.h"
#include "../mod/mod_loader.h"
#include "../core/logging.h"

#include <lauxlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// ============================================================================
// Static State: UUID to Name Mapping
// ============================================================================

#define MAX_MOD_UUIDS 128
#define UUID_LEN 64

typedef struct {
    char uuid[UUID_LEN];
    char name[256];
    char folder[256];       // meta Folder (== pak internal dir); Directory for Info
    char version64[32];     // packed int64 version string, decoded into Info.ModVersion
} ModUuidEntry;

static ModUuidEntry g_mod_uuids[MAX_MOD_UUIDS];
static int g_mod_uuid_count = 0;
static bool g_uuids_loaded = false;

/**
 * Parse modsettings.lsx to extract UUID -> Name mapping.
 */
static void load_mod_uuids(void) {
    if (g_uuids_loaded) return;
    // Don't set g_uuids_loaded until we successfully parse

    const char *home = getenv("HOME");
    if (!home) return;

    char path[1024];
    snprintf(path, sizeof(path),
             "%s/Documents/Larian Studios/Baldur's Gate 3/PlayerProfiles/Public/modsettings.lsx",
             home);

    FILE *f = fopen(path, "r");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 10 * 1024 * 1024) {
        fclose(f);
        return;
    }

    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return;
    }

    size_t bytes_read = fread(content, 1, size, f);
    fclose(f);

    if (bytes_read != (size_t)size) {
        // Partial read - don't use potentially garbage data
        free(content);
        return;
    }
    content[size] = '\0';

    // Parse each ModuleShortDesc node
    // Structure: <node id="ModuleShortDesc">
    //              <attribute id="UUID" type="FixedString" value="..."/>
    //              <attribute id="Name" type="LSString" value="..."/>
    //            </node>

    const char *node_start = content;
    while ((node_start = strstr(node_start, "<node id=\"ModuleShortDesc\">")) != NULL) {
        // Find the closing </node>
        const char *node_end = strstr(node_start, "</node>");
        if (!node_end) break;

        // Extract UUID — accept both type="FixedString" (legacy) and type="guid" (BG3MacModManager)
        const char *uuid_marker_fs = "attribute id=\"UUID\" type=\"FixedString\" value=\"";
        const char *uuid_marker_guid = "attribute id=\"UUID\" type=\"guid\" value=\"";
        const char *uuid_start = strstr(node_start, uuid_marker_fs);
        size_t uuid_marker_len = strlen(uuid_marker_fs);
        if (!uuid_start || uuid_start >= node_end) {
            uuid_start = strstr(node_start, uuid_marker_guid);
            uuid_marker_len = strlen(uuid_marker_guid);
        }
        char uuid[UUID_LEN] = "";

        if (uuid_start && uuid_start < node_end) {
            uuid_start += uuid_marker_len;
            const char *uuid_end = strchr(uuid_start, '"');
            if (uuid_end && uuid_end < node_end) {
                size_t len = uuid_end - uuid_start;
                if (len < UUID_LEN) {
                    strncpy(uuid, uuid_start, len);
                    uuid[len] = '\0';
                }
            }
        }

        // Extract Name
        const char *name_marker = "attribute id=\"Name\" type=\"LSString\" value=\"";
        const char *name_start = strstr(node_start, name_marker);
        char name[256] = "";

        if (name_start && name_start < node_end) {
            name_start += strlen(name_marker);
            const char *name_end = strchr(name_start, '"');
            if (name_end && name_end < node_end) {
                size_t len = name_end - name_start;
                if (len < sizeof(name)) {
                    strncpy(name, name_start, len);
                    name[len] = '\0';
                }
            }
        }

        // Extract Folder (pak internal directory) and Version64
        const char *folder_marker = "attribute id=\"Folder\" type=\"LSString\" value=\"";
        const char *folder_start = strstr(node_start, folder_marker);
        char folder[256] = "";
        if (folder_start && folder_start < node_end) {
            folder_start += strlen(folder_marker);
            const char *fe = strchr(folder_start, '"');
            if (fe && fe < node_end) {
                size_t len = fe - folder_start;
                if (len < sizeof(folder)) { strncpy(folder, folder_start, len); folder[len] = '\0'; }
            }
        }

        const char *ver_marker = "attribute id=\"Version64\" type=\"int64\" value=\"";
        const char *ver_start = strstr(node_start, ver_marker);
        char version64[32] = "";
        if (ver_start && ver_start < node_end) {
            ver_start += strlen(ver_marker);
            const char *ve = strchr(ver_start, '"');
            if (ve && ve < node_end) {
                size_t len = ve - ver_start;
                if (len < sizeof(version64)) { strncpy(version64, ver_start, len); version64[len] = '\0'; }
            }
        }

        // Store if both found
        if (uuid[0] && name[0] && g_mod_uuid_count < MAX_MOD_UUIDS) {
            ModUuidEntry *e = &g_mod_uuids[g_mod_uuid_count];
            strncpy(e->uuid, uuid, UUID_LEN - 1);   e->uuid[UUID_LEN - 1] = '\0';
            strncpy(e->name, name, 255);            e->name[255] = '\0';
            strncpy(e->folder, folder, 255);        e->folder[255] = '\0';
            strncpy(e->version64, version64, 31);   e->version64[31] = '\0';
            g_mod_uuid_count++;
        }

        node_start = node_end;
    }

    free(content);

    // Only mark as loaded after successful parse
    g_uuids_loaded = true;

    LOG_MOD_DEBUG("Loaded %d mod UUID mappings", g_mod_uuid_count);
}

/**
 * Find mod name by UUID.
 */
static const char *find_mod_by_uuid(const char *uuid) {
    load_mod_uuids();

    for (int i = 0; i < g_mod_uuid_count; i++) {
        if (strcasecmp(g_mod_uuids[i].uuid, uuid) == 0) {
            return g_mod_uuids[i].name;
        }
    }
    return NULL;
}

// ============================================================================
// Lua Functions
// ============================================================================

/**
 * Ext.Mod.IsModLoaded(modGuid) -> boolean
 *
 * Check if a mod is loaded by its UUID or name.
 */
static int lua_mod_is_mod_loaded(lua_State *L) {
    const char *mod_id = luaL_checkstring(L, 1);

    // Try as UUID first
    const char *mod_name = find_mod_by_uuid(mod_id);
    if (mod_name) {
        // Found by UUID - mod is loaded
        lua_pushboolean(L, 1);
        return 1;
    }

    // Try as name
    int count = mod_get_detected_count();
    for (int i = 0; i < count; i++) {
        const char *name = mod_get_detected_name(i);
        if (name && strcasecmp(name, mod_id) == 0) {
            lua_pushboolean(L, 1);
            return 1;
        }
    }

    lua_pushboolean(L, 0);
    return 1;
}

/**
 * Ext.Mod.GetLoadOrder() -> table
 *
 * Returns array of mod UUIDs in load order.
 */
static int lua_mod_get_load_order(lua_State *L) {
    load_mod_uuids();

    lua_newtable(L);

    for (int i = 0; i < g_mod_uuid_count; i++) {
        lua_pushstring(L, g_mod_uuids[i].uuid);
        lua_rawseti(L, -2, i + 1);
    }

    return 1;
}

/**
 * Push a mod object matching the real BG3SE shape: a top-level table plus a
 * nested `Info` (ModuleInfo) table. SE libraries (CommunityLibrary, MCM,
 * CompatibilityFramework) read mod.Info.ModVersion / .Directory / .ModuleUUID;
 * a missing Info table aborted their bootstraps.
 */
static void push_mod_table(lua_State *L, const ModUuidEntry *e) {
    const char *dir = e->folder[0] ? e->folder : e->name;

    lua_newtable(L);  // mod

    lua_pushstring(L, e->uuid);  lua_setfield(L, -2, "UUID");
    lua_pushstring(L, e->name);  lua_setfield(L, -2, "Name");
    lua_pushstring(L, dir);      lua_setfield(L, -2, "Directory");

    int se_count = mod_get_se_count();
    bool is_se = false;
    for (int j = 0; j < se_count; j++) {
        const char *sn = mod_get_se_name(j);
        if (sn && (strcasecmp(sn, e->name) == 0 ||
                   (e->folder[0] && strcasecmp(sn, e->folder) == 0))) {
            is_se = true;
            break;
        }
    }
    lua_pushboolean(L, is_se);  lua_setfield(L, -2, "HasScriptExtender");

    // Info (ModuleInfo) sub-table — what SE libraries actually read.
    lua_newtable(L);  // Info
    lua_pushstring(L, e->name);  lua_setfield(L, -2, "Name");
    lua_pushstring(L, dir);      lua_setfield(L, -2, "Directory");
    lua_pushstring(L, e->uuid);  lua_setfield(L, -2, "ModuleUUID");
    lua_pushstring(L, "");       lua_setfield(L, -2, "Author");
    lua_pushstring(L, "");       lua_setfield(L, -2, "Description");

    // ModVersion, decoded from the packed int64 (Norbyte layout):
    // Major:7 (>>55) Minor:8 (>>47) Revision:16 (>>31) Build:31 (low).
    uint64_t v = e->version64[0] ? strtoull(e->version64, NULL, 10) : 0;
    lua_Integer major = (lua_Integer)((v >> 55) & 0x7f);
    lua_Integer minor = (lua_Integer)((v >> 47) & 0xff);
    lua_Integer revision = (lua_Integer)((v >> 31) & 0xffff);
    lua_Integer build = (lua_Integer)(v & 0x7fffffff);
    lua_newtable(L);  // ModVersion
    // Array form ModVersion[1..4] — this is what mods (MCM, CommunityLibrary)
    // actually read (e.g. string.format("%d.%d.%d.%d", ModVersion[1], ...)).
    // A missing [1] made string.format throw and aborted MCM's CreateModMenu,
    // which is why UIReady never fired (window auto-opened, content stayed empty).
    lua_pushinteger(L, major);    lua_rawseti(L, -2, 1);
    lua_pushinteger(L, minor);    lua_rawseti(L, -2, 2);
    lua_pushinteger(L, revision); lua_rawseti(L, -2, 3);
    lua_pushinteger(L, build);    lua_rawseti(L, -2, 4);
    // Named fields too, for consumers that use them.
    lua_pushinteger(L, major);    lua_setfield(L, -2, "Major");
    lua_pushinteger(L, minor);    lua_setfield(L, -2, "Minor");
    lua_pushinteger(L, revision); lua_setfield(L, -2, "Revision");
    lua_pushinteger(L, build);    lua_setfield(L, -2, "Build");
    lua_setfield(L, -2, "ModVersion");

    lua_newtable(L);  lua_setfield(L, -2, "Dependencies");

    lua_setfield(L, -2, "Info");  // mod.Info = Info
}

/**
 * Ext.Mod.GetMod(modGuid) -> table|nil
 *
 * Get mod information by UUID.
 */
static int lua_mod_get_mod(lua_State *L) {
    const char *uuid = luaL_checkstring(L, 1);

    load_mod_uuids();

    for (int i = 0; i < g_mod_uuid_count; i++) {
        if (strcasecmp(g_mod_uuids[i].uuid, uuid) == 0) {
            push_mod_table(L, &g_mod_uuids[i]);
            return 1;
        }
    }

    lua_pushnil(L);
    return 1;
}

/**
 * Ext.Mod.GetBaseMod() -> table
 *
 * Get the base game mod (GustavX).
 */
static int lua_mod_get_base_mod(lua_State *L) {
    load_mod_uuids();

    for (int i = 0; i < g_mod_uuid_count; i++) {
        if (strcmp(g_mod_uuids[i].name, "GustavX") == 0) {
            lua_newtable(L);

            lua_pushstring(L, g_mod_uuids[i].uuid);
            lua_setfield(L, -2, "UUID");

            lua_pushstring(L, g_mod_uuids[i].name);
            lua_setfield(L, -2, "Name");

            return 1;
        }
    }

    // Return empty table if not found
    lua_newtable(L);
    return 1;
}

/**
 * Ext.Mod.GetModManager() -> userdata (stub)
 *
 * Returns a placeholder - full implementation would need game memory access.
 */
static int lua_mod_get_mod_manager(lua_State *L) {
    // Return a table with basic info for now
    lua_newtable(L);

    lua_pushinteger(L, g_mod_uuid_count);
    lua_setfield(L, -2, "ModCount");

    return 1;
}

// ============================================================================
// Public API
// ============================================================================

bool lua_mod_is_loaded(const char *mod_uuid) {
    const char *mod_name = find_mod_by_uuid(mod_uuid);
    if (mod_name) {
        return true;
    }

    // Try as name
    int count = mod_get_detected_count();
    for (int i = 0; i < count; i++) {
        const char *name = mod_get_detected_name(i);
        if (name && strcasecmp(name, mod_uuid) == 0) {
            return true;
        }
    }

    return false;
}

void lua_mod_register(lua_State *L, int ext_table_index) {
    // Convert to absolute index before pushing new values onto stack
    int abs_ext_index = lua_absindex(L, ext_table_index);

    // Create Ext.Mod table
    lua_newtable(L);

    // Register functions
    lua_pushcfunction(L, lua_mod_is_mod_loaded);
    lua_setfield(L, -2, "IsModLoaded");

    lua_pushcfunction(L, lua_mod_get_load_order);
    lua_setfield(L, -2, "GetLoadOrder");

    lua_pushcfunction(L, lua_mod_get_mod);
    lua_setfield(L, -2, "GetMod");

    lua_pushcfunction(L, lua_mod_get_base_mod);
    lua_setfield(L, -2, "GetBaseMod");

    lua_pushcfunction(L, lua_mod_get_mod_manager);
    lua_setfield(L, -2, "GetModManager");

    // Set as Ext.Mod
    lua_setfield(L, abs_ext_index, "Mod");

    LOG_LUA_INFO("Registered Ext.Mod namespace (5 functions)");
}
