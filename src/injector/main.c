/**
 * BG3SE-macOS - Baldur's Gate 3 Script Extender for macOS
 *
 * This dylib is loaded via DYLD_INSERT_LIBRARIES before the game starts.
 * The constructor runs automatically when the library is loaded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dirent.h>
#include <sys/stat.h>
#include <zlib.h>

// LZ4 decompression
#include "lz4/lz4.h"

// Dobby hooking framework (suppress warnings from third-party header)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvariadic-macros"
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include "Dobby/include/dobby.h"
#pragma clang diagnostic pop

// Lua runtime (C library, needs extern "C" for C++ linkage)
#ifdef __cplusplus
extern "C" {
#endif
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#ifdef __cplusplus
}
#endif

// Entity Component System
#include "entity_system.h"

// Core modules
#include "version.h"
#include "logging.h"

// Osiris modules
#include "osiris_types.h"
#include "osiris_functions.h"
#include "pattern_scan.h"

// PAK file reading
#include "pak_reader.h"

// Lua modules
#include "lua_ext.h"
#include "lua_json.h"
#include "lua_osiris.h"
#include "lua_stats.h"
#include "lua_debug.h"

// Stats system
#include "stats_manager.h"

// Mod loader
#include "mod_loader.h"

// Console
#include "console.h"

// Timer system
#include "timer.h"
#include "lua_timer.h"

// PersistentVars
#include "lua_persistentvars.h"

// Event system
#include "lua_events.h"

// Game state tracking
#include "game_state.h"

// Enable hooks (set to 0 to disable for testing)
#define ENABLE_HOOKS 1

// Forward declarations
static void enumerate_loaded_images(void);
static void check_osiris_library(void);
static void install_hooks(void);
static void init_lua(void);
static void shutdown_lua(void);

// Forward declarations for Osiris wrappers (defined later in file)
static OsiArgumentDesc *alloc_args(int count);
static void set_arg_string(OsiArgumentDesc *arg, const char *value, int isGuid);
static void set_arg_int(OsiArgumentDesc *arg, int32_t value);
static void set_arg_real(OsiArgumentDesc *arg, float value);
static int osiris_query_by_id(uint32_t funcId, OsiArgumentDesc *args);
static int osi_is_tagged(const char *character, const char *tag);
static float osi_get_distance_to(const char *char1, const char *char2);
static void osi_dialog_request_stop(const char *dialog);

// Original function pointers (filled by Dobby)
static void *orig_InitGame = NULL;
static void *orig_Load = NULL;
static void *orig_Event = NULL;

// Hook call counters
static int initGame_call_count = 0;
static int load_call_count = 0;
static int event_call_count = 0;

// ============================================================================
// Osiris Runtime State
// ============================================================================

// Global function pointers (resolved at runtime)
static InternalQueryFn pfn_InternalQuery = NULL;
static InternalCallFn pfn_InternalCall = NULL;
static pFunctionDataFn pfn_pFunctionData = NULL;
static void *g_OsiFunctionMan = NULL;
static void *g_COsiris = NULL;  // Captured from hook calls

// Global pointer to OsiFunctionMan from libOsiris
static void **g_pOsiFunctionMan = NULL;  // Points to the global _OsiFunctionMan

// Captured player GUIDs from events (we learn these by observing)
#define MAX_KNOWN_PLAYERS 8
static char g_knownPlayerGuids[MAX_KNOWN_PLAYERS][128];
static int g_knownPlayerCount = 0;

// Current dialog tracking (learned from AutomatedDialogStarted events)
static char g_currentDialogResource[256] = {0};  // Dialog resource ID
static int g_currentDialogInstance = -1;         // Dialog instance ID (if known)
static int g_currentDialogPlayerCount = 1;       // Number of players in dialog (default 1)

// Dialog participants (characters currently in an active dialog)
#define MAX_DIALOG_PARTICIPANTS 8
static char g_dialogParticipants[MAX_DIALOG_PARTICIPANTS][128];
static int g_dialogParticipantCount = 0;

// Known functions we want to track (events, queries, calls)
// Format: {name, funcId (0=discover at runtime), arity, type}

static KnownFunction g_knownFunctions[] = {
    // =========================================================================
    // Events (OSI_FUNC_EVENT = 1) - discovered via runtime observation
    // =========================================================================
    {"AutomatedDialogStarted", 2147492339, 4, OSI_FUNC_EVENT},  // 0x800021f3
    {"AutomatedDialogEnded", 2147492347, 4, OSI_FUNC_EVENT},    // 0x800021fb
    {"DialogStarted", 0, 2, OSI_FUNC_EVENT},
    {"DialogEnded", 0, 2, OSI_FUNC_EVENT},
    {"CharacterJoinedParty", 0, 1, OSI_FUNC_EVENT},
    {"CharacterLeftParty", 0, 1, OSI_FUNC_EVENT},
    {"CombatStarted", 0, 1, OSI_FUNC_EVENT},
    {"CombatEnded", 0, 1, OSI_FUNC_EVENT},
    {"CombatRoundStarted", 0, 1, OSI_FUNC_EVENT},
    {"TurnStarted", 0, 1, OSI_FUNC_EVENT},
    {"TurnEnded", 0, 1, OSI_FUNC_EVENT},
    {"LevelGameplayStarted", 0, 2, OSI_FUNC_EVENT},
    {"CharacterDied", 0, 1, OSI_FUNC_EVENT},
    {"CharacterResurrected", 0, 1, OSI_FUNC_EVENT},

    // =========================================================================
    // Procedures (OSI_FUNC_PROC = 5) - common PROC events
    // =========================================================================
    {"PROC_CharacterEnteredCombat", 0, 1, OSI_FUNC_PROC},
    {"PROC_CharacterLeftCombat", 0, 1, OSI_FUNC_PROC},
    {"PROC_EnterCombat", 0, 2, OSI_FUNC_PROC},
    {"PROC_LeaveCombat", 0, 2, OSI_FUNC_PROC},

    // =========================================================================
    // Queries (OSI_FUNC_QUERY = 2) - return values
    // =========================================================================
    {"CharacterGetLevel", 0, 2, OSI_FUNC_QUERY},
    {"GetDistanceTo", 0, 3, OSI_FUNC_QUERY},
    {"IsTagged", 0, 2, OSI_FUNC_QUERY},
    {"GetUUID", 0, 2, OSI_FUNC_QUERY},
    {"CharacterGetDisplayName", 0, 2, OSI_FUNC_QUERY},
    {"IsAlive", 0, 1, OSI_FUNC_QUERY},
    {"IsDead", 0, 1, OSI_FUNC_QUERY},
    {"CharacterIsPartyMember", 0, 1, OSI_FUNC_QUERY},
    {"CharacterIsPlayer", 0, 1, OSI_FUNC_QUERY},
    {"CharacterIsInCombat", 0, 1, OSI_FUNC_QUERY},
    {"CharacterGetAbility", 0, 3, OSI_FUNC_QUERY},
    {"CharacterGetHostCharacter", 0, 1, OSI_FUNC_QUERY},
    {"HasActiveStatus", 0, 2, OSI_FUNC_QUERY},
    {"GetPosition", 0, 4, OSI_FUNC_QUERY},
    {"QRY_IsTagged", 0, 2, OSI_FUNC_QUERY},
    {"QRY_StartDialog_Fixed", 0, 4, OSI_FUNC_QUERY},

    // =========================================================================
    // Calls (OSI_FUNC_CALL = 3) - no return value
    // =========================================================================
    {"ApplyStatus", 0, 4, OSI_FUNC_CALL},
    {"RemoveStatus", 0, 2, OSI_FUNC_CALL},
    {"PlaySound", 0, 2, OSI_FUNC_CALL},
    {"ShowNotification", 0, 2, OSI_FUNC_CALL},
    {"TeleportToPosition", 0, 5, OSI_FUNC_CALL},
    {"AddExperience", 0, 4, OSI_FUNC_CALL},
    {"SetTag", 0, 2, OSI_FUNC_CALL},
    {"ClearTag", 0, 2, OSI_FUNC_CALL},
    {"CharacterAddSpell", 0, 2, OSI_FUNC_CALL},
    {"DialogRequestStop", 0, 1, OSI_FUNC_CALL},
    {"StartDialog", 0, 4, OSI_FUNC_CALL},

    // =========================================================================
    // Databases (OSI_FUNC_DATABASE = 4)
    // =========================================================================
    {"DB_Players", 0, 1, OSI_FUNC_DATABASE},
    {"DB_PartyCriminals", 0, 2, OSI_FUNC_DATABASE},

    {NULL, 0, 0, 0}  // Sentinel
};

// Legacy alias for compatibility
#define g_knownEvents g_knownFunctions

// Track if hooks are already installed
static int hooks_installed = 0;

// ============================================================================
// ARM64 Pattern Database for Fallback Symbol Resolution
// ============================================================================
// These patterns are unique byte sequences found in function bodies.
// They're used when dlsym fails (e.g., after game updates change symbol names).
// Pattern offset is bytes from function start where pattern is found.

// Patterns discovered from libOsiris.dylib ARM64 (BG3 Patch 7)
// These patterns are at offset +28 (after function prologue)
static const FunctionPattern g_osirisPatterns[] = {
    {
        "InternalQuery",
        "_Z13InternalQueryjP16COsiArgumentDesc",
        "FD 43 04 91 F3 03 01 AA 15 90 01 51 BF 22 00 71 A2 04 00 54 53 1B 00 B4",
        28
    },
    {
        "InternalCall",
        "_Z12InternalCalljP18COsipParameterList",
        "F3 03 00 AA 28 20 00 91 09 04 00 51 3F 0D 00 71 E2 02 00 54 29 08 40 F9",
        28
    },
    {
        "COsiris::Event",
        "_ZN7COsiris5EventEjP16COsiArgumentDesc",
        "F4 03 02 AA F3 03 01 AA 76 02 00 D0 C8 4A 4D 39 68 02 18 36 68 02 00 D0",
        28
    },
    { NULL, NULL, NULL, 0 }  // Sentinel
};

/**
 * Try to resolve a function address using pattern scanning.
 * Returns function pointer if found, NULL otherwise.
 */
static void *resolve_by_pattern(const char *image_name, const FunctionPattern *pat) {
    void *text_start = NULL;
    size_t text_size = 0;

    if (!get_macho_text_section(image_name, &text_start, &text_size)) {
        return NULL;
    }

    void *found = find_pattern_str(text_start, text_size, pat->pattern);
    if (found) {
        // Adjust back by pattern offset to get function start
        void *func_addr = (void *)((uintptr_t)found - pat->pattern_offset);
        log_message("[PatternScan] %s found via pattern at %p", pat->name, func_addr);
        return func_addr;
    }

    return NULL;
}

/**
 * Resolve symbol with dlsym, falling back to pattern scan if needed.
 */
static void *resolve_osiris_symbol(void *handle, const FunctionPattern *pat) {
    // First try dlsym (fast path)
    void *addr = dlsym(handle, pat->symbol);
    if (addr) {
        return addr;
    }

    // Fallback to pattern scanning
    log_message("[Resolve] dlsym failed for %s, trying pattern scan...", pat->name);
    return resolve_by_pattern("libOsiris.dylib", pat);
}

// Lua state
static lua_State *L = NULL;

// Module loading state
#define MAX_LOADED_MODULES 256
static char loaded_modules[MAX_LOADED_MODULES][MAX_PATH_LEN];
static int loaded_module_count = 0;
static char mods_base_path[MAX_PATH_LEN] = "";

// ============================================================================
// Module Loading Helpers
// ============================================================================

/**
 * Check if a module has already been loaded
 */
static int is_module_loaded(const char *full_path) {
    for (int i = 0; i < loaded_module_count; i++) {
        if (strcmp(loaded_modules[i], full_path) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * Mark a module as loaded
 */
static void mark_module_loaded(const char *full_path) {
    if (loaded_module_count < MAX_LOADED_MODULES) {
        strncpy(loaded_modules[loaded_module_count], full_path, MAX_PATH_LEN - 1);
        loaded_modules[loaded_module_count][MAX_PATH_LEN - 1] = '\0';
        loaded_module_count++;
    }
}

/**
 * Initialize the mods base path
 * Mods can be in:
 * 1. Steam workshop: ~/Library/Application Support/Steam/steamapps/workshop/content/1086940/
 * 2. Local mods: ~/Documents/Larian Studios/Baldur's Gate 3/Mods/
 * 3. Extracted mods (for development): /tmp/<modname>_extracted/
 */
static void init_mods_base_path(void) {
    const char *home = getenv("HOME");
    if (!home) return;

    // Use local mods directory by default
    snprintf(mods_base_path, sizeof(mods_base_path),
             "%s/Documents/Larian Studios/Baldur's Gate 3/Mods", home);

    log_message("Mods base path: %s", mods_base_path);
}

/**
 * Extract ModTable value from Config.json content
 * Returns allocated string (caller must free) or NULL if not found
 */
static char *extract_mod_table(const char *config_content) {
    // Look for "ModTable": "value" pattern
    const char *key = "\"ModTable\"";
    const char *pos = strstr(config_content, key);
    if (!pos) return NULL;

    // Skip past the key and find the colon
    pos += strlen(key);
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == ':')) pos++;

    // Should now be at opening quote
    if (*pos != '"') return NULL;
    pos++;  // Skip opening quote

    // Find closing quote
    const char *end = strchr(pos, '"');
    if (!end) return NULL;

    // Extract the value
    size_t len = end - pos;
    char *value = (char *)malloc(len + 1);
    if (!value) return NULL;

    strncpy(value, pos, len);
    value[len] = '\0';

    return value;
}

/**
 * Read Config.json and extract ModTable for a mod
 * Tries various paths where Config.json might be
 */
static char *get_mod_table_name(const char *mod_name) {
    char config_path[MAX_PATH_LEN];
    char *mod_table = NULL;

    // Try 1: Documents/Mods folder (extracted mod)
    const char *home = getenv("HOME");
    if (home) {
        snprintf(config_path, sizeof(config_path),
                 "%s/Documents/Larian Studios/Baldur's Gate 3/Mods/%s/ScriptExtender/Config.json",
                 home, mod_name);

        FILE *f = fopen(config_path, "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long size = ftell(f);
            fseek(f, 0, SEEK_SET);

            if (size > 0 && size < 64 * 1024) {  // Sanity check: max 64KB
                char *content = (char *)malloc(size + 1);
                if (content) {
                    fread(content, 1, size, f);
                    content[size] = '\0';
                    mod_table = extract_mod_table(content);
                    free(content);
                }
            }
            fclose(f);
            if (mod_table) {
                log_message("[Lua] Found ModTable '%s' for mod %s", mod_table, mod_name);
                return mod_table;
            }
        }
    }

    // Try 2: /tmp extracted mods
    snprintf(config_path, sizeof(config_path),
             "/tmp/%s_extracted/Mods/%s/ScriptExtender/Config.json",
             mod_name, mod_name);

    FILE *f = fopen(config_path, "r");
    if (f) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (size > 0 && size < 64 * 1024) {
            char *content = (char *)malloc(size + 1);
            if (content) {
                fread(content, 1, size, f);
                content[size] = '\0';
                mod_table = extract_mod_table(content);
                free(content);
            }
        }
        fclose(f);
        if (mod_table) {
            log_message("[Lua] Found ModTable '%s' for mod %s", mod_table, mod_name);
            return mod_table;
        }
    }

    // Fallback: Use mod_name as ModTable
    mod_table = strdup(mod_name);
    log_message("[Lua] Using mod name '%s' as ModTable (Config.json not found or no ModTable)", mod_name);
    return mod_table;
}

/**
 * Set up Mods.<ModTable> namespace in Lua
 * Creates the global 'Mods' table if it doesn't exist
 * Creates the Mods.<mod_table> subtable
 */
static void setup_mod_namespace(lua_State *L, const char *mod_table) {
    // Get or create global 'Mods' table
    lua_getglobal(L, "Mods");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);  // Remove nil
        lua_newtable(L);
        lua_pushvalue(L, -1);  // Duplicate for setglobal
        lua_setglobal(L, "Mods");
        log_message("[Lua] Created global 'Mods' table");
    }

    // Now Mods table is on stack
    // Create Mods.<mod_table> = {}
    lua_newtable(L);
    lua_setfield(L, -2, mod_table);
    lua_pop(L, 1);  // Pop Mods table

    log_message("[Lua] Created namespace Mods.%s", mod_table);
}

/**
 * Try to find and load a Lua file from various locations
 * Returns 1 if found and loaded successfully, 0 otherwise
 */
static int try_load_lua_file(lua_State *L, const char *full_path) {
    FILE *f = fopen(full_path, "r");
    if (!f) {
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        return 0;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    // Load and execute the Lua code
    int status = luaL_loadbuffer(L, content, size, full_path);
    free(content);

    if (status != LUA_OK) {
        log_message("[Lua] Error loading %s: %s", full_path, lua_tostring(L, -1));
        lua_pop(L, 1);
        return 0;
    }

    // Execute the loaded chunk
    if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK) {
        log_message("[Lua] Error executing %s: %s", full_path, lua_tostring(L, -1));
        lua_pop(L, 1);
        return 0;
    }

    return 1;
}

/**
 * Ext.Require(path) - Load and execute a Lua module
 * Paths are relative to the current mod's ScriptExtender/Lua/ folder
 * Modules are cached - subsequent calls return cached results
 * Supports loading from both filesystem (extracted mods) and PAK files
 */
static int lua_ext_require(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    log_message("[Lua] Ext.Require('%s')", path);

    const char *lua_base = mod_get_current_lua_base();
    const char *pak_path = mod_get_current_pak_path();
    const char *mod_name = mod_get_current_name();

    // Try filesystem first (for extracted mods)
    if (lua_base && strlen(lua_base) > 0) {
        // Build full path using the base path from where bootstrap was loaded
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", lua_base, path);

        // Check if already loaded
        if (is_module_loaded(full_path)) {
            log_message("[Lua] Module already loaded: %s", path);
            lua_pushnil(L);
            return 1;
        }

        // Try to load from the tracked base path
        if (try_load_lua_file(L, full_path)) {
            mark_module_loaded(full_path);
            log_message("[Lua] Loaded module from: %s", full_path);
            if (lua_gettop(L) == 0) {
                lua_pushnil(L);
            }
            return 1;
        }
    }

    // Try PAK file (for non-extracted mods)
    if (pak_path && strlen(pak_path) > 0 && mod_name && strlen(mod_name) > 0) {
        char pak_lua_path[MAX_PATH_LEN];
        snprintf(pak_lua_path, sizeof(pak_lua_path),
                 "Mods/%s/ScriptExtender/Lua/%s", mod_name, path);

        // Check if already loaded (use PAK path as key)
        char cache_key[MAX_PATH_LEN];
        snprintf(cache_key, sizeof(cache_key), "pak:%s:%s", pak_path, pak_lua_path);

        if (is_module_loaded(cache_key)) {
            log_message("[Lua] Module already loaded from PAK: %s", path);
            lua_pushnil(L);
            return 1;
        }

        if (mod_load_lua_from_pak(L, pak_path, pak_lua_path)) {
            mark_module_loaded(cache_key);
            log_message("[Lua] Loaded module from PAK: %s", pak_lua_path);
            if (lua_gettop(L) == 0) {
                lua_pushnil(L);
            }
            return 1;
        }
    }

    // Module not found
    log_message("[Lua] Warning: Module not found: %s", path);
    if (lua_base && strlen(lua_base) > 0) {
        log_message("[Lua]   Tried filesystem: %s/%s", lua_base, path);
    }
    if (pak_path && strlen(pak_path) > 0) {
        log_message("[Lua]   Tried PAK: %s (Mods/%s/ScriptExtender/Lua/%s)",
                    pak_path, mod_name, path);
    }

    lua_pushnil(L);
    return 1;
}

// ============================================================================
// Ext.Events - Event System (implementation in lua_events.c)
// ============================================================================

// Note: The full event system implementation is now in src/lua/lua_events.c
// This section provides helper functions for firing events from main.c

// Track last tick time for delta calculation
static uint64_t g_last_tick_time_ms = 0;

/**
 * Register the Ext API in Lua
 */
static void register_ext_api(lua_State *L) {
    // Create Ext table
    lua_newtable(L);

    // Basic functions (via lua_ext module)
    lua_ext_register_basic(L, -1);

    // Ext.Require (stays in main.c due to mod loading dependencies)
    lua_pushcfunction(L, lua_ext_require);
    lua_setfield(L, -2, "Require");

    // Ext.IO namespace (via lua_ext module)
    lua_ext_register_io(L, -1);

    // Ext.Memory namespace (for interactive memory probing)
    lua_ext_register_memory(L, -1);

    // Ext.Json namespace (via lua_json module)
    lua_json_register(L, -1);

    // Ext.Events namespace (event system - new modular implementation)
    lua_events_register(L, -1);

    // Ext.Stats namespace (stats system)
    lua_stats_register(L, -1);

    // Ext.Debug namespace (memory introspection)
    lua_ext_register_debug(L, -1);

    // Ext.Types namespace (type introspection)
    lua_ext_register_types(L, -1);

    // Ext.Timer namespace (timer system)
    lua_timer_register(L, -1);

    // Ext.Vars namespace (persistent variables)
    lua_persistentvars_register(L, -1);

    // Set Ext as global
    lua_setglobal(L, "Ext");

    // Register global helper functions (must be after Ext is set as global)
    lua_ext_register_global_helpers(L);

    log_message("Ext API registered in Lua");
}

// ============================================================================
// Osi namespace - Osiris function bindings (stubs)
// ============================================================================

/**
 * GetHostCharacter() - Returns the host player's character UUID
 * For now returns a placeholder string
 */
static int lua_gethostcharacter(lua_State *L) {
    // Find the host character - it's the player GUID that doesn't match origin companions
    // Origin companions have GUIDs like "S_Player_Astarion_xxx", "S_Player_Gale_xxx", etc.
    // The custom/host character has a different pattern (e.g., "HalfElves_Male_High_Player_Dev_xxx")
    const char *hostGuid = NULL;

    for (int i = 0; i < g_knownPlayerCount; i++) {
        const char *guid = g_knownPlayerGuids[i];
        // Check if this is NOT an origin companion (origin companions start with "S_Player_")
        if (strncmp(guid, "S_Player_", 9) != 0) {
            hostGuid = guid;
            break;
        }
    }

    // Fallback: if no custom character found, return first player
    if (!hostGuid && g_knownPlayerCount > 0) {
        hostGuid = g_knownPlayerGuids[0];
    }

    if (hostGuid) {
        log_message("[Lua] GetHostCharacter() -> '%s'", hostGuid);
        lua_pushstring(L, hostGuid);
    } else {
        log_message("[Lua] GetHostCharacter() -> nil (no players discovered yet)");
        lua_pushnil(L);
    }
    return 1;
}

/**
 * Osi.IsTagged(character, tag) - Check if character has a tag
 * Uses real Osiris query when available, falls back to heuristics
 */
static int lua_osi_istagged(lua_State *L) {
    const char *character = luaL_checkstring(L, 1);
    const char *tag = luaL_checkstring(L, 2);

    int result = 0;

    // Try real Osiris query first
    if (pfn_InternalQuery) {
        int osi_result = osi_is_tagged(character, tag);
        if (osi_result >= 0) {
            // Real query succeeded
            log_message("[Lua] Osi.IsTagged('%s', '%s') -> %d (via Osiris)", character, tag, osi_result);
            lua_pushboolean(L, osi_result);
            return 1;
        }
        // Fall through to heuristic if function not found
    }

    // Fallback: heuristic for dialog-related tags
    // Tag 306b9b05-1057-4770-aa17-01af21acd650 checks dialog participation
    if (strcmp(tag, "306b9b05-1057-4770-aa17-01af21acd650") == 0) {
        // Return true for any known player character when in a dialog
        if (g_currentDialogResource[0] != '\0') {
            // We're in a dialog - check if this is a known player
            for (int i = 0; i < g_knownPlayerCount; i++) {
                if (strcmp(g_knownPlayerGuids[i], character) == 0) {
                    result = 1;
                    break;
                }
            }
        }
    }

    log_message("[Lua] Osi.IsTagged('%s', '%s') -> %d (heuristic)", character, tag, result);
    lua_pushboolean(L, result);
    return 1;
}

/**
 * Osi.GetDistanceTo(char1, char2) - Get distance between characters
 * Uses real Osiris query when available, falls back to 0
 */
static int lua_osi_getdistanceto(lua_State *L) {
    const char *char1 = luaL_checkstring(L, 1);
    const char *char2 = luaL_checkstring(L, 2);

    // Try real Osiris query first
    if (pfn_InternalQuery) {
        float distance = osi_get_distance_to(char1, char2);
        if (distance >= 0.0f) {
            log_message("[Lua] Osi.GetDistanceTo('%s', '%s') -> %.2f (via Osiris)", char1, char2, distance);
            lua_pushnumber(L, distance);
            return 1;
        }
        // Fall through if function not found
    }

    log_message("[Lua] Osi.GetDistanceTo('%s', '%s') -> 0.0 (fallback)", char1, char2);
    lua_pushnumber(L, 0.0);
    return 1;
}

/**
 * Osi.DialogGetNumberOfInvolvedPlayers(instance_id) - Get player count in dialog
 * Returns the tracked player count (default 1 for single-player)
 */
static int lua_osi_dialoggetnumberofinvolvedplayers(lua_State *L) {
    int instance_id = -1;
    if (lua_gettop(L) >= 1) {
        if (lua_isinteger(L, 1)) {
            instance_id = (int)lua_tointeger(L, 1);
        } else if (lua_isnumber(L, 1)) {
            instance_id = (int)lua_tonumber(L, 1);
        }
    }
    log_message("[Lua] Osi.DialogGetNumberOfInvolvedPlayers(%d) -> %d",
                instance_id, g_currentDialogPlayerCount);
    lua_pushinteger(L, g_currentDialogPlayerCount);
    return 1;
}

/**
 * Osi.SpeakerGetDialog(character, index) - Get dialog resource
 * Returns the current dialog resource if we've captured one
 */
static int lua_osi_speakergetdialog(lua_State *L) {
    const char *character = "";
    int index = 0;
    if (lua_gettop(L) >= 1 && lua_isstring(L, 1)) {
        character = lua_tostring(L, 1);
    }
    if (lua_gettop(L) >= 2) {
        if (lua_isinteger(L, 2)) {
            index = (int)lua_tointeger(L, 2);
        } else if (lua_isnumber(L, 2)) {
            index = (int)lua_tonumber(L, 2);
        }
    }
    log_message("[Lua] Osi.SpeakerGetDialog('%s', %d) -> '%s'",
                character, index, g_currentDialogResource);
    lua_pushstring(L, g_currentDialogResource);
    return 1;
}

/**
 * Osi.DialogRequestStop(dialog) - Stop a dialog
 * Uses real Osiris call when available
 */
static int lua_osi_dialogrequeststop(lua_State *L) {
    const char *dialog = NULL;
    if (lua_gettop(L) >= 1 && lua_isstring(L, 1)) {
        dialog = lua_tostring(L, 1);
    }

    // Try real Osiris call first
    if (pfn_InternalCall && dialog) {
        log_message("[Lua] Osi.DialogRequestStop('%s') - calling Osiris", dialog);
        osi_dialog_request_stop(dialog);
    } else {
        log_message("[Lua] Osi.DialogRequestStop() called (no-op: %s)",
                    dialog ? "InternalCall not available" : "no dialog specified");
    }

    return 0;
}

/**
 * Osi.QRY_StartDialog_Fixed(resource, character) - Start a dialog
 * Uses real Osiris query when available
 */
static int lua_osi_qry_startdialog_fixed(lua_State *L) {
    const char *resource = luaL_optstring(L, 1, NULL);
    const char *character = luaL_optstring(L, 2, NULL);

    // Try real Osiris query first
    if (pfn_InternalQuery && resource && character) {
        uint32_t funcId = osi_func_lookup_id("QRY_StartDialog_Fixed");
        if (funcId != INVALID_FUNCTION_ID) {
            OsiArgumentDesc *args = alloc_args(2);
            if (args) {
                set_arg_string(&args[0], resource, 0);   // String (resource)
                set_arg_string(&args[1], character, 1);  // GUID
                int result = osiris_query_by_id(funcId, args);
                log_message("[Lua] Osi.QRY_StartDialog_Fixed('%s', '%s') -> %d (via Osiris)",
                           resource, character, result);
                lua_pushboolean(L, result);
                return 1;
            }
        }
    }

    log_message("[Lua] Osi.QRY_StartDialog_Fixed('%s', '%s') -> false (fallback)",
                resource ? resource : "nil", character ? character : "nil");
    lua_pushboolean(L, 0);
    return 1;
}

/**
 * Check if a GUID looks like a player character
 * Player GUIDs typically start with "S_Player_" in BG3
 */
static int is_player_guid(const char *guid) {
    if (!guid) return 0;
    // Player characters have "S_Player_" prefix
    if (strncmp(guid, "S_Player_", 9) == 0) return 1;
    // Also check for common player names (Tav, custom characters)
    if (strstr(guid, "_Player_") != NULL) return 1;
    return 0;
}

/**
 * Extract just the UUID portion from a full template GUID string.
 * e.g., "S_Player_Astarion_c7c13742-bacd-460a-8f65-f864fe41f255" -> "c7c13742-bacd-460a-8f65-f864fe41f255"
 * Returns pointer to start of UUID within the input string, or the input if no underscore found.
 */
static const char *extract_uuid_from_guid(const char *guid) {
    if (!guid) return guid;

    // UUID format: 8-4-4-4-12 = 36 characters
    // Find the last underscore before the UUID
    size_t len = strlen(guid);
    if (len >= 36) {
        // Check if last 36 chars look like a UUID (has hyphens at right positions)
        const char *uuid_start = guid + len - 36;
        if (uuid_start[-1] == '_' || uuid_start == guid) {
            // Verify it looks like a UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            if (uuid_start[8] == '-' && uuid_start[13] == '-' &&
                uuid_start[18] == '-' && uuid_start[23] == '-') {
                return uuid_start;
            }
        }
    }

    // Fallback: look for last underscore
    const char *last_underscore = strrchr(guid, '_');
    if (last_underscore && strlen(last_underscore + 1) == 36) {
        return last_underscore + 1;
    }

    return guid;  // Return original if no pattern found
}

/**
 * Track a player GUID if we haven't seen it before.
 * Extracts just the UUID portion for HashMap compatibility.
 */
static void track_player_guid(const char *guid) {
    if (!guid || !is_player_guid(guid)) return;
    if (g_knownPlayerCount >= MAX_KNOWN_PLAYERS) return;

    // Extract just the UUID portion for HashMap lookup
    const char *uuid = extract_uuid_from_guid(guid);

    // Check if already tracked
    for (int i = 0; i < g_knownPlayerCount; i++) {
        if (strcmp(g_knownPlayerGuids[i], uuid) == 0) return;
    }

    // Add to list (store UUID only)
    strncpy(g_knownPlayerGuids[g_knownPlayerCount], uuid,
            sizeof(g_knownPlayerGuids[0]) - 1);
    g_knownPlayerGuids[g_knownPlayerCount][sizeof(g_knownPlayerGuids[0]) - 1] = '\0';
    g_knownPlayerCount++;
    log_message("[Players] Discovered player UUID: %s (from %s, total: %d)", uuid, guid, g_knownPlayerCount);
}

/**
 * DB_Players database accessor
 * Creates a table with a :Get() method that returns player list
 */
static int lua_osi_db_players_get(lua_State *L) {
    log_message("[Lua] Osi.DB_Players:Get() called, known players: %d", g_knownPlayerCount);

    // Return table of known players: { {guid1}, {guid2}, ... }
    lua_newtable(L);

    for (int i = 0; i < g_knownPlayerCount; i++) {
        // Each entry is a table with the GUID as first element
        lua_newtable(L);
        lua_pushstring(L, g_knownPlayerGuids[i]);
        lua_rawseti(L, -2, 1);  // t[1] = guid
        lua_rawseti(L, -2, i + 1);  // result[i+1] = {guid}
    }

    return 1;
}

/**
 * Ext.Entity.GetDiscoveredPlayers() -> { guid1, guid2, ... }
 * Returns a simple array of discovered player GUIDs
 */
static int lua_entity_get_discovered_players(lua_State *L) {
    lua_newtable(L);

    for (int i = 0; i < g_knownPlayerCount; i++) {
        lua_pushstring(L, g_knownPlayerGuids[i]);
        lua_rawseti(L, -2, i + 1);  // result[i+1] = guid
    }

    log_message("[Entity] GetDiscoveredPlayers() returning %d players", g_knownPlayerCount);
    return 1;
}

// ============================================================================
// Dynamic Osi.* Metatable Implementation
// ============================================================================

/**
 * Convert an Osiris argument value to a Lua value and push onto stack.
 * Returns 1 if value was pushed, 0 if type unknown.
 */
static int osi_value_to_lua(lua_State *L, OsiArgumentValue *val) {
    switch (val->typeId) {
        case OSI_TYPE_NONE:
            lua_pushnil(L);
            return 1;
        case OSI_TYPE_INTEGER:
            lua_pushinteger(L, val->int32Val);
            return 1;
        case OSI_TYPE_INTEGER64:
            lua_pushinteger(L, val->int64Val);
            return 1;
        case OSI_TYPE_REAL:
            lua_pushnumber(L, val->floatVal);
            return 1;
        case OSI_TYPE_STRING:
        case OSI_TYPE_GUIDSTRING:
            if (val->stringVal) {
                lua_pushstring(L, val->stringVal);
            } else {
                lua_pushstring(L, "");
            }
            return 1;
        default:
            log_message("[OsiValue] Unknown type %d", val->typeId);
            lua_pushnil(L);
            return 1;
    }
}

/**
 * Dynamic Osiris function dispatcher
 * This closure is returned by Osi.__index for unknown function names.
 * The function name is stored as upvalue 1.
 */
static int osi_dynamic_call(lua_State *L) {
    // Get function name from upvalue
    const char *funcName = lua_tostring(L, lua_upvalueindex(1));
    if (!funcName) {
        return luaL_error(L, "Osi function name not found in upvalue");
    }

    // Look up function ID
    uint32_t funcId = osi_func_lookup_id(funcName);
    if (funcId == INVALID_FUNCTION_ID) {
        // Function not yet discovered - return nil gracefully
        log_message("[Osi.%s] Function not found in cache (not yet discovered)", funcName);
        lua_pushnil(L);
        return 1;
    }

    // Get function info to determine type
    uint8_t arity = 0;
    uint8_t funcType = OSI_FUNC_UNKNOWN;
    osi_func_get_info(funcName, &arity, &funcType);

    int numArgs = lua_gettop(L);
    log_message("[Osi.%s] Called with %d args (funcId=0x%x, type=%s[%d])",
                funcName, numArgs, funcId, osi_func_type_str(funcType), funcType);

    // Check if we have the required function pointers
    if (!pfn_InternalQuery && !pfn_InternalCall) {
        log_message("[Osi.%s] ERROR: No Osiris function pointers available", funcName);
        lua_pushnil(L);
        return 1;
    }

    // Allocate arguments
    OsiArgumentDesc *args = NULL;
    if (numArgs > 0) {
        args = alloc_args(numArgs);
        if (!args) {
            return luaL_error(L, "Failed to allocate Osiris arguments");
        }

        // Convert Lua arguments to Osiris arguments
        for (int i = 0; i < numArgs; i++) {
            int argIdx = i + 1;  // Lua indices start at 1
            int luaType = lua_type(L, argIdx);

            switch (luaType) {
                case LUA_TSTRING: {
                    const char *str = lua_tostring(L, argIdx);
                    // Check if it looks like a GUID
                    int isGuid = (str && strlen(str) >= 36 &&
                                  strchr(str, '-') != NULL);
                    set_arg_string(&args[i], str, isGuid);
                    break;
                }
                case LUA_TNUMBER: {
                    if (lua_isinteger(L, argIdx)) {
                        set_arg_int(&args[i], (int32_t)lua_tointeger(L, argIdx));
                    } else {
                        set_arg_real(&args[i], (float)lua_tonumber(L, argIdx));
                    }
                    break;
                }
                case LUA_TBOOLEAN: {
                    set_arg_int(&args[i], lua_toboolean(L, argIdx) ? 1 : 0);
                    break;
                }
                case LUA_TNIL: {
                    // Nil treated as empty string
                    set_arg_string(&args[i], "", 0);
                    break;
                }
                default: {
                    log_message("[Osi.%s] Warning: Unsupported arg type %d at position %d",
                                funcName, luaType, argIdx);
                    set_arg_string(&args[i], "", 0);
                    break;
                }
            }
        }
    }

    // Call the appropriate function based on type
    // Per Windows BG3SE Function.inl dispatch logic:
    // - Query, SysQuery, UserQuery → InternalQuery
    // - Call, SysCall → InternalCall
    // - Event, Proc → Event dispatch
    // - Database → Special handling (can be data insert or user query)
    int result = 0;

    switch (funcType) {
        case OSI_FUNC_QUERY:
        case OSI_FUNC_SYSQUERY:
        case OSI_FUNC_USERQUERY:
            // Query types - use InternalQuery
            if (pfn_InternalQuery) {
                result = pfn_InternalQuery(funcId, args);
                log_message("[Osi.%s] InternalQuery returned %d", funcName, result);

                if (result && numArgs > 0) {
                    // Query succeeded - return all argument values (OUT params filled)
                    int returnCount = 0;
                    for (int i = 0; i < numArgs; i++) {
                        osi_value_to_lua(L, &args[i].value);
                        returnCount++;
                    }
                    log_message("[Osi.%s] Returning %d values from query", funcName, returnCount);
                    return returnCount;
                } else if (result) {
                    // Query succeeded but no args - return true
                    lua_pushboolean(L, 1);
                    return 1;
                } else {
                    // Query failed - return nil
                    lua_pushnil(L);
                    return 1;
                }
            }
            break;

        case OSI_FUNC_CALL:
        case OSI_FUNC_SYSCALL:
            // Call types - use InternalCall
            if (pfn_InternalCall) {
                result = pfn_InternalCall(funcId, (void *)args);
                log_message("[Osi.%s] InternalCall returned %d", funcName, result);
                // Calls don't return values
                return 0;
            }
            break;

        case OSI_FUNC_EVENT:
        case OSI_FUNC_PROC:
            // Event/Proc types - these trigger events, use InternalCall
            if (pfn_InternalCall) {
                result = pfn_InternalCall(funcId, (void *)args);
                log_message("[Osi.%s] Event/Proc dispatch returned %d", funcName, result);
                return 0;
            }
            break;

        case OSI_FUNC_DATABASE:
            // Database can be data insert or user query
            // For now, treat as query first, then call
            if (pfn_InternalQuery) {
                result = pfn_InternalQuery(funcId, args);
                if (result) {
                    log_message("[Osi.%s] Database query returned %d", funcName, result);
                    if (numArgs > 0) {
                        int returnCount = 0;
                        for (int i = 0; i < numArgs; i++) {
                            osi_value_to_lua(L, &args[i].value);
                            returnCount++;
                        }
                        return returnCount;
                    }
                    lua_pushboolean(L, 1);
                    return 1;
                }
            }
            // Fall through to try as insert
            if (pfn_InternalCall) {
                result = pfn_InternalCall(funcId, (void *)args);
                log_message("[Osi.%s] Database insert returned %d", funcName, result);
                return 0;
            }
            break;

        case OSI_FUNC_UNKNOWN:
        default:
            // Unknown type - try query first, then call (fallback heuristic)
            log_message("[Osi.%s] Unknown type %d, trying query then call", funcName, funcType);
            if (pfn_InternalQuery) {
                result = pfn_InternalQuery(funcId, args);
                if (result) {
                    log_message("[Osi.%s] Query (fallback) succeeded", funcName);
                    if (numArgs > 0) {
                        int returnCount = 0;
                        for (int i = 0; i < numArgs; i++) {
                            osi_value_to_lua(L, &args[i].value);
                            returnCount++;
                        }
                        return returnCount;
                    }
                    lua_pushboolean(L, 1);
                    return 1;
                }
            }
            // Try as a call
            if (pfn_InternalCall) {
                result = pfn_InternalCall(funcId, (void *)args);
                if (result) {
                    log_message("[Osi.%s] Call (fallback) succeeded", funcName);
                    return 0;
                }
            }
            break;
    }

    lua_pushnil(L);
    return 1;
}

/**
 * Osi table __index metamethod
 * Called when accessing Osi.FuncName for unknown keys.
 * Returns a closure that will call the Osiris function dynamically.
 */
static int osi_index_handler(lua_State *L) {
    // Stack: Osi table (1), key (2)
    const char *key = lua_tostring(L, 2);
    if (!key) {
        lua_pushnil(L);
        return 1;
    }

    log_message("[Osi.__index] Looking up '%s'", key);

    // Special case: DB_Players returns a table with :Get() method
    if (strcmp(key, "DB_Players") == 0) {
        lua_newtable(L);
        lua_pushcfunction(L, lua_osi_db_players_get);
        lua_setfield(L, -2, "Get");
        // Cache it in the Osi table
        lua_pushvalue(L, -1);  // Duplicate the table
        lua_setfield(L, 1, "DB_Players");  // Osi.DB_Players = table
        return 1;
    }

    // Check if function is in our cache
    uint32_t funcId = osi_func_lookup_id(key);
    if (funcId == INVALID_FUNCTION_ID) {
        // Function not discovered yet - return a closure anyway
        // It will return nil when called if still not found
        log_message("[Osi.__index] '%s' not yet discovered, returning lazy closure", key);
    } else {
        log_message("[Osi.__index] '%s' found (funcId=0x%x)", key, funcId);
    }

    // Create a closure with the function name as upvalue
    lua_pushstring(L, key);  // Push function name as upvalue
    lua_pushcclosure(L, osi_dynamic_call, 1);  // Create closure with 1 upvalue

    // Cache the closure in the Osi table for future accesses
    lua_pushvalue(L, -1);  // Duplicate the closure
    lua_setfield(L, 1, key);  // Osi[key] = closure

    return 1;
}

/**
 * Register Osi namespace with dynamic metatable
 */
static void register_osi_namespace(lua_State *L) {
    // Create Osi table
    lua_newtable(L);

    // Pre-register known functions that have special implementations
    // These override the dynamic lookup for better behavior

    lua_pushcfunction(L, lua_osi_istagged);
    lua_setfield(L, -2, "IsTagged");

    lua_pushcfunction(L, lua_osi_getdistanceto);
    lua_setfield(L, -2, "GetDistanceTo");

    lua_pushcfunction(L, lua_osi_dialoggetnumberofinvolvedplayers);
    lua_setfield(L, -2, "DialogGetNumberOfInvolvedPlayers");

    lua_pushcfunction(L, lua_osi_speakergetdialog);
    lua_setfield(L, -2, "SpeakerGetDialog");

    lua_pushcfunction(L, lua_osi_dialogrequeststop);
    lua_setfield(L, -2, "DialogRequestStop");

    lua_pushcfunction(L, lua_osi_qry_startdialog_fixed);
    lua_setfield(L, -2, "QRY_StartDialog_Fixed");

    // Create DB_Players table with :Get() method
    lua_newtable(L);
    lua_pushcfunction(L, lua_osi_db_players_get);
    lua_setfield(L, -2, "Get");
    lua_setfield(L, -2, "DB_Players");

    // Create metatable for Osi with __index handler for dynamic function lookup
    lua_newtable(L);  // metatable
    lua_pushcfunction(L, osi_index_handler);
    lua_setfield(L, -2, "__index");  // metatable.__index = osi_index_handler
    lua_setmetatable(L, -2);  // setmetatable(Osi, metatable)

    // Set Osi as global
    lua_setglobal(L, "Osi");

    // Also register GetHostCharacter as a global function
    lua_pushcfunction(L, lua_gethostcharacter);
    lua_setglobal(L, "GetHostCharacter");

    log_message("Osi namespace registered with dynamic metatable");
}

/**
 * _P(...) - Print debug message (BG3SE compatibility)
 * Same as Ext.Print()
 */
static int lua_global_print(lua_State *L) {
    return lua_ext_print(L);
}

/**
 * _D(value) - Dump value for debugging (BG3SE compatibility)
 * Prints a detailed representation of the value
 */
static int lua_global_dump(lua_State *L) {
    int t = lua_type(L, 1);
    const char *tname = lua_typename(L, t);

    switch (t) {
        case LUA_TNIL:
            log_message("[Lua] _D: nil");
            break;
        case LUA_TBOOLEAN:
            log_message("[Lua] _D: %s", lua_toboolean(L, 1) ? "true" : "false");
            break;
        case LUA_TNUMBER:
            log_message("[Lua] _D: %g", lua_tonumber(L, 1));
            break;
        case LUA_TSTRING:
            log_message("[Lua] _D: \"%s\"", lua_tostring(L, 1));
            break;
        case LUA_TTABLE: {
            // Use JSON stringify for tables
            luaL_Buffer b;
            luaL_buffinit(L, &b);
            json_stringify_value(L, 1, &b);
            luaL_pushresult(&b);
            log_message("[Lua] _D: %s", lua_tostring(L, -1));
            lua_pop(L, 1);
            break;
        }
        default:
            log_message("[Lua] _D: <%s: %p>", tname, lua_topointer(L, 1));
            break;
    }

    return 0;
}

/**
 * Register global debug functions (_P, _D)
 */
static void register_global_functions(lua_State *L) {
    lua_pushcfunction(L, lua_global_print);
    lua_setglobal(L, "_P");

    lua_pushcfunction(L, lua_global_dump);
    lua_setglobal(L, "_D");

    log_message("Global debug functions registered (_P, _D)");
}

/**
 * Try to load a mod's bootstrap script
 * Returns 1 if loaded successfully, 0 if not found, -1 on error
 */
static int load_mod_bootstrap(lua_State *L, const char *mod_name, const char *bootstrap_type) {
    char full_path[MAX_PATH_LEN];
    char bootstrap_file[64];

    snprintf(bootstrap_file, sizeof(bootstrap_file), "Bootstrap%s.lua", bootstrap_type);

    // First try extracted mods in /tmp (for development)
    // Note: The extraction creates a different structure, let's check the actual path
    char lua_base[MAX_PATH_LEN];

    snprintf(lua_base, sizeof(lua_base),
             "/tmp/%s_extracted/Mods/%s/ScriptExtender/Lua",
             mod_name, mod_name);
    snprintf(full_path, sizeof(full_path), "%s/%s", lua_base, bootstrap_file);

    log_message("[Lua] Looking for %s bootstrap: %s", mod_name, full_path);

    // Check if file exists before trying to load (so we can set base path first)
    FILE *test_f = fopen(full_path, "r");
    if (test_f) {
        fclose(test_f);
        // Set mod context BEFORE loading so Ext.Require works during bootstrap
        mod_set_current(mod_name, lua_base, NULL);
        log_message("[Lua] Set mod Lua base: %s", lua_base);
        if (try_load_lua_file(L, full_path)) {
            log_message("[Lua] Loaded %s %s", mod_name, bootstrap_file);
            return 1;
        }
    }

    // Try alternative extraction path (mrc -> mrc_extracted structure varies)
    snprintf(lua_base, sizeof(lua_base),
             "/tmp/mrc_extracted/Mods/%s/ScriptExtender/Lua",
             mod_name);
    snprintf(full_path, sizeof(full_path), "%s/%s", lua_base, bootstrap_file);

    test_f = fopen(full_path, "r");
    if (test_f) {
        fclose(test_f);
        mod_set_current(mod_name, lua_base, NULL);
        log_message("[Lua] Set mod Lua base: %s", lua_base);
        if (try_load_lua_file(L, full_path)) {
            log_message("[Lua] Loaded %s %s from mrc_extracted", mod_name, bootstrap_file);
            return 1;
        }
    }

    // Try local mods directory
    snprintf(lua_base, sizeof(lua_base),
             "%s/%s/ScriptExtender/Lua",
             mods_base_path, mod_name);
    snprintf(full_path, sizeof(full_path), "%s/%s", lua_base, bootstrap_file);

    test_f = fopen(full_path, "r");
    if (test_f) {
        fclose(test_f);
        mod_set_current(mod_name, lua_base, NULL);
        log_message("[Lua] Set mod Lua base: %s", lua_base);
        if (try_load_lua_file(L, full_path)) {
            log_message("[Lua] Loaded %s %s", mod_name, bootstrap_file);
            return 1;
        }
    }

    // Try loading from PAK file in Mods folder
    char pak_path[MAX_PATH_LEN];
    if (mod_find_pak(mod_name, pak_path, sizeof(pak_path))) {
        char pak_lua_path[MAX_PATH_LEN];
        snprintf(pak_lua_path, sizeof(pak_lua_path),
                 "Mods/%s/ScriptExtender/Lua/%s", mod_name, bootstrap_file);

        log_message("[Lua] Trying to load %s from PAK: %s", bootstrap_file, pak_path);

        // Set mod context for PAK loading (clear lua_base since we're using PAK)
        mod_set_current(mod_name, NULL, pak_path);

        if (mod_load_lua_from_pak(L, pak_path, pak_lua_path)) {
            log_message("[Lua] Loaded %s %s from PAK", mod_name, bootstrap_file);
            return 1;
        }

        // Clear PAK path on failure
        mod_set_current(mod_name, NULL, NULL);
    }

    // Clear mod context if not found
    mod_set_current(NULL, NULL, NULL);

    log_message("[Lua] Bootstrap not found for mod: %s (%s)", mod_name, bootstrap_file);
    return 0;
}

/**
 * Load all mod bootstraps for SE-enabled mods
 * Uses the dynamically detected SE mods populated by mod_detect_enabled()
 */
static void load_mod_scripts(lua_State *L) {
    log_message("=== Loading Mod Scripts ===");

    // Initialize the mods base path
    init_mods_base_path();

    // Check if we have any SE mods detected
    int se_count = mod_get_se_count();
    if (se_count == 0) {
        log_message("[Lua] No SE mods detected to load");
        log_message("=== Mod Script Loading Complete ===");
        return;
    }

    log_message("[Lua] Loading %d detected SE mod(s)...", se_count);

    for (int i = 0; i < se_count; i++) {
        const char *mod_name = mod_get_se_name(i);
        log_message("[Lua] Attempting to load SE mod: %s", mod_name);

        // Get ModTable name from Config.json (or fallback to mod_name)
        char *mod_table = get_mod_table_name(mod_name);
        if (mod_table) {
            // Set up Mods.<ModTable> namespace before loading scripts
            setup_mod_namespace(L, mod_table);
            free(mod_table);
        }

        // Try to load server bootstrap (runs on both client and server in BG3)
        if (load_mod_bootstrap(L, mod_name, "Server") > 0) {
            log_message("[Lua] Successfully loaded server scripts for: %s", mod_name);
        }

        // Also try client bootstrap if it exists
        if (load_mod_bootstrap(L, mod_name, "Client") > 0) {
            log_message("[Lua] Successfully loaded client scripts for: %s", mod_name);
        }
    }

    log_message("=== Mod Script Loading Complete ===");
}

/**
 * Initialize Lua runtime
 */
static void init_lua(void) {
    log_message("Initializing Lua runtime...");

    L = luaL_newstate();
    if (!L) {
        log_message("ERROR: Failed to create Lua state");
        return;
    }

    // Open standard libraries
    luaL_openlibs(L);

    // Register our Ext API
    register_ext_api(L);

    // Register Ext.Osiris namespace (via lua_osiris module)
    lua_osiris_register(L);

    // Register Osi namespace (stub functions)
    register_osi_namespace(L);

    // Register global debug functions
    register_global_functions(L);

    // Register Entity system API (Ext.Entity.*)
    entity_register_lua(L);

    // Initialize console (file-based Lua command input)
    console_init();

    // Initialize timer system
    timer_init();

    // Initialize game state tracker
    game_state_init();

    // Add GetDiscoveredPlayers to Ext.Entity (uses main.c's player tracking)
    lua_getglobal(L, "Ext");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "Entity");
        if (lua_istable(L, -1)) {
            lua_pushcfunction(L, lua_entity_get_discovered_players);
            lua_setfield(L, -2, "GetDiscoveredPlayers");
        }
        lua_pop(L, 1);  // pop Entity
    }
    lua_pop(L, 1);  // pop Ext

    // Run a test script
    const char *test_script =
        "Ext.Print('BG3SE-macOS Lua runtime initialized!')\n"
        "Ext.Print('Version: ' .. Ext.GetVersion())\n"
        "Ext.Print('IsClient: ' .. tostring(Ext.IsClient()))\n"
        "Ext.Print('IsServer: ' .. tostring(Ext.IsServer()))\n"
        "-- Test JSON parsing\n"
        "local json = '{\"name\": \"test\", \"value\": 42, \"enabled\": true}'\n"
        "local parsed = Ext.Json.Parse(json)\n"
        "if parsed then\n"
        "  Ext.Print('JSON Parse test: name=' .. tostring(parsed.name) .. ', value=' .. tostring(parsed.value))\n"
        "end\n"
        "-- Test _P and _D\n"
        "_P('Debug print test via _P')\n"
        "_D({test = 'table', num = 123})\n";

    if (luaL_dostring(L, test_script) != LUA_OK) {
        const char *error = lua_tostring(L, -1);
        log_message("Lua error: %s", error);
        lua_pop(L, 1);
    }

    log_message("Lua %s initialized", LUA_VERSION);
}

/**
 * Shutdown Lua runtime
 */
static void shutdown_lua(void) {
    if (L) {
        log_message("Shutting down Lua runtime...");
        lua_close(L);
        L = NULL;
    }
}

// ============================================================================
// Osiris Hooks
// ============================================================================

// Track if mod scripts have been loaded
static int mod_scripts_loaded = 0;

/**
 * Hooked COsiris::InitGame - called when game initializes Osiris
 * Mangled name: _ZN7COsiris8InitGameEv
 * This is a member function, so 'this' pointer is first arg
 */
static void fake_InitGame(void *thisPtr) {
    initGame_call_count++;
    log_message(">>> COsiris::InitGame called! (count: %d, this: %p)", initGame_call_count, thisPtr);

    // Capture COsiris pointer for function lookups
    if (!g_COsiris) {
        g_COsiris = thisPtr;
        log_message("  Captured COsiris instance: %p", g_COsiris);

        // Try to find function manager - it may be at a fixed offset in COsiris
        // or it may be the same object (COsiris might inherit from COsiFunctionMan)
        if (!g_OsiFunctionMan) {
            g_OsiFunctionMan = thisPtr;  // Try using COsiris directly first
            log_message("  Using COsiris as function manager: %p", g_OsiFunctionMan);
        }
    }

    // Call original
    if (orig_InitGame) {
        ((void (*)(void*))orig_InitGame)(thisPtr);
    }

    log_message(">>> COsiris::InitGame returned");

    // Enumerate Osiris functions after initialization (only once)
    static int functions_enumerated = 0;
    if (!functions_enumerated && g_pOsiFunctionMan && *g_pOsiFunctionMan) {
        functions_enumerated = 1;
        osi_func_enumerate();
    }

    // Notify Lua that Osiris is initialized
    if (L) {
        luaL_dostring(L, "Ext.Print('Osiris initialized!')");

        // Load mod scripts after Osiris is initialized (only once)
        if (!mod_scripts_loaded) {
            mod_scripts_loaded = 1;

            // Notify game state tracker that session is loading
            game_state_on_session_loading(L);

            events_fire(L, EVENT_MODULE_LOAD_STARTED);
            load_mod_scripts(L);
        }
    }
}

/**
 * Hooked COsiris::Load - called when loading save/story data
 * Mangled name: _ZN7COsiris4LoadER12COsiSmartBuf
 * Signature: bool COsiris::Load(COsiSmartBuf&)
 * This is a member function with a reference parameter, returns bool
 */
static int fake_Load(void *thisPtr, void *smartBuf) {
    load_call_count++;
    log_message(">>> COsiris::Load called! (count: %d, this: %p, buf: %p)", load_call_count, thisPtr, smartBuf);

    // Call original and preserve return value
    int result = 0;
    if (orig_Load) {
        result = ((int (*)(void*, void*))orig_Load)(thisPtr, smartBuf);
    }

    log_message(">>> COsiris::Load returned: %d", result);

    // Notify Lua that a save was loaded
    if (L && result) {
        luaL_dostring(L, "Ext.Print('Story/save data loaded!')");

        // Try to discover EntityWorld now that the game is fully loaded
        // This is the best time - EocServer should be initialized
        if (!entity_system_ready()) {
            log_message("[Entity] Attempting EntityWorld discovery after save load...");
            if (entity_discover_world()) {
                log_message("[Entity] EntityWorld discovered successfully!");
            } else {
                log_message("[Entity] EntityWorld discovery failed - try Ext.Entity.Discover() later");
            }
        }

        // Load mod scripts after save is loaded (if not already loaded)
        // This handles the case where InitGame wasn't called (loading existing save)
        if (!mod_scripts_loaded) {
            mod_scripts_loaded = 1;
            events_fire(L, EVENT_MODULE_LOAD_STARTED);
            load_mod_scripts(L);
        }

        // Initialize subsystems BEFORE firing Lua events
        // (so Lua handlers can use Stats, Entity APIs)

        // Retry TypeId discovery now that the game is fully loaded
        // TypeId globals may not have been initialized at injection time
        entity_on_session_loaded();

        // Check stats system now that the game is loaded
        stats_manager_on_session_loaded();

        // Fire StatsLoaded event (stats system is now ready)
        events_fire(L, EVENT_STATS_LOADED);

        // Restore persistent variables BEFORE firing SessionLoaded
        // (so mods can access restored data in their callbacks)
        persist_restore_all(L);

        // Notify game state tracker that session is loaded (fires GameStateChanged: LoadSession -> Running)
        game_state_on_session_loaded(L);

        // Fire SessionLoaded event after subsystems are ready
        events_fire(L, EVENT_SESSION_LOADED);
    }

    return result;
}

// ============================================================================
// Osiris Direct Query/Call Wrappers
// ============================================================================

// Pool of reusable argument descriptors (avoids malloc per call)
#define ARG_POOL_SIZE 32
static OsiArgumentDesc g_argPool[ARG_POOL_SIZE];
static int g_argPoolUsed = 0;

/**
 * Allocate argument descriptors from pool
 * Returns NULL if pool exhausted
 */
static OsiArgumentDesc *alloc_args(int count) {
    if (count <= 0 || count > ARG_POOL_SIZE) return NULL;
    if (g_argPoolUsed + count > ARG_POOL_SIZE) {
        // Pool exhausted - reset (not thread safe, but BG3 is single-threaded for Osiris)
        g_argPoolUsed = 0;
    }

    OsiArgumentDesc *args = &g_argPool[g_argPoolUsed];
    g_argPoolUsed += count;

    // Initialize and link
    memset(args, 0, count * sizeof(OsiArgumentDesc));
    for (int i = 0; i < count - 1; i++) {
        args[i].nextParam = &args[i + 1];
    }
    args[count - 1].nextParam = NULL;

    return args;
}

/**
 * Set argument value as string/GUID
 */
static void set_arg_string(OsiArgumentDesc *arg, const char *value, int isGuid) {
    if (!arg) return;
    arg->value.typeId = isGuid ? OSI_TYPE_GUIDSTRING : OSI_TYPE_STRING;
    arg->value.stringVal = (char *)value;  // Note: caller must ensure lifetime
}

/**
 * Set argument value as integer
 */
__attribute__((unused))
static void set_arg_int(OsiArgumentDesc *arg, int32_t value) {
    if (!arg) return;
    arg->value.typeId = OSI_TYPE_INTEGER;
    arg->value.int32Val = value;
}

/**
 * Set argument value as real (float)
 */
__attribute__((unused))
static void set_arg_real(OsiArgumentDesc *arg, float value) {
    if (!arg) return;
    arg->value.typeId = OSI_TYPE_REAL;
    arg->value.floatVal = value;
}

/**
 * Execute an Osiris query by function ID
 * Returns 1 on success, 0 on failure
 * Output values are written back to args
 */
static int osiris_query_by_id(uint32_t funcId, OsiArgumentDesc *args) {
    if (!pfn_InternalQuery) {
        log_message("[OsiQuery] ERROR: InternalQuery not resolved");
        return 0;
    }

    int result = pfn_InternalQuery(funcId, args);
    return result;
}

/**
 * Execute an Osiris query by name
 * Returns 1 on success, 0 on failure
 */
__attribute__((unused))
static int osiris_query(const char *funcName, OsiArgumentDesc *args) {
    uint32_t funcId = osi_func_lookup_id(funcName);
    if (funcId == INVALID_FUNCTION_ID) {
        log_message("[OsiQuery] Function '%s' not found in cache", funcName);
        return 0;
    }

    log_message("[OsiQuery] Calling %s (id=0x%x)", funcName, funcId);
    return osiris_query_by_id(funcId, args);
}

/**
 * Execute an Osiris call (proc/event) by function ID
 * Returns 1 on success, 0 on failure
 */
static int osiris_call_by_id(uint32_t funcId, OsiArgumentDesc *args) {
    if (!pfn_InternalCall) {
        log_message("[OsiCall] ERROR: InternalCall not resolved");
        return 0;
    }

    // Note: InternalCall takes COsipParameterList, not OsiArgumentDesc
    // For now, this may need adjustment based on actual signature
    int result = pfn_InternalCall(funcId, (void *)args);
    return result;
}

/**
 * Execute an Osiris call by name
 * Returns 1 on success, 0 on failure
 */
__attribute__((unused))
static int osiris_call(const char *funcName, OsiArgumentDesc *args) {
    uint32_t funcId = osi_func_lookup_id(funcName);
    if (funcId == INVALID_FUNCTION_ID) {
        log_message("[OsiCall] Function '%s' not found in cache", funcName);
        return 0;
    }

    log_message("[OsiCall] Calling %s (id=0x%x)", funcName, funcId);
    return osiris_call_by_id(funcId, args);
}

// ============================================================================
// Convenience wrappers for common Osiris functions
// ============================================================================

/**
 * QRY_IsTagged(character, tag) - Check if character has a tag
 * Returns 1 if tagged, 0 if not or on error
 */
static int osi_is_tagged(const char *character, const char *tag) {
    // Look up QRY_IsTagged or IsTagged
    uint32_t funcId = osi_func_lookup_id("QRY_IsTagged");
    if (funcId == INVALID_FUNCTION_ID) {
        funcId = osi_func_lookup_id("IsTagged");
    }
    if (funcId == INVALID_FUNCTION_ID) {
        // Function not yet discovered
        return -1;  // Unknown
    }

    OsiArgumentDesc *args = alloc_args(2);
    if (!args) return -1;

    set_arg_string(&args[0], character, 1);  // GUID
    set_arg_string(&args[1], tag, 1);        // GUID

    return osiris_query_by_id(funcId, args);
}

/**
 * GetDistanceTo(char1, char2) - Get distance between characters
 * Returns distance in meters, or -1.0 on error
 */
static float osi_get_distance_to(const char *char1, const char *char2) {
    uint32_t funcId = osi_func_lookup_id("QRY_GetDistance");
    if (funcId == INVALID_FUNCTION_ID) {
        funcId = osi_func_lookup_id("GetDistanceTo");
    }
    if (funcId == INVALID_FUNCTION_ID) {
        return -1.0f;
    }

    // This query returns a float as out param
    OsiArgumentDesc *args = alloc_args(3);
    if (!args) return -1.0f;

    set_arg_string(&args[0], char1, 1);  // GUID
    set_arg_string(&args[1], char2, 1);  // GUID
    args[2].value.typeId = OSI_TYPE_REAL;  // Out param

    if (osiris_query_by_id(funcId, args)) {
        return args[2].value.floatVal;
    }

    return -1.0f;
}

/**
 * DialogRequestStop(dialog) - Stop a dialog
 */
static void osi_dialog_request_stop(const char *dialog) {
    uint32_t funcId = osi_func_lookup_id("DialogRequestStop");
    if (funcId == INVALID_FUNCTION_ID) {
        funcId = osi_func_lookup_id("Proc_DialogRequestStop");
    }
    if (funcId == INVALID_FUNCTION_ID) {
        log_message("[OsiCall] DialogRequestStop not found");
        return;
    }

    OsiArgumentDesc *args = alloc_args(1);
    if (!args) return;

    set_arg_string(&args[0], dialog, 1);
    osiris_call_by_id(funcId, args);
}

/**
 * Count arguments in an OsiArgumentDesc chain
 */
static int count_osi_args(OsiArgumentDesc *args) {
    int count = 0;
    OsiArgumentDesc *current = args;
    while (current && count < 20) {  // Safety limit
        count++;
        current = current->nextParam;
    }
    return count;
}

/**
 * Dispatch event to registered Lua callbacks
 */
static void dispatch_event_to_lua(const char *eventName, int arity,
                                   OsiArgumentDesc *args, const char *timing) {
    (void)arity;  // Currently unused - listener uses its own requested arity
    if (!L || !eventName) return;

    int listener_count = lua_osiris_get_listener_count();
    for (int i = 0; i < listener_count; i++) {
        OsirisListener *listener = lua_osiris_get_listener(i);
        if (!listener) continue;

        // Match by name and timing only - arity is how many args listener wants
        if (strcmp(listener->event_name, eventName) == 0 &&
            strcmp(listener->timing, timing) == 0) {

            // Get callback from Lua registry
            lua_rawgeti(L, LUA_REGISTRYINDEX, listener->callback_ref);
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, 1);
                continue;
            }

            // Log callback dispatch
            log_message("[Osiris] Dispatching %s callback (%s, arity=%d)",
                       eventName, timing, listener->arity);

            // Push arguments (up to listener's requested arity)
            int argsToPass = listener->arity;
            int pushed = 0;
            OsiArgumentDesc *arg = args;
            while (arg && pushed < argsToPass) {
                // For now, push as strings - will refine based on type
                if (arg->value.typeId == OSI_TYPE_STRING ||
                    arg->value.typeId == OSI_TYPE_GUIDSTRING) {
                    if (arg->value.stringVal) {
                        lua_pushstring(L, arg->value.stringVal);
                    } else {
                        lua_pushnil(L);
                    }
                } else if (arg->value.typeId == OSI_TYPE_INTEGER) {
                    lua_pushinteger(L, arg->value.int32Val);
                } else if (arg->value.typeId == OSI_TYPE_INTEGER64) {
                    lua_pushinteger(L, (lua_Integer)arg->value.int64Val);
                } else if (arg->value.typeId == OSI_TYPE_REAL) {
                    lua_pushnumber(L, arg->value.floatVal);
                } else {
                    // Unknown type - try string
                    if (arg->value.stringVal) {
                        lua_pushstring(L, arg->value.stringVal);
                    } else {
                        lua_pushnil(L);
                    }
                }
                pushed++;
                arg = arg->nextParam;
            }

            // Call the callback
            if (lua_pcall(L, pushed, 0, 0) != LUA_OK) {
                log_message("[Osiris] Callback error for %s: %s",
                           eventName, lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        }
    }
}

/**
 * Hooked COsiris::Event - called for all Osiris events
 * Mangled name: _ZN7COsiris5EventEjP16COsiArgumentDesc
 * Signature: void COsiris::Event(unsigned int funcId, COsiArgumentDesc* args)
 */
static void fake_Event(void *thisPtr, uint32_t funcId, OsiArgumentDesc *args) {
    event_call_count++;

    // Poll for console commands and run tick systems
    if (L) {
        console_poll(L);
        timer_update(L);  // Process timer callbacks
        persist_tick(L);  // Check for dirty PersistentVars to auto-save

        // Fire Tick event with delta time
        double now = timer_get_monotonic_ms();
        if (g_last_tick_time_ms == 0) {
            g_last_tick_time_ms = (uint64_t)now;
        }
        float delta_seconds = (float)(now - g_last_tick_time_ms) / 1000.0f;
        g_last_tick_time_ms = (uint64_t)now;
        events_fire_tick(L, delta_seconds);
    }

    // Capture COsiris pointer if we haven't already
    if (!g_COsiris && thisPtr) {
        g_COsiris = thisPtr;
        g_OsiFunctionMan = thisPtr;  // Try using COsiris as function manager
        log_message(">>> Captured COsiris from Event: %p", g_COsiris);
    }

    // Get function name if available (may trigger cache lookup)
    const char *funcName = osi_func_get_name(funcId);
    int arity = count_osi_args(args);

    // Try to cache this function if we don't know it yet
    if (!funcName) {
        osi_func_cache_from_event(funcId);
        funcName = osi_func_get_name(funcId);  // Try again after caching
    }

    // Track unique function IDs for analysis
    osi_func_track_seen(funcId, (uint8_t)arity);

    // Track player GUIDs from event arguments (learn as we observe events)
    OsiArgumentDesc *scanArg = args;
    while (scanArg) {
        if ((scanArg->value.typeId == OSI_TYPE_STRING ||
             scanArg->value.typeId == OSI_TYPE_GUIDSTRING) &&
            scanArg->value.stringVal) {
            track_player_guid(scanArg->value.stringVal);
        }
        scanArg = scanArg->nextParam;
    }

    // Log event (limit frequency to avoid log spam)
    if (event_call_count <= 50 || (event_call_count % 100 == 0) || funcName != NULL) {
        if (funcName) {
            log_message(">>> Event[%d]: %s (id=%u, arity=%d, args=%p)",
                       event_call_count, funcName, funcId, arity, (void*)args);
        } else {
            log_message(">>> Event[%d]: id=%u (arity=%d, args=%p)",
                       event_call_count, funcId, arity, (void*)args);
        }

        // Dump first few bytes of args for structure analysis (first 10 events only)
        if (args && event_call_count <= 10) {
            uint8_t *p = (uint8_t *)args;
            log_message("    args bytes[0-31]: %02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x",
                       p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                       p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
                       p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
                       p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);

            // Try to read as our assumed structure
            log_message("    Assumed: nextParam=%p, typeId=%u, stringVal=%p",
                       (void*)args->nextParam, args->value.typeId,
                       (void*)args->value.stringVal);

            // If it looks like a string, try to print it
            if (args->value.typeId >= OSI_TYPE_STRING &&
                args->value.typeId <= OSI_TYPE_GUIDSTRING &&
                args->value.stringVal) {
                // Safety check - verify it's a readable address
                log_message("    String arg: %.80s", args->value.stringVal);
            }
        }
    }

    // Track dialog state from dialog events
    if (funcName) {
        if (strcmp(funcName, "AutomatedDialogStarted") == 0 && args) {
            // Clear previous participants
            g_dialogParticipantCount = 0;

            // Log and capture all 4 arguments
            OsiArgumentDesc *arg = args;
            int argIdx = 0;
            while (arg && argIdx < 4) {
                if ((arg->value.typeId == OSI_TYPE_STRING ||
                     arg->value.typeId == OSI_TYPE_GUIDSTRING) &&
                    arg->value.stringVal) {
                    log_message("[Dialog] Arg[%d]: %s", argIdx, arg->value.stringVal);

                    // Store first arg as dialog resource
                    if (argIdx == 0) {
                        strncpy(g_currentDialogResource, arg->value.stringVal,
                                sizeof(g_currentDialogResource) - 1);
                        g_currentDialogResource[sizeof(g_currentDialogResource) - 1] = '\0';
                    }

                    // Track all GUID args as potential participants
                    if (g_dialogParticipantCount < MAX_DIALOG_PARTICIPANTS) {
                        strncpy(g_dialogParticipants[g_dialogParticipantCount],
                                arg->value.stringVal,
                                sizeof(g_dialogParticipants[0]) - 1);
                        g_dialogParticipants[g_dialogParticipantCount][sizeof(g_dialogParticipants[0]) - 1] = '\0';
                        g_dialogParticipantCount++;
                    }
                } else if (arg->value.typeId == OSI_TYPE_INTEGER) {
                    log_message("[Dialog] Arg[%d]: (int) %d", argIdx, arg->value.int32Val);
                } else if (arg->value.typeId == OSI_TYPE_INTEGER64) {
                    log_message("[Dialog] Arg[%d]: (int64) %lld", argIdx, arg->value.int64Val);
                }
                arg = arg->nextParam;
                argIdx++;
            }

            g_currentDialogPlayerCount = 1;  // Single-player default
            log_message("[Dialog] Started with %d participants", g_dialogParticipantCount);
        } else if (strcmp(funcName, "AutomatedDialogEnded") == 0) {
            // Clear dialog state when dialog ends
            log_message("[Dialog] Ended: %s", g_currentDialogResource);
            g_currentDialogResource[0] = '\0';
            g_currentDialogInstance = -1;
            g_dialogParticipantCount = 0;
        }
    }

    // Dispatch to "before" callbacks if we know the function name
    if (funcName) {
        dispatch_event_to_lua(funcName, arity, args, "before");
    }

    // Call original
    if (orig_Event) {
        ((OsiEventFn)orig_Event)(thisPtr, funcId, args);
    }

    // Dispatch to "after" callbacks
    if (funcName) {
        dispatch_event_to_lua(funcName, arity, args, "after");
    }
}

/**
 * Enumerate all loaded dynamic libraries
 * This helps us understand what's loaded and find libOsiris.dylib
 */
static void enumerate_loaded_images(void) {
    uint32_t count = _dyld_image_count();
    log_message("Loaded images: %u", count);

    int interesting_count = 0;
    for (uint32_t i = 0; i < count && interesting_count < 15; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            // Only log interesting ones (not system frameworks)
            if (strstr(name, "Baldur") || strstr(name, "Osiris") ||
                strstr(name, "steam") || strstr(name, "Steam") ||
                strstr(name, "BG3") || strstr(name, "bg3se") ||
                strstr(name, "Larian") || strstr(name, "discord") ||
                strstr(name, "Bink") || strstr(name, "PlayFab") ||
                strstr(name, "Http")) {
                log_message("  [%u] %s", i, name);
                interesting_count++;
            }
        }
    }
}

/**
 * Resolve Osiris function pointers - called on every libOsiris load
 * This must be called even if hooks are already installed, because
 * ASLR changes addresses between game launches.
 */
static void resolve_osiris_function_pointers(void *osiris) {
    if (!osiris) return;

    log_message("Resolving Osiris function pointers...");

    // pFunctionData - try both symbol name variants
    pfn_pFunctionData = (pFunctionDataFn)dlsym(osiris, "_ZN15COsiFunctionMan13pFunctionDataEj");
    if (!pfn_pFunctionData) {
        pfn_pFunctionData = (pFunctionDataFn)dlsym(osiris, "__ZN15COsiFunctionMan13pFunctionDataEj");
    }

    // Get the global OsiFunctionMan pointer
    g_pOsiFunctionMan = (void **)dlsym(osiris, "_OsiFunctionMan");
    if (!g_pOsiFunctionMan && pfn_pFunctionData) {
        // Calculate from library base using pFunctionData as reference
        // pFunctionData is at offset 0x2a04c, OsiFunctionMan is at 0x9f348
        uintptr_t pFuncDataAddr = (uintptr_t)pfn_pFunctionData;
        uintptr_t libBase = pFuncDataAddr - 0x2a04c;
        g_pOsiFunctionMan = (void **)(libBase + 0x9f348);
        log_message("  OsiFunctionMan calculated from base: %p (base=0x%lx)",
                   (void*)g_pOsiFunctionMan, (unsigned long)libBase);
    }

    // Update function cache module with new runtime pointers
    osi_func_cache_set_runtime(pfn_pFunctionData, g_pOsiFunctionMan);
    osi_func_cache_set_known_events(g_knownEvents);

    log_message("Osiris function pointers resolved:");
    log_message("  pFunctionData: %p%s", (void*)pfn_pFunctionData,
                pfn_pFunctionData ? "" : " (NOT FOUND)");
    log_message("  OsiFunctionMan global: %p", (void*)g_pOsiFunctionMan);
    if (g_pOsiFunctionMan) {
        log_message("  OsiFunctionMan instance: %p", *g_pOsiFunctionMan);
    }
}

/**
 * Install Dobby hooks on Osiris functions
 */
static void install_hooks(void) {
#if ENABLE_HOOKS
    // Get libOsiris handle - try various paths
    void *osiris = dlopen("@rpath/libOsiris.dylib", RTLD_NOLOAD);
    if (!osiris) {
        // Try @executable_path relative (works when injected into BG3)
        osiris = dlopen("@executable_path/../Frameworks/libOsiris.dylib", RTLD_NOW);
    }

    if (!osiris) {
        log_message("ERROR: Could not get libOsiris handle for hooking");
        return;
    }

    // ALWAYS resolve function pointers (ASLR changes addresses between launches)
    resolve_osiris_function_pointers(osiris);

    // Only install actual hooks once
    if (hooks_installed) {
        log_message("Hooks already installed, skipping hook installation");
        return;
    }

    log_message("Installing Dobby hooks...");

    // Test pattern scanner infrastructure
    log_message("=== Pattern Scanner Test ===");
    void *text_start = NULL;
    size_t text_size = 0;
    if (get_macho_text_section("libOsiris.dylib", &text_start, &text_size)) {
        log_message("  libOsiris __TEXT,__text: %p (size: 0x%zx / %zu MB)",
                    text_start, text_size, text_size / (1024 * 1024));
    } else {
        log_message("  WARNING: Could not get libOsiris __TEXT section");
    }

    // Get function addresses (C++ mangled names)
    void *initGameAddr = dlsym(osiris, "_ZN7COsiris8InitGameEv");
    void *loadAddr = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");
    void *eventAddr = dlsym(osiris, "_ZN7COsiris5EventEjP16COsiArgumentDesc");

    // Pattern scanner verification: create pattern from known function bytes
    if (text_start && text_size > 0 && eventAddr) {
        // Read first 8 bytes of COsiris::Event and convert to pattern
        const unsigned char *event_bytes = (const unsigned char *)eventAddr;
        char test_pattern[64];
        snprintf(test_pattern, sizeof(test_pattern),
                 "%02X %02X %02X %02X %02X %02X %02X %02X",
                 event_bytes[0], event_bytes[1], event_bytes[2], event_bytes[3],
                 event_bytes[4], event_bytes[5], event_bytes[6], event_bytes[7]);

        log_message("  COsiris::Event first 8 bytes: %s", test_pattern);

        // Try to find this pattern
        void *found = find_pattern_str(text_start, text_size, test_pattern);
        if (found == eventAddr) {
            log_message("  Pattern scanner VERIFIED: found COsiris::Event at correct address");
        } else if (found) {
            log_message("  Pattern found at %p (expected %p) - multiple matches?", found, eventAddr);
        } else {
            log_message("  WARNING: Pattern scanner failed to find COsiris::Event");
        }
    }
    log_message("=== End Pattern Scanner Test ===");

    // Resolve function pointers for Osiris calls (not hooked, just called)
    // Resolve InternalQuery/InternalCall (only needed for hooks, not for function cache)
    // Use pattern-based fallback if dlsym fails
    pfn_InternalQuery = (InternalQueryFn)resolve_osiris_symbol(osiris, &g_osirisPatterns[0]);
    if (!pfn_InternalQuery) {
        log_message("  WARNING: InternalQuery not found");
    }

    pfn_InternalCall = (InternalCallFn)resolve_osiris_symbol(osiris, &g_osirisPatterns[1]);
    if (!pfn_InternalCall) {
        log_message("  WARNING: InternalCall not found");
    }

    log_message("  InternalQuery: %p%s", (void*)pfn_InternalQuery,
                pfn_InternalQuery ? "" : " (NOT FOUND)");
    log_message("  InternalCall: %p%s", (void*)pfn_InternalCall,
                pfn_InternalCall ? "" : " (NOT FOUND)");

    int hook_count = 0;

    // Hook COsiris::InitGame
    if (initGameAddr) {
        int result = DobbyHook(initGameAddr, (void *)fake_InitGame, &orig_InitGame);
        if (result == 0) {
            log_message("  COsiris::InitGame hooked successfully (orig: %p)", orig_InitGame);
            hook_count++;
        } else {
            log_message("  ERROR: Failed to hook COsiris::InitGame (error: %d)", result);
        }
    } else {
        log_message("  COsiris::InitGame not found, skipping");
    }

    // Hook COsiris::Load
    if (loadAddr) {
        int result = DobbyHook(loadAddr, (void *)fake_Load, &orig_Load);
        if (result == 0) {
            log_message("  COsiris::Load hooked successfully (orig: %p)", orig_Load);
            hook_count++;
        } else {
            log_message("  ERROR: Failed to hook COsiris::Load (error: %d)", result);
        }
    } else {
        log_message("  COsiris::Load not found, skipping");
    }

    // Hook COsiris::Event - this is the key hook for event interception!
    if (eventAddr) {
        int result = DobbyHook(eventAddr, (void *)fake_Event, &orig_Event);
        if (result == 0) {
            log_message("  COsiris::Event hooked successfully (orig: %p)", orig_Event);
            hook_count++;
        } else {
            log_message("  ERROR: Failed to hook COsiris::Event (error: %d)", result);
        }
    } else {
        log_message("  COsiris::Event not found, skipping");
    }

    log_message("Hooks installed: %d/3", hook_count);
    hooks_installed = 1;

    // Initialize Entity System
    // Find the BG3 main executable (not our injected dylib)
    // With DYLD_INSERT_LIBRARIES, our dylib is at index 0, so we need to search
    {
        uint32_t image_count = _dyld_image_count();
        bool found = false;

        for (uint32_t i = 0; i < image_count && !found; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;

            // Skip dylibs - we want the main executable
            if (strstr(name, ".dylib")) continue;

            // Look for the BG3 executable specifically
            // Path ends with: .app/Contents/MacOS/Baldur's Gate 3
            if (strstr(name, "Baldur") && strstr(name, "MacOS")) {
                const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
                intptr_t slide = _dyld_get_image_vmaddr_slide(i);
                void *binary_base = (void *)((uintptr_t)header);

                log_message("Found BG3 executable (index %u): %s", i, name);
                log_message("  Base: %p, Slide: 0x%lx", binary_base, (long)slide);

                int result = entity_system_init(binary_base);
                if (result == 0) {
                    log_message("Entity system initialized (function pointers ready)");
                } else {
                    log_message("WARNING: Entity system initialization failed: %d", result);
                }

                // Initialize stats manager
                stats_manager_init(binary_base);
                if (stats_manager_ready()) {
                    log_message("Stats system initialized and ready");
                } else {
                    log_message("Stats system initialized (will be ready after game loads)");
                }
                found = true;
            }
        }

        if (!found) {
            log_message("WARNING: Could not find BG3 main executable for entity system");
        }
    }
#else
    log_message("Hooks DISABLED (ENABLE_HOOKS=0)");
#endif
}

/**
 * Check if libOsiris.dylib is loaded and examine its exports
 */
static void check_osiris_library(void) {
    // Try to find libOsiris.dylib
    void *osiris = dlopen("@rpath/libOsiris.dylib", RTLD_NOLOAD);

    if (!osiris) {
        // Try @executable_path relative (works when injected into BG3)
        osiris = dlopen("@executable_path/../Frameworks/libOsiris.dylib", RTLD_NOW);
    }

    if (osiris) {
        log_message("libOsiris.dylib handle obtained!");

        // Look up key exported C symbols
        void *debugHook = dlsym(osiris, "DebugHook");
        void *createRule = dlsym(osiris, "CreateRule");
        void *defineFunction = dlsym(osiris, "DefineFunction");
        void *setInitSection = dlsym(osiris, "SetInitSection");

        // Try C++ mangled names for COsiris methods
        void *initGame = dlsym(osiris, "_ZN7COsiris8InitGameEv");
        void *load = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");

        log_message("Osiris symbol addresses:");
        log_message("  DebugHook: %p", debugHook);
        log_message("  CreateRule: %p", createRule);
        log_message("  DefineFunction: %p", defineFunction);
        log_message("  SetInitSection: %p", setInitSection);
        log_message("  COsiris::InitGame: %p", initGame);
        log_message("  COsiris::Load: %p", load);

        // Count how many we found
        int found = 0;
        if (debugHook) found++;
        if (createRule) found++;
        if (defineFunction) found++;
        if (setInitSection) found++;
        if (initGame) found++;
        if (load) found++;

        log_message("Found %d/6 key Osiris symbols", found);

        // Don't close - we need this handle for hooks
        // dlclose(osiris);
    } else {
        log_message("libOsiris.dylib not yet loaded");
        log_message("  dlerror: %s", dlerror());
    }
}

/**
 * Callback for when new images are loaded
 * This lets us know when libOsiris.dylib becomes available
 */
static void image_added_callback(const struct mach_header *mh, intptr_t slide) {
    // Find the name of this image
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "libOsiris")) {
                log_message(">>> libOsiris.dylib loaded dynamically! Slide: 0x%lx", (long)slide);
                check_osiris_library();
                // Install hooks when Osiris loads
                install_hooks();
            }
            break;
        }
    }
}

/**
 * Main constructor - runs when dylib is loaded
 */
__attribute__((constructor))
static void bg3se_init(void) {
    // Initialize logging
    log_init();

    // Initialize function cache module
    osi_func_cache_init();

    log_message("=== %s v%s initialized ===", BG3SE_NAME, BG3SE_VERSION);
    log_message("Running in process: %s (PID: %d)", getprogname(), getpid());

    // Get architecture
#if defined(__arm64__)
    log_message("Architecture: ARM64 (Apple Silicon)");
#elif defined(__x86_64__)
    log_message("Architecture: x86_64 (Rosetta/Intel)");
#else
    log_message("Architecture: Unknown");
#endif

    // Log Dobby availability
    log_message("Dobby inline hooking: enabled");

    // Detect and log enabled mods
    mod_detect_enabled();

    // Initialize Lua runtime
    init_lua();

    // Enumerate loaded images
    enumerate_loaded_images();

    // Check for Osiris library
    check_osiris_library();

    // Try to install hooks now (in case Osiris is already loaded)
    install_hooks();

    // Register callback for when new images load
    _dyld_register_func_for_add_image(image_added_callback);

    log_message("Image load callback registered");
    log_message("=== Initialization complete ===");
}

/**
 * Destructor - runs when dylib is unloaded (usually at process exit)
 */
__attribute__((destructor))
static void bg3se_cleanup(void) {
    log_message("=== %s shutting down ===", BG3SE_NAME);
    log_message("Final hook call counts:");
    log_message("  COsiris::InitGame: %d calls", initGame_call_count);
    log_message("  COsiris::Load: %d calls", load_call_count);
    log_message("  COsiris::Event: %d calls", event_call_count);

    // Log function cache summary
    log_message("Osiris functions: %d cached, %d unique IDs observed",
                osi_func_get_cache_count(), osi_func_get_seen_count());

    // Shutdown Lua
    shutdown_lua();
}
