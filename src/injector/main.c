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
#include "custom_functions.h"
#include "pattern_scan.h"

// PAK file reading
#include "pak_reader.h"

// Lua modules
#include "lua_ext.h"
#include "lua_context.h"
#include "lua_json.h"
#include "lua_osiris.h"
#include "lua_stats.h"
#include "lua_debug.h"
#include "lua_logging.h"

// Stats system
#include "stats_manager.h"
#include "prototype_managers.h"
#include "functor_hooks.h"

// Mod loader
#include "mod_loader.h"

// Console
#include "console.h"

// Timer system
#include "timer.h"
#include "lua_timer.h"

// Path override system
#include "path_override.h"

// PersistentVars
#include "lua_persistentvars.h"

// User Variables (entity.Vars)
#include "user_variables.h"

// Event system
#include "lua_events.h"

// Game state tracking
#include "game_state.h"

// Input system
#include "input.h"

// Math library
#include "math_ext.h"

// Overlay console
#include "overlay.h"

// ImGui Metal backend
#include "imgui_metal_backend.h"

// ImGui Lua bindings
#include "lua_imgui.h"

// Enum system
#include "enum_registry.h"

// Lifetime scoping
#include "lifetime.h"

// Localization system
#include "localization.h"
#include "lua_localization.h"

// StaticData system
#include "staticdata_manager.h"
#include "lua_staticdata.h"

// Template system
#include "template_manager.h"
#include "lua_template.h"

// Resource system
#include "resource_manager.h"
#include "lua_resource.h"

// Mod system (Issue #6: NetChannel dependency)
#include "lua_mod.h"

// Network system (Issue #6: NetChannel API)
#include "lua_net.h"
#include "net_hooks.h"

// Level system (Ext.Level: physics, tiles)
#include "level_manager.h"
#include "lua_level.h"

// Audio system (Ext.Audio: WWise engine)
#include "audio_manager.h"
#include "lua_audio.h"

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

// DivFunctions: Call/Query pointers captured from RegisterDIVFunctions hook.
// These use the correct OsiArgumentDesc* signature (Issue #66 fix).
// InternalCall uses COsipParameterList* — wrong type, causes SIGSEGV.
static DivCallProc g_divCall = NULL;
static DivCallProc g_divQuery = NULL;
static void *orig_RegisterDIVFunctions = NULL;

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
        LOG_HOOKS_DEBUG("%s found via pattern at %p", pat->name, func_addr);
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
    LOG_HOOKS_DEBUG("dlsym failed for %s, trying pattern scan...", pat->name);
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

    LOG_MOD_INFO("Mods base path: %s", mods_base_path);
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
                LOG_LUA_INFO("Found ModTable '%s' for mod %s", mod_table, mod_name);
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
            LOG_LUA_INFO("Found ModTable '%s' for mod %s", mod_table, mod_name);
            return mod_table;
        }
    }

    // Fallback: Use mod_name as ModTable
    mod_table = strdup(mod_name);
    LOG_LUA_INFO("Using mod name '%s' as ModTable (Config.json not found or no ModTable)", mod_name);
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
        LOG_LUA_INFO("Created global 'Mods' table");
    }

    // Now Mods table is on stack
    // Create Mods.<mod_table> = {}
    lua_newtable(L);
    lua_setfield(L, -2, mod_table);
    lua_pop(L, 1);  // Pop Mods table

    LOG_LUA_INFO("Created namespace Mods.%s", mod_table);
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
        LOG_LUA_INFO("Error loading %s: %s", full_path, lua_tostring(L, -1));
        lua_pop(L, 1);
        return 0;
    }

    // Execute the loaded chunk
    if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK) {
        LOG_LUA_INFO("Error executing %s: %s", full_path, lua_tostring(L, -1));
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
    LOG_LUA_INFO("Ext.Require('%s')", path);

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
            LOG_LUA_INFO("Module already loaded: %s", path);
            lua_pushnil(L);
            return 1;
        }

        // Try to load from the tracked base path
        if (try_load_lua_file(L, full_path)) {
            mark_module_loaded(full_path);
            LOG_LUA_INFO("Loaded module from: %s", full_path);
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
            LOG_LUA_INFO("Module already loaded from PAK: %s", path);
            lua_pushnil(L);
            return 1;
        }

        if (mod_load_lua_from_pak(L, pak_path, pak_lua_path)) {
            mark_module_loaded(cache_key);
            LOG_LUA_INFO("Loaded module from PAK: %s", pak_lua_path);
            if (lua_gettop(L) == 0) {
                lua_pushnil(L);
            }
            return 1;
        }
    }

    // Module not found
    LOG_LUA_WARN(" Module not found: %s", path);
    if (lua_base && strlen(lua_base) > 0) {
        LOG_LUA_INFO("  Tried filesystem: %s/%s", lua_base, path);
    }
    if (pak_path && strlen(pak_path) > 0) {
        LOG_LUA_INFO("  Tried PAK: %s (Mods/%s/ScriptExtender/Lua/%s)",
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

    // Ext.Log namespace (logging API)
    lua_ext_register_log(L, -1);

    // Ext.Types namespace (type introspection)
    lua_ext_register_types(L, -1);

    // Ext.Timer namespace (timer system)
    lua_timer_register(L, -1);

    // Ext.Vars namespace (persistent variables)
    lua_persistentvars_register(L, -1);

    // Add user variables to Ext.Vars (RegisterUserVariable, GetEntitiesWithVariable, etc.)
    lua_getfield(L, -1, "Vars");  // Get Ext.Vars table
    if (lua_istable(L, -1)) {
        uvar_register_lua(L, -1);
        // Load persisted variables
        uvar_load_all(L);
        mvar_load_all(L);
    }
    lua_pop(L, 1);  // Pop Ext.Vars

    // Ext.Enums namespace (enum and bitfield types)
    enum_register_ext_enums(L);

    // Ext.Loca namespace (localization system)
    lua_ext_register_loca(L, -1);

    // Ext.StaticData namespace (immutable game data)
    lua_staticdata_register(L, -1);

    // Ext.Template namespace (game object templates)
    lua_template_register(L, -1);

    // Ext.Resource namespace (game resources)
    lua_resource_register(L, -1);

    // Ext.IMGUI namespace (debug overlay)
    lua_imgui_register(L, -1);

    // Ext.Mod namespace (mod information - Issue #6 dependency)
    lua_mod_register(L, -1);

    // Ext.Net namespace (network messaging - Issue #6)
    // Note: is_server is determined by context, for now use true as we're server-side
    lua_net_register(L, -1, true);

    // Ext.Level namespace (physics raycasting, tile queries)
    lua_level_register(L, -1);

    // Ext.Audio namespace (WWise audio engine control)
    lua_audio_register(L, -1);

    // Set Ext as global
    lua_setglobal(L, "Ext");

    // Load Net library scripts (must be after Ext is global - scripts use Ext.*)
    lua_net_load_scripts(L);

    // Register global helper functions (must be after Ext is set as global)
    lua_ext_register_global_helpers(L);

    LOG_LUA_INFO("Ext API registered in Lua");
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
        LOG_LUA_INFO("GetHostCharacter() -> '%s'", hostGuid);
        lua_pushstring(L, hostGuid);
    } else {
        LOG_LUA_INFO("GetHostCharacter() -> nil (no players discovered yet)");
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
            LOG_LUA_INFO("Osi.IsTagged('%s', '%s') -> %d (via Osiris)", character, tag, osi_result);
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

    LOG_LUA_INFO("Osi.IsTagged('%s', '%s') -> %d (heuristic)", character, tag, result);
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
            LOG_LUA_INFO("Osi.GetDistanceTo('%s', '%s') -> %.2f (via Osiris)", char1, char2, distance);
            lua_pushnumber(L, distance);
            return 1;
        }
        // Fall through if function not found
    }

    LOG_LUA_INFO("Osi.GetDistanceTo('%s', '%s') -> 0.0 (fallback)", char1, char2);
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
    LOG_LUA_INFO("Osi.DialogGetNumberOfInvolvedPlayers(%d) -> %d",
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
    LOG_LUA_INFO("Osi.SpeakerGetDialog('%s', %d) -> '%s'",
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
        LOG_LUA_INFO("Osi.DialogRequestStop('%s') - calling Osiris", dialog);
        osi_dialog_request_stop(dialog);
    } else {
        LOG_LUA_INFO("Osi.DialogRequestStop() called (no-op: %s)",
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
                LOG_LUA_INFO("Osi.QRY_StartDialog_Fixed('%s', '%s') -> %d (via Osiris)",
                           resource, character, result);
                lua_pushboolean(L, result);
                return 1;
            }
        }
    }

    LOG_LUA_INFO("Osi.QRY_StartDialog_Fixed('%s', '%s') -> false (fallback)",
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

// extract_uuid_from_guid() is now provided by guid_lookup.c

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
    LOG_ENTITY_DEBUG("Discovered player UUID: %s (from %s, total: %d)", uuid, guid, g_knownPlayerCount);
}

/**
 * DB_Players database accessor
 * Creates a table with a :Get() method that returns player list
 */
static int lua_osi_db_players_get(lua_State *L) {
    LOG_LUA_INFO("Osi.DB_Players:Get() called, known players: %d", g_knownPlayerCount);

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

    LOG_ENTITY_DEBUG("GetDiscoveredPlayers() returning %d players", g_knownPlayerCount);
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
            LOG_OSIRIS_DEBUG("Unknown type %d", val->typeId);
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

    // Check for custom function first
    CustomFunction *customFunc = custom_func_get_by_name(funcName);
    if (customFunc) {
        LOG_OSIRIS_DEBUG("Osi.%s: Dispatching to custom function (ID=0x%x, type=%d)",
                        funcName, customFunc->assigned_id, customFunc->type);

        // Build OsiArgumentDesc from Lua arguments (for IN params)
        int numArgs = lua_gettop(L);
        OsiArgumentDesc *args = NULL;

        if (numArgs > 0) {
            args = alloc_args(numArgs);
            if (!args) {
                return luaL_error(L, "Failed to allocate arguments for custom function");
            }

            // Convert Lua args to Osiris args
            for (int i = 0; i < numArgs; i++) {
                int argIdx = i + 1;
                int luaType = lua_type(L, argIdx);
                switch (luaType) {
                    case LUA_TSTRING: {
                        const char *str = lua_tostring(L, argIdx);
                        int isGuid = (str && strlen(str) >= 36 && strchr(str, '-') != NULL);
                        set_arg_string(&args[i], str, isGuid);
                        break;
                    }
                    case LUA_TNUMBER:
                        if (lua_isinteger(L, argIdx)) {
                            set_arg_int(&args[i], (int32_t)lua_tointeger(L, argIdx));
                        } else {
                            set_arg_real(&args[i], (float)lua_tonumber(L, argIdx));
                        }
                        break;
                    case LUA_TBOOLEAN:
                        set_arg_int(&args[i], lua_toboolean(L, argIdx) ? 1 : 0);
                        break;
                    default:
                        set_arg_string(&args[i], "", 0);
                        break;
                }
            }
        }

        int result = 0;
        if (customFunc->type == CUSTOM_FUNC_QUERY) {
            result = custom_func_query(L, customFunc->assigned_id, args);
            if (result) {
                // Query returns OUT params - they're pushed by custom_func_query
                // We need to return the values from the Lua callback
                // custom_func_query handles this internally; we just return the OUT param count
                return customFunc->num_out_params;
            } else {
                lua_pushnil(L);
                return 1;
            }
        } else if (customFunc->type == CUSTOM_FUNC_CALL) {
            result = custom_func_call(L, customFunc->assigned_id, args);
            // Calls don't return values
            return 0;
        } else {
            // Events shouldn't be called this way
            LOG_OSIRIS_ERROR("Osi.%s: Cannot directly call event functions", funcName);
            lua_pushnil(L);
            return 1;
        }
    }

    // Look up function ID (native Osiris function)
    uint32_t funcId = osi_func_lookup_id(funcName);
    if (funcId == INVALID_FUNCTION_ID) {
        // Function not yet discovered - return nil gracefully
        LOG_OSIRIS_DEBUG("Osi.%s: Function not found in cache (not yet discovered)", funcName);
        lua_pushnil(L);
        return 1;
    }

    // Get function info to determine type
    uint8_t arity = 0;
    uint8_t funcType = OSI_FUNC_UNKNOWN;
    osi_func_get_info(funcName, &arity, &funcType);

    int numArgs = lua_gettop(L);
    LOG_OSIRIS_DEBUG("Osi.%s: Called with %d args (funcId=0x%x, type=%s[%d])",
                funcName, numArgs, funcId, osi_func_type_str(funcType), funcType);

    // Check if we have the required function pointers
    if (!pfn_InternalQuery && !pfn_InternalCall) {
        LOG_OSIRIS_DEBUG("Osi.%s: ERROR: No Osiris function pointers available", funcName);
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
                    LOG_OSIRIS_DEBUG("Osi.%s: Warning: Unsupported arg type %d at position %d",
                                funcName, luaType, argIdx);
                    set_arg_string(&args[i], "", 0);
                    break;
                }
            }
        }
    }

    // Call the appropriate function based on type
    // Per Windows BG3SE Function.inl dispatch logic:
    // - Query, SysQuery, UserQuery → DivFunctions::Query (or InternalQuery fallback)
    // - Call, SysCall → DivFunctions::Call (or InternalCall fallback)
    // - Event, Proc → DivFunctions::Call
    // - Database → Special handling (can be data insert or user query)
    //
    // Issue #66: DivFunctions pointers use correct OsiArgumentDesc* signature.
    // InternalCall takes COsipParameterList* (different struct) → SIGSEGV on ARM64.
    int result = 0;

    // Select dispatch functions: prefer DivFunctions (correct type), fall back to Internal*
    DivCallProc queryFn = g_divQuery ? g_divQuery : (DivCallProc)pfn_InternalQuery;
    DivCallProc callFn = g_divCall ? g_divCall : NULL;

    switch (funcType) {
        case OSI_FUNC_QUERY:
        case OSI_FUNC_SYSQUERY:
        case OSI_FUNC_USERQUERY:
            // Query types
            if (queryFn) {
                result = queryFn(funcId, args);
                LOG_OSIRIS_DEBUG("Osi.%s: Query returned %d (via %s)", funcName, result,
                                g_divQuery ? "DivQuery" : "InternalQuery");

                if (result && numArgs > 0) {
                    int returnCount = 0;
                    for (int i = 0; i < numArgs; i++) {
                        osi_value_to_lua(L, &args[i].value);
                        returnCount++;
                    }
                    LOG_OSIRIS_DEBUG("Osi.%s: Returning %d values from query", funcName, returnCount);
                    return returnCount;
                } else if (result) {
                    lua_pushboolean(L, 1);
                    return 1;
                } else {
                    lua_pushnil(L);
                    return 1;
                }
            }
            break;

        case OSI_FUNC_CALL:
        case OSI_FUNC_SYSCALL:
            // Call types
            if (callFn) {
                result = callFn(funcId, args);
                LOG_OSIRIS_DEBUG("Osi.%s: Call returned %d (via DivCall)", funcName, result);
                return 0;
            }
            break;

        case OSI_FUNC_EVENT:
        case OSI_FUNC_PROC:
            // Event/Proc types
            if (callFn) {
                result = callFn(funcId, args);
                LOG_OSIRIS_DEBUG("Osi.%s: Event/Proc dispatch returned %d (via DivCall)", funcName, result);
                return 0;
            }
            break;

        case OSI_FUNC_DATABASE:
            // Database can be data insert or user query
            if (queryFn) {
                result = queryFn(funcId, args);
                if (result) {
                    LOG_OSIRIS_DEBUG("Osi.%s: Database query returned %d", funcName, result);
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
            if (callFn) {
                result = callFn(funcId, args);
                LOG_OSIRIS_DEBUG("Osi.%s: Database insert returned %d", funcName, result);
                return 0;
            }
            break;

        case OSI_FUNC_UNKNOWN:
        default:
            // Unknown type - try query first, then call
            LOG_OSIRIS_DEBUG("Osi.%s: Unknown type %d, trying query then call", funcName, funcType);
            if (queryFn) {
                result = queryFn(funcId, args);
                if (result) {
                    LOG_OSIRIS_DEBUG("Osi.%s: Query (fallback) succeeded", funcName);
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
            if (callFn) {
                result = callFn(funcId, args);
                if (result) {
                    LOG_OSIRIS_DEBUG("Osi.%s: Call (fallback) succeeded", funcName);
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

    LOG_OSIRIS_DEBUG("Looking up '%s'", key);

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
        LOG_OSIRIS_DEBUG("'%s' not yet discovered, returning lazy closure", key);
    } else {
        LOG_OSIRIS_DEBUG("'%s' found (funcId=0x%x)", key, funcId);
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

    LOG_OSIRIS_INFO("Osi namespace registered with dynamic metatable");
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
            LOG_LUA_INFO("_D: nil");
            break;
        case LUA_TBOOLEAN:
            LOG_LUA_INFO("_D: %s", lua_toboolean(L, 1) ? "true" : "false");
            break;
        case LUA_TNUMBER:
            LOG_LUA_INFO("_D: %g", lua_tonumber(L, 1));
            break;
        case LUA_TSTRING:
            LOG_LUA_INFO("_D: \"%s\"", lua_tostring(L, 1));
            break;
        case LUA_TTABLE: {
            // Use JSON stringify for tables
            luaL_Buffer b;
            luaL_buffinit(L, &b);
            json_stringify_value(L, 1, &b);
            luaL_pushresult(&b);
            LOG_LUA_INFO("_D: %s", lua_tostring(L, -1));
            lua_pop(L, 1);
            break;
        }
        default:
            LOG_LUA_INFO("_D: <%s: %p>", tname, lua_topointer(L, 1));
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

    LOG_LUA_INFO("Global debug functions registered (_P, _D)");
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

    LOG_LUA_INFO("Looking for %s bootstrap: %s", mod_name, full_path);

    // Check if file exists before trying to load (so we can set base path first)
    FILE *test_f = fopen(full_path, "r");
    if (test_f) {
        fclose(test_f);
        // Set mod context BEFORE loading so Ext.Require works during bootstrap
        mod_set_current(mod_name, lua_base, NULL);
        LOG_LUA_INFO("Set mod Lua base: %s", lua_base);
        if (try_load_lua_file(L, full_path)) {
            LOG_LUA_INFO("Loaded %s %s", mod_name, bootstrap_file);
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
        LOG_LUA_INFO("Set mod Lua base: %s", lua_base);
        if (try_load_lua_file(L, full_path)) {
            LOG_LUA_INFO("Loaded %s %s from mrc_extracted", mod_name, bootstrap_file);
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
        LOG_LUA_INFO("Set mod Lua base: %s", lua_base);
        if (try_load_lua_file(L, full_path)) {
            LOG_LUA_INFO("Loaded %s %s", mod_name, bootstrap_file);
            return 1;
        }
    }

    // Try loading from PAK file in Mods folder
    char pak_path[MAX_PATH_LEN];
    if (mod_find_pak(mod_name, pak_path, sizeof(pak_path))) {
        char pak_lua_path[MAX_PATH_LEN];
        snprintf(pak_lua_path, sizeof(pak_lua_path),
                 "Mods/%s/ScriptExtender/Lua/%s", mod_name, bootstrap_file);

        LOG_LUA_INFO("Trying to load %s from PAK: %s", bootstrap_file, pak_path);

        // Set mod context for PAK loading (clear lua_base since we're using PAK)
        mod_set_current(mod_name, NULL, pak_path);

        if (mod_load_lua_from_pak(L, pak_path, pak_lua_path)) {
            LOG_LUA_INFO("Loaded %s %s from PAK", mod_name, bootstrap_file);
            return 1;
        }

        // Clear PAK path on failure
        mod_set_current(mod_name, NULL, NULL);
    }

    // Clear mod context if not found
    mod_set_current(NULL, NULL, NULL);

    LOG_LUA_INFO("Bootstrap not found for mod: %s (%s)", mod_name, bootstrap_file);
    return 0;
}

/**
 * Load all mod bootstraps for SE-enabled mods
 * Uses the dynamically detected SE mods populated by mod_detect_enabled()
 */
static void load_mod_scripts(lua_State *L) {
    LOG_MOD_INFO("=== Loading Mod Scripts ===");

    // Initialize the mods base path
    init_mods_base_path();

    // Check if we have any SE mods detected
    int se_count = mod_get_se_count();
    if (se_count == 0) {
        LOG_LUA_INFO("No SE mods detected to load");
        LOG_MOD_INFO("=== Mod Script Loading Complete ===");
        return;
    }

    LOG_LUA_INFO("Loading %d detected SE mod(s)...", se_count);

    // Phase 1: Load all server bootstraps (in SERVER context)
    LOG_LUA_INFO("=== Loading Server Bootstraps ===");
    lua_context_set(LUA_CONTEXT_SERVER);

    for (int i = 0; i < se_count; i++) {
        const char *mod_name = mod_get_se_name(i);

        // Get ModTable name from Config.json (or fallback to mod_name)
        char *mod_table = get_mod_table_name(mod_name);
        if (mod_table) {
            // Set up Mods.<ModTable> namespace before loading scripts
            setup_mod_namespace(L, mod_table);
            free(mod_table);
        }

        // Load server bootstrap in SERVER context
        if (load_mod_bootstrap(L, mod_name, "Server") > 0) {
            LOG_LUA_INFO("Loaded BootstrapServer.lua for: %s (context=Server)", mod_name);
        }
    }

    // Phase 2: Load all client bootstraps (in CLIENT context)
    LOG_LUA_INFO("=== Loading Client Bootstraps ===");
    lua_context_set(LUA_CONTEXT_CLIENT);

    for (int i = 0; i < se_count; i++) {
        const char *mod_name = mod_get_se_name(i);

        // Load client bootstrap in CLIENT context
        if (load_mod_bootstrap(L, mod_name, "Client") > 0) {
            LOG_LUA_INFO("Loaded BootstrapClient.lua for: %s (context=Client)", mod_name);
        }
    }

    // Stay in CLIENT context after loading (we're on a client machine)
    LOG_MOD_INFO("=== Mod Script Loading Complete (final context=Client) ===");
}

// ============================================================================
// Overlay Console Callbacks
// ============================================================================

/**
 * Callback when user submits a command in the overlay console
 */
static void overlay_command_handler(const char *command) {
    if (!command) return;

    // IMPORTANT: Don't execute Lua from AppKit callback context.
    // Queue the command and execute on the Lua-owning tick thread.
    console_queue_lua_command(command);
}

/**
 * Hotkey callback to toggle overlay visibility
 */
static void overlay_toggle_hotkey(void *userData) {
    (void)userData;
    overlay_toggle();
}

/**
 * Initialize Lua runtime
 */
static void init_lua(void) {
    LOG_LUA_INFO("Initializing Lua runtime...");

    L = luaL_newstate();
    if (!L) {
        LOG_LUA_ERROR("Failed to create Lua state");
        return;
    }

    // Open standard libraries
    luaL_openlibs(L);

    // Initialize context system (client/server tracking)
    lua_context_init();

    // Initialize lifetime scoping system
    lifetime_lua_init(L);

    // Initialize enum registry and register metatables
    enum_registry_init();
    enum_register_definitions();
    enum_register_metatables(L);

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

    // Initialize path override system
    path_override_init();

    // Initialize game state tracker
    game_state_init();

    // Initialize input system (NSEvent swizzling)
    if (input_init()) {
        // Register Ext.Input namespace
        lua_getglobal(L, "Ext");
        if (lua_istable(L, -1)) {
            lua_input_register(L, lua_gettop(L));
        }
        lua_pop(L, 1);  // pop Ext

        // Set Lua state for input event dispatch
        input_set_lua_state(L);

        // Initialize overlay console with Tanit symbol
        overlay_init();
        overlay_set_command_callback(overlay_command_handler);
        console_set_lua_state(L);

        // Register Ctrl+` hotkey to toggle overlay console
        // macOS keyCode 50 = backtick/grave accent key
        input_register_hotkey(50, INPUT_MOD_CTRL, overlay_toggle_hotkey, NULL, "ToggleConsole");
        LOG_CONSOLE_DEBUG("Registered Ctrl+` hotkey for console toggle");
    }

    // Register Ext.Math namespace
    lua_getglobal(L, "Ext");
    if (lua_istable(L, -1)) {
        lua_math_register(L, lua_gettop(L));
    }
    lua_pop(L, 1);  // pop Ext

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

    // Run a test script (context is NONE at init, before mod loading sets it)
    const char *test_script =
        "Ext.Print('BG3SE-macOS Lua runtime initialized!')\n"
        "Ext.Print('Version: ' .. Ext.GetVersion())\n"
        "Ext.Print('Context: ' .. Ext.GetContext() .. ' (IsServer=' .. tostring(Ext.IsServer()) .. ', IsClient=' .. tostring(Ext.IsClient()) .. ')')\n"
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
        LOG_LUA_ERROR(" %s", error);
        lua_pop(L, 1);
    }

    LOG_LUA_INFO("Lua %s initialized", LUA_VERSION);
}

/**
 * Shutdown Lua runtime
 */
static void shutdown_lua(void) {
    if (L) {
        LOG_LUA_INFO("Shutting down Lua runtime...");

        // Shutdown input system before closing Lua
        input_shutdown();

        // Clear custom Osiris functions before closing Lua state
        lua_osiris_reset_custom_functions(L);

        lua_close(L);
        L = NULL;
    }
}

// ============================================================================
// Osiris Hooks
// ============================================================================

// Track if mod scripts have been loaded
static int mod_scripts_loaded = 0;

// ============================================================================
// Deferred Session Init (Issue #65)
//
// Moves ~2,800 mach_vm_read_overwrite kernel calls out of fake_Load and into
// the tick loop (fake_Event). This prevents the game from bouncing back to
// LoadSession on some machines (especially macOS Tahoe / M4).
//
// State machine:
//   IDLE → PENDING (requested by fake_Load) → COMPLETE (all init done)
// ============================================================================

typedef enum {
    SESSION_INIT_IDLE = 0,
    SESSION_INIT_PENDING,
    SESSION_INIT_COMPLETE
} SessionInitState;

static SessionInitState s_session_init_state = SESSION_INIT_IDLE;

static void request_deferred_session_init(void) {
    if (s_session_init_state == SESSION_INIT_COMPLETE) {
        // Already complete — on save reload, allow re-init
        s_session_init_state = SESSION_INIT_PENDING;
        LOG_GAME_INFO("Deferred session init re-requested (save reload)");
        return;
    }
    s_session_init_state = SESSION_INIT_PENDING;
    LOG_GAME_INFO("Deferred session init requested (Issue #65)");
}

/**
 * Tick function for deferred session initialization.
 * Called from fake_Event tick loop. Performs all heavy init work
 * that was previously in fake_Load:
 *   - EntityWorld discovery + TypeId discovery (~2,200 kernel calls)
 *   - Stats system validation (~68 kernel calls)
 *   - Static data capture (~400-600 kernel calls)
 *   - Fires: StatsStructureLoaded, StatsLoaded, SessionLoaded, ModuleResume
 *   - Sets state to Running + requests deferred net init
 *
 * Returns true if init was completed this tick.
 */
static bool deferred_session_init_tick(void) {
    if (s_session_init_state != SESSION_INIT_PENDING) return false;
    if (!L) return false;

    // BG3SE_MINIMAL: skip all subsystem initialization (Issue #65 debugging)
    // Only Osiris hooks + basic Lua API remain active
    static int minimal_mode = -1;
    if (minimal_mode < 0) minimal_mode = (getenv("BG3SE_MINIMAL") != NULL);
    if (minimal_mode) {
        log_message("[WARN] BG3SE_MINIMAL=1: ALL subsystem init skipped. "
                    "Mods will NOT receive SessionLoaded/StatsLoaded events. "
                    "PersistentVars will NOT be restored. Network hooks disabled.");
        game_state_on_session_loaded(L);  // Still transition to Running
        s_session_init_state = SESSION_INIT_COMPLETE;
        return true;
    }

    uint64_t t_start = (uint64_t)timer_get_monotonic_ms();
    LOG_GAME_INFO("Deferred session init starting...");

    // Step 1: Entity world discovery
    uint64_t t0 = t_start;
    if (!entity_system_ready()) {
        LOG_ENTITY_DEBUG("Attempting EntityWorld discovery (deferred)...");
        if (entity_discover_world()) {
            LOG_ENTITY_DEBUG("EntityWorld discovered successfully!");
        } else {
            LOG_ENTITY_DEBUG("EntityWorld discovery failed - try Ext.Entity.Discover() later");
        }
    }
    uint64_t t1 = (uint64_t)timer_get_monotonic_ms();
    LOG_GAME_INFO("  entity_discover_world: %llums", (unsigned long long)(t1 - t0));

    // Step 2: TypeId discovery (~2,200 kernel calls)
    t0 = t1;
    entity_on_session_loaded();
    t1 = (uint64_t)timer_get_monotonic_ms();
    LOG_GAME_INFO("  entity_on_session_loaded: %llums", (unsigned long long)(t1 - t0));

    // Step 3: Stats system validation
    t0 = t1;
    stats_manager_on_session_loaded();
    t1 = (uint64_t)timer_get_monotonic_ms();
    LOG_GAME_INFO("  stats_manager_on_session_loaded: %llums", (unsigned long long)(t1 - t0));

    // Step 4: Static data capture
    t0 = t1;
    staticdata_post_init_capture();
    t1 = (uint64_t)timer_get_monotonic_ms();
    LOG_GAME_INFO("  staticdata_post_init_capture: %llums", (unsigned long long)(t1 - t0));

    // Step 5: Fire events + state transition
    events_fire(L, EVENT_STATS_STRUCTURE_LOADED);
    events_fire(L, EVENT_STATS_LOADED);
    persist_restore_all(L);
    game_state_on_session_loaded(L);  // LoadSession → Running
    events_fire(L, EVENT_SESSION_LOADED);
    events_fire(L, EVENT_MODULE_RESUME);

    // Step 6: Now net hooks can proceed (state is Running)
    net_hooks_request_deferred_init();

    s_session_init_state = SESSION_INIT_COMPLETE;

    uint64_t t_end = (uint64_t)timer_get_monotonic_ms();
    LOG_GAME_INFO("Deferred session init complete: %llums total",
                  (unsigned long long)(t_end - t_start));

    return true;
}

/**
 * Hooked COsiris::RegisterDIVFunctions - engine registers Call/Query dispatch
 * Mangled name: _ZN7COsiris20RegisterDIVFunctionsEP19TOsirisInitFunction
 *
 * The DivFunctions struct contains Call and Query function pointers that
 * correctly take OsiArgumentDesc* (unlike InternalCall which takes
 * COsipParameterList* — a different struct that causes SIGSEGV on ARM64).
 *
 * Windows BG3SE hooks this same function: OsirisWrappers.cpp:38
 */
static void fake_RegisterDIVFunctions(void *thisPtr, DivFunctions *functions) {
    LOG_HOOKS_INFO(">>> COsiris::RegisterDIVFunctions called (this=%p, funcs=%p)", thisPtr, (void*)functions);

    if (functions) {
        g_divCall = functions->call;
        g_divQuery = functions->query;
        LOG_HOOKS_INFO("  Captured DivFunctions: Call=%p, Query=%p",
                       (void*)g_divCall, (void*)g_divQuery);
        if (functions->error) {
            LOG_HOOKS_DEBUG("  DivFunctions: Error=%p, Assert=%p",
                           (void*)functions->error, (void*)functions->assert_fn);
        }
    } else {
        LOG_HOOKS_WARN("  RegisterDIVFunctions called with NULL functions pointer");
    }

    // Call original
    if (orig_RegisterDIVFunctions) {
        ((void(*)(void*, DivFunctions*))orig_RegisterDIVFunctions)(thisPtr, functions);
    }
}

/**
 * Hooked COsiris::InitGame - called when game initializes Osiris
 * Mangled name: _ZN7COsiris8InitGameEv
 * This is a member function, so 'this' pointer is first arg
 */
static void fake_InitGame(void *thisPtr) {
    initGame_call_count++;
    LOG_OSIRIS_DEBUG(">>> COsiris::InitGame called! (count: %d, this: %p)", initGame_call_count, thisPtr);

    // Capture COsiris pointer for function lookups
    if (!g_COsiris) {
        g_COsiris = thisPtr;
        LOG_OSIRIS_DEBUG("  Captured COsiris instance: %p", g_COsiris);

        // Try to find function manager - it may be at a fixed offset in COsiris
        // or it may be the same object (COsiris might inherit from COsiFunctionMan)
        if (!g_OsiFunctionMan) {
            g_OsiFunctionMan = thisPtr;  // Try using COsiris directly first
            LOG_OSIRIS_DEBUG("  Using COsiris as function manager: %p", g_OsiFunctionMan);
        }
    }

    // Call original
    if (orig_InitGame) {
        ((void (*)(void*))orig_InitGame)(thisPtr);
    }

    LOG_OSIRIS_DEBUG(">>> COsiris::InitGame returned");

    // Enumerate Osiris functions after initialization (only once)
    static int functions_enumerated = 0;
    if (!functions_enumerated && g_pOsiFunctionMan && *g_pOsiFunctionMan) {
        functions_enumerated = 1;
        osi_func_enumerate();
    }

    // Notify Lua that Osiris is initialized
    if (L) {
        luaL_dostring(L, "Ext.Print('Osiris initialized!')");

        // NOTE: Do NOT call game_state_on_session_loading() here.
        // By the time InitGame fires, fake_Load has already set state to Running.
        // Resetting to LoadSession here corrupted the state machine and broke
        // deferred net init (Issue #65).

        // Load mod scripts after Osiris is initialized (only once per game launch)
        if (!mod_scripts_loaded) {
            mod_scripts_loaded = 1;

            events_fire(L, EVENT_MODULE_LOAD_STARTED);
            load_mod_scripts(L);
        }

        // FALLBACK: Run deferred session init NOW if still pending (Issue #65).
        // On some machines (macOS Tahoe 26.2, M4), fake_Event never fires —
        // the game tears down the session before any Osiris events flow.
        // The tick-loop-based init would never run, leaving the session
        // permanently stuck at LoadSession. Running it here during InitGame
        // is our last chance before the game engine may abort.
        // On machines where Events DO fire, this is a no-op (state is already
        // COMPLETE by the first Event tick, or this runs it slightly earlier).
        if (s_session_init_state == SESSION_INIT_PENDING) {
            LOG_GAME_INFO("Running deferred session init from InitGame (Event fallback - Issue #65)");
            deferred_session_init_tick();
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
    LOG_OSIRIS_DEBUG(">>> COsiris::Load called! (count: %d, this: %p, buf: %p)", load_call_count, thisPtr, smartBuf);

    // Notify game state tracker that we're loading (fires GameStateChanged: Running -> LoadSession)
    if (L) {
        game_state_on_session_loading(L);
    }

    // Call original and preserve return value
    int result = 0;
    if (orig_Load) {
        result = ((int (*)(void*, void*))orig_Load)(thisPtr, smartBuf);
    }

    LOG_OSIRIS_DEBUG(">>> COsiris::Load returned: %d", result);

    // Notify Lua that a save was loaded
    if (L && result) {
        luaL_dostring(L, "Ext.Print('Story/save data loaded!')");

        // Load mod scripts after save is loaded (if not already loaded)
        // This handles the case where InitGame wasn't called (loading existing save)
        // NOTE: Mod loading stays in fake_Load (needs to happen before first tick)
        if (!mod_scripts_loaded) {
            mod_scripts_loaded = 1;
            events_fire(L, EVENT_MODULE_LOAD_STARTED);
            load_mod_scripts(L);
        }

        // Request deferred session init — just sets a flag, zero kernel calls.
        // All heavy work (entity TypeId discovery, stats, staticdata, events)
        // is deferred to deferred_session_init_tick() in the tick loop.
        // This prevents ~2,800 mach_vm_read_overwrite kernel calls from
        // blocking the timing-sensitive window after COsiris::Load (Issue #65).
        request_deferred_session_init();
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
    // Prefer DivFunctions::Query (correct OsiArgumentDesc* signature, Issue #66)
    if (g_divQuery) {
        return g_divQuery(funcId, args);
    }
    // Fallback to InternalQuery (uses OsiArgumentDesc* too, but may not be available)
    if (pfn_InternalQuery) {
        return pfn_InternalQuery(funcId, args);
    }
    LOG_OSIRIS_DEBUG("ERROR: No query dispatch available (DivQuery=%p, InternalQuery=%p)",
                     (void*)g_divQuery, (void*)pfn_InternalQuery);
    return 0;
}

/**
 * Execute an Osiris query by name
 * Returns 1 on success, 0 on failure
 */
__attribute__((unused))
static int osiris_query(const char *funcName, OsiArgumentDesc *args) {
    uint32_t funcId = osi_func_lookup_id(funcName);
    if (funcId == INVALID_FUNCTION_ID) {
        LOG_OSIRIS_DEBUG("Function '%s' not found in cache", funcName);
        return 0;
    }

    LOG_OSIRIS_DEBUG("Calling %s (id=0x%x)", funcName, funcId);
    return osiris_query_by_id(funcId, args);
}

/**
 * Execute an Osiris call (proc/event) by function ID
 * Returns 1 on success, 0 on failure
 */
static int osiris_call_by_id(uint32_t funcId, OsiArgumentDesc *args) {
    // Prefer DivFunctions::Call (correct OsiArgumentDesc* signature, Issue #66)
    if (g_divCall) {
        return g_divCall(funcId, args);
    }
    // WARNING: InternalCall takes COsipParameterList*, NOT OsiArgumentDesc*.
    // This fallback path is UNSAFE and will likely crash on ARM64.
    // It only exists for the case where RegisterDIVFunctions hasn't fired yet.
    if (pfn_InternalCall) {
        LOG_OSIRIS_WARN("osiris_call_by_id: falling back to InternalCall (wrong struct type!)");
        int result = pfn_InternalCall(funcId, (void *)args);
        return result;
    }
    LOG_OSIRIS_DEBUG("ERROR: No call dispatch available (DivCall=%p, InternalCall=%p)",
                     (void*)g_divCall, (void*)pfn_InternalCall);
    return 0;
}

/**
 * Execute an Osiris call by name
 * Returns 1 on success, 0 on failure
 */
__attribute__((unused))
static int osiris_call(const char *funcName, OsiArgumentDesc *args) {
    uint32_t funcId = osi_func_lookup_id(funcName);
    if (funcId == INVALID_FUNCTION_ID) {
        LOG_OSIRIS_DEBUG("Function '%s' not found in cache", funcName);
        return 0;
    }

    LOG_OSIRIS_DEBUG("Calling %s (id=0x%x)", funcName, funcId);
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
        LOG_OSIRIS_DEBUG("DialogRequestStop not found");
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
            LOG_OSIRIS_INFO("Dispatching %s callback (%s, arity=%d)",
                       eventName, timing, listener->arity);

            // Begin lifetime scope for this callback
            LifetimeHandle scope = lifetime_lua_begin_scope(L);

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
                LOG_OSIRIS_INFO("Callback error for %s: %s",
                           eventName, lua_tostring(L, -1));
                lua_pop(L, 1);
            }

            // End lifetime scope - all userdata created in callback become invalid
            lifetime_lua_end_scope(L);
            (void)scope;  // Suppress unused warning
        }
    }

    // ========================================================================
    // Osiris → Ext.Events Bridge (Issue #51)
    // Fire Ext.Events.TurnStarted/TurnEnded when Osiris turn events fire
    // ========================================================================
    if (strcmp(timing, "after") == 0) {  // Only fire once per event
        const char *characterGuid = NULL;

        // Extract character GUID from first argument
        if (args && (args->value.typeId == OSI_TYPE_STRING ||
                     args->value.typeId == OSI_TYPE_GUIDSTRING) &&
            args->value.stringVal) {
            characterGuid = args->value.stringVal;
        }

        if (strcmp(eventName, "TurnStarted") == 0) {
            events_fire_turn_started_from_osiris(L, characterGuid);
        } else if (strcmp(eventName, "TurnEnded") == 0) {
            events_fire_turn_ended_from_osiris(L, characterGuid);
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
        input_poll(L);
        lua_imgui_set_lua_state(L);  // Set Lua state for IMGUI event callbacks
        timer_update(L);  // Process timer callbacks
        timer_update_persistent(L);  // Process persistent timer callbacks
        persist_tick(L);  // Check for dirty PersistentVars to auto-save

        // Fire Tick event with delta time
        double now = timer_get_monotonic_ms();
        if (g_last_tick_time_ms == 0) {
            g_last_tick_time_ms = (uint64_t)now;
        }
        double delta_ms = now - g_last_tick_time_ms;
        float delta_seconds = (float)delta_ms / 1000.0f;
        g_last_tick_time_ms = (uint64_t)now;

        // Update game time tracking (for Ext.Timer.GameTime/DeltaTime)
        timer_tick(delta_ms);

        events_fire_tick(L, delta_seconds);

        // Poll for one-frame event components (Issue #51)
        events_poll_oneframe_components(L);

        // Process pending network messages (Issue #6: NetChannel API)
        // Note: In full implementation, client_L would be the client Lua state
        lua_net_process_messages(L, L);  // Both server and client in same process for now

        // Deferred session initialization (Issue #65)
        // Performs entity/stats/staticdata init + fires SessionLoaded here
        // instead of during fake_Load. This prevents ~2,800 kernel calls
        // from blocking the timing-sensitive COsiris::Load window.
        deferred_session_init_tick();

        // Deferred network initialization (Issue #65)
        // Performs net capture/hook/insert here; depends on Running state
        // which is set by deferred_session_init_tick above.
        if (net_hooks_deferred_tick()) {
            LOG_NET_INFO("Network hooks initialized via deferred tick");
        }
    }

    // Capture COsiris pointer if we haven't already
    if (!g_COsiris && thisPtr) {
        g_COsiris = thisPtr;
        g_OsiFunctionMan = thisPtr;  // Try using COsiris as function manager
        LOG_OSIRIS_DEBUG(">>> Captured COsiris from Event: %p", g_COsiris);
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
            LOG_OSIRIS_DEBUG(">>> Event[%d]: %s (id=%u, arity=%d, args=%p)",
                       event_call_count, funcName, funcId, arity, (void*)args);
        } else {
            LOG_OSIRIS_DEBUG(">>> Event[%d]: id=%u (arity=%d, args=%p)",
                       event_call_count, funcId, arity, (void*)args);
        }

        // Dump first few bytes of args for structure analysis (first 10 events only)
        if (args && event_call_count <= 10) {
            uint8_t *p = (uint8_t *)args;
            LOG_OSIRIS_DEBUG("    args bytes[0-31]: %02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x",
                       p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                       p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
                       p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
                       p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);

            // Try to read as our assumed structure
            LOG_OSIRIS_DEBUG("    Assumed: nextParam=%p, typeId=%u, stringVal=%p",
                       (void*)args->nextParam, args->value.typeId,
                       (void*)args->value.stringVal);

            // If it looks like a string, try to print it
            if (args->value.typeId >= OSI_TYPE_STRING &&
                args->value.typeId <= OSI_TYPE_GUIDSTRING &&
                args->value.stringVal) {
                // Safety check - verify it's a readable address
                LOG_OSIRIS_DEBUG("    String arg: %.80s", args->value.stringVal);
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
                    LOG_OSIRIS_DEBUG("Arg[%d]: %s", argIdx, arg->value.stringVal);

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
                    LOG_OSIRIS_DEBUG("Arg[%d]: (int) %d", argIdx, arg->value.int32Val);
                } else if (arg->value.typeId == OSI_TYPE_INTEGER64) {
                    LOG_OSIRIS_DEBUG("Arg[%d]: (int64) %lld", argIdx, arg->value.int64Val);
                }
                arg = arg->nextParam;
                argIdx++;
            }

            g_currentDialogPlayerCount = 1;  // Single-player default
            LOG_OSIRIS_DEBUG("Started with %d participants", g_dialogParticipantCount);
        } else if (strcmp(funcName, "AutomatedDialogEnded") == 0) {
            // Clear dialog state when dialog ends
            LOG_OSIRIS_DEBUG("Ended: %s", g_currentDialogResource);
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
    LOG_CORE_DEBUG("Loaded images: %u", count);

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
                LOG_CORE_DEBUG("  [%u] %s", i, name);
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

    LOG_OSIRIS_INFO("Resolving Osiris function pointers...");

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
        LOG_OSIRIS_DEBUG("  OsiFunctionMan calculated from base: %p (base=0x%lx)",
                   (void*)g_pOsiFunctionMan, (unsigned long)libBase);
    }

    // Update function cache module with new runtime pointers
    osi_func_cache_set_runtime(pfn_pFunctionData, g_pOsiFunctionMan);
    osi_func_cache_set_known_events(g_knownEvents);

    LOG_OSIRIS_INFO("Osiris function pointers resolved:");
    LOG_OSIRIS_DEBUG("  pFunctionData: %p%s", (void*)pfn_pFunctionData,
                pfn_pFunctionData ? "" : " (NOT FOUND)");
    LOG_OSIRIS_DEBUG("  OsiFunctionMan global: %p", (void*)g_pOsiFunctionMan);
    if (g_pOsiFunctionMan) {
        LOG_OSIRIS_DEBUG("  OsiFunctionMan instance: %p", *g_pOsiFunctionMan);
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
        LOG_HOOKS_ERROR("Could not get libOsiris handle for hooking");
        return;
    }

    // ALWAYS resolve function pointers (ASLR changes addresses between launches)
    resolve_osiris_function_pointers(osiris);

    // Only install actual hooks once
    if (hooks_installed) {
        LOG_HOOKS_DEBUG("Hooks already installed, skipping hook installation");
        return;
    }

    // BG3SE_NO_HOOKS: Skip all Dobby hook installation (Issue #65 diagnostic).
    // The dylib still loads, Lua initializes, but no functions are patched.
    // This tests whether the hooks themselves cause the game to abort.
    static int no_hooks = -1;
    if (no_hooks < 0) no_hooks = (getenv("BG3SE_NO_HOOKS") != NULL);
    if (no_hooks) {
        LOG_HOOKS_INFO("BG3SE_NO_HOOKS=1: ALL Dobby hooks SKIPPED. "
                       "Lua runtime is active but Osiris/Event interception disabled.");
        hooks_installed = 1;  // Prevent re-entry
        // Still initialize subsystems (entity, stats, etc.) for diagnostics
        goto init_subsystems;
    }

    LOG_HOOKS_INFO("Installing Dobby hooks...");

    // Test pattern scanner infrastructure
    LOG_HOOKS_DEBUG("=== Pattern Scanner Test ===");
    void *text_start = NULL;
    size_t text_size = 0;
    if (get_macho_text_section("libOsiris.dylib", &text_start, &text_size)) {
        LOG_HOOKS_DEBUG("  libOsiris __TEXT,__text: %p (size: 0x%zx / %zu MB)",
                    text_start, text_size, text_size / (1024 * 1024));
    } else {
        LOG_HOOKS_WARN(" Could not get libOsiris __TEXT section");
    }

    // Get function addresses (C++ mangled names)
    void *initGameAddr = dlsym(osiris, "_ZN7COsiris8InitGameEv");
    void *loadAddr = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");
    void *eventAddr = dlsym(osiris, "_ZN7COsiris5EventEjP16COsiArgumentDesc");

    // RegisterDIVFunctions: engine registers Call/Query dispatch pointers here.
    // We hook this to capture DivFunctions::Call/Query which take OsiArgumentDesc* (Issue #66).
    // Try COsiris:: first (matches Windows BG3SE), fall back to CDIV::
    void *regDivAddr = dlsym(osiris, "_ZN7COsiris20RegisterDIVFunctionsEP19TOsirisInitFunction");
    if (!regDivAddr) {
        regDivAddr = dlsym(osiris, "_ZN4CDIV20RegisterDIVFunctionsEP19TOsirisInitFunction");
    }

    // Pattern scanner verification: create pattern from known function bytes
    if (text_start && text_size > 0 && eventAddr) {
        // Read first 8 bytes of COsiris::Event and convert to pattern
        const unsigned char *event_bytes = (const unsigned char *)eventAddr;
        char test_pattern[64];
        snprintf(test_pattern, sizeof(test_pattern),
                 "%02X %02X %02X %02X %02X %02X %02X %02X",
                 event_bytes[0], event_bytes[1], event_bytes[2], event_bytes[3],
                 event_bytes[4], event_bytes[5], event_bytes[6], event_bytes[7]);

        LOG_HOOKS_DEBUG("  COsiris::Event first 8 bytes: %s", test_pattern);

        // Try to find this pattern
        void *found = find_pattern_str(text_start, text_size, test_pattern);
        if (found == eventAddr) {
            LOG_HOOKS_DEBUG("  Pattern scanner VERIFIED: found COsiris::Event at correct address");
        } else if (found) {
            LOG_HOOKS_DEBUG("  Pattern found at %p (expected %p) - multiple matches?", found, eventAddr);
        } else {
            LOG_HOOKS_WARN(" Pattern scanner failed to find COsiris::Event");
        }
    }
    LOG_HOOKS_DEBUG("=== End Pattern Scanner Test ===");

    // Resolve function pointers for Osiris calls (not hooked, just called)
    // Resolve InternalQuery/InternalCall (only needed for hooks, not for function cache)
    // Use pattern-based fallback if dlsym fails
    pfn_InternalQuery = (InternalQueryFn)resolve_osiris_symbol(osiris, &g_osirisPatterns[0]);
    if (!pfn_InternalQuery) {
        LOG_HOOKS_WARN(" InternalQuery not found");
    }

    pfn_InternalCall = (InternalCallFn)resolve_osiris_symbol(osiris, &g_osirisPatterns[1]);
    if (!pfn_InternalCall) {
        LOG_HOOKS_WARN(" InternalCall not found");
    }

    LOG_OSIRIS_DEBUG("  InternalQuery: %p%s", (void*)pfn_InternalQuery,
                pfn_InternalQuery ? "" : " (NOT FOUND)");
    LOG_OSIRIS_DEBUG("  InternalCall: %p%s", (void*)pfn_InternalCall,
                pfn_InternalCall ? "" : " (NOT FOUND)");

    int hook_count = 0;

    // Hook COsiris::InitGame
    if (initGameAddr) {
        int result = DobbyHook(initGameAddr, (void *)fake_InitGame, &orig_InitGame);
        if (result == 0) {
            LOG_HOOKS_INFO("  COsiris::InitGame hooked successfully (orig: %p)", orig_InitGame);
            hook_count++;
        } else {
            LOG_HOOKS_ERROR(" Failed to hook COsiris::InitGame (error: %d)", result);
        }
    } else {
        LOG_HOOKS_DEBUG("  COsiris::InitGame not found, skipping");
    }

    // Hook COsiris::Load
    if (loadAddr) {
        int result = DobbyHook(loadAddr, (void *)fake_Load, &orig_Load);
        if (result == 0) {
            LOG_HOOKS_INFO("  COsiris::Load hooked successfully (orig: %p)", orig_Load);
            hook_count++;
        } else {
            LOG_HOOKS_ERROR(" Failed to hook COsiris::Load (error: %d)", result);
        }
    } else {
        LOG_HOOKS_DEBUG("  COsiris::Load not found, skipping");
    }

    // Hook COsiris::Event - this is the key hook for event interception!
    if (eventAddr) {
        int result = DobbyHook(eventAddr, (void *)fake_Event, &orig_Event);
        if (result == 0) {
            LOG_HOOKS_INFO("  COsiris::Event hooked successfully (orig: %p)", orig_Event);
            hook_count++;
        } else {
            LOG_HOOKS_ERROR(" Failed to hook COsiris::Event (error: %d)", result);
        }
    } else {
        LOG_HOOKS_DEBUG("  COsiris::Event not found, skipping");
    }

    // Hook RegisterDIVFunctions - captures Call/Query dispatch pointers (Issue #66)
    if (regDivAddr) {
        int result = DobbyHook(regDivAddr, (void *)fake_RegisterDIVFunctions, &orig_RegisterDIVFunctions);
        if (result == 0) {
            LOG_HOOKS_INFO("  RegisterDIVFunctions hooked successfully (orig: %p)", orig_RegisterDIVFunctions);
            hook_count++;
        } else {
            LOG_HOOKS_ERROR(" Failed to hook RegisterDIVFunctions (error: %d)", result);
        }
    } else {
        LOG_HOOKS_WARN(" RegisterDIVFunctions not found — Osiris calls will use InternalCall fallback (may crash!)");
    }

    LOG_HOOKS_INFO("Hooks installed: %d/4", hook_count);
    hooks_installed = 1;

init_subsystems:
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

                LOG_CORE_INFO("Found BG3 executable (index %u): %s", i, name);
                LOG_CORE_DEBUG("  Base: %p, Slide: 0x%lx", binary_base, (long)slide);

                int result = entity_system_init(binary_base);
                if (result == 0) {
                    LOG_ENTITY_INFO("Entity system initialized (function pointers ready)");
                } else {
                    LOG_ENTITY_WARN("Entity system initialization failed: %d", result);
                }

                // Initialize stats manager
                stats_manager_init(binary_base);
                if (stats_manager_ready()) {
                    LOG_STATS_INFO("Stats system initialized and ready");
                } else {
                    LOG_STATS_INFO("Stats system initialized (will be ready after game loads)");
                }

                // Initialize prototype managers (for Ext.Stats.Sync)
                prototype_managers_init(binary_base);
                if (prototype_managers_ready()) {
                    LOG_STATS_INFO("Prototype managers initialized");
                } else {
                    LOG_STATS_INFO("Prototype managers initialized (singletons resolve at runtime)");
                }

                // Initialize static data manager (for Ext.StaticData)
                staticdata_manager_init(binary_base);
                LOG_CORE_INFO("StaticData manager initialized (managers captured via hooks)");

                // Initialize template manager (for Ext.Template)
                template_manager_init(binary_base);
                LOG_CORE_INFO("Template manager initialized (capture via Frida)");

                // Initialize resource manager (for Ext.Resource)
                resource_manager_init(binary_base);
                LOG_CORE_INFO("Resource manager initialized");

                // Initialize level manager (for Ext.Level)
                level_manager_init(binary_base);
                LOG_CORE_INFO("Level manager initialized");

                // Initialize audio manager (for Ext.Audio)
                audio_manager_init(binary_base);
                LOG_CORE_INFO("Audio manager initialized");

                // Initialize localization system
                localization_init(binary_base);
                LOG_CORE_INFO("Localization system initialized");

                // Initialize functor hooks (ExecuteFunctor/AfterExecuteFunctor events)
                if (functor_hooks_init(L)) {
                    LOG_HOOKS_INFO("Functor hooks initialized");
                } else {
                    LOG_HOOKS_WARN("Functor hooks initialization failed (events won't fire)");
                }
                found = true;
            }
        }

        if (!found) {
            LOG_CORE_WARN("Could not find BG3 main executable for entity system");
        }
    }
#else
    LOG_HOOKS_INFO("Hooks DISABLED (ENABLE_HOOKS=0)");
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
        LOG_OSIRIS_INFO("libOsiris.dylib handle obtained!");

        // Look up key exported C symbols
        void *debugHook = dlsym(osiris, "DebugHook");
        void *createRule = dlsym(osiris, "CreateRule");
        void *defineFunction = dlsym(osiris, "DefineFunction");
        void *setInitSection = dlsym(osiris, "SetInitSection");

        // Try C++ mangled names for COsiris methods
        void *initGame = dlsym(osiris, "_ZN7COsiris8InitGameEv");
        void *load = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");

        LOG_OSIRIS_DEBUG("Osiris symbol addresses:");
        LOG_OSIRIS_DEBUG("  DebugHook: %p", debugHook);
        LOG_OSIRIS_DEBUG("  CreateRule: %p", createRule);
        LOG_OSIRIS_DEBUG("  DefineFunction: %p", defineFunction);
        LOG_OSIRIS_DEBUG("  SetInitSection: %p", setInitSection);
        LOG_OSIRIS_DEBUG("  COsiris::InitGame: %p", initGame);
        LOG_OSIRIS_DEBUG("  COsiris::Load: %p", load);

        // Count how many we found
        int found = 0;
        if (debugHook) found++;
        if (createRule) found++;
        if (defineFunction) found++;
        if (setInitSection) found++;
        if (initGame) found++;
        if (load) found++;

        LOG_OSIRIS_INFO("Found %d/6 key Osiris symbols", found);

        // Don't close - we need this handle for hooks
        // dlclose(osiris);
    } else {
        LOG_OSIRIS_DEBUG("libOsiris.dylib not yet loaded");
        LOG_OSIRIS_DEBUG("  dlerror: %s", dlerror());
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
                LOG_OSIRIS_INFO(">>> libOsiris.dylib loaded dynamically! Slide: 0x%lx", (long)slide);
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

    LOG_CORE_INFO("=== %s v%s initialized ===", BG3SE_NAME, BG3SE_VERSION);
    LOG_CORE_INFO("Running in process: %s (PID: %d)", getprogname(), getpid());

    // Get architecture
#if defined(__arm64__)
    LOG_CORE_INFO("Architecture: ARM64 (Apple Silicon)");
#elif defined(__x86_64__)
    LOG_CORE_INFO("Architecture: x86_64 (Rosetta/Intel)");
#else
    LOG_CORE_INFO("Architecture: Unknown");
#endif

    // Log Dobby availability
    LOG_HOOKS_INFO("Dobby inline hooking: enabled");

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

    LOG_HOOKS_INFO("Image load callback registered");

    // NOTE: ImGui Metal backend is initialized lazily via Ext.IMGUI.Show()
    // Calling imgui_metal_init() here during dylib constructor causes crashes
    // because the game's Metal rendering isn't ready yet.

    LOG_CORE_INFO("=== Initialization complete ===");
}

/**
 * Destructor - runs when dylib is unloaded (usually at process exit)
 */
__attribute__((destructor))
static void bg3se_cleanup(void) {
    LOG_CORE_INFO("=== %s shutting down ===", BG3SE_NAME);

    // Fire Shutdown event before cleanup (if Lua is still running)
    // This allows mods to perform cleanup tasks (save state, close resources)
    if (L) {
        events_fire(L, EVENT_SHUTDOWN);
    }

    LOG_HOOKS_INFO("Final hook call counts:");
    LOG_OSIRIS_DEBUG("  COsiris::InitGame: %d calls", initGame_call_count);
    LOG_OSIRIS_DEBUG("  COsiris::Load: %d calls", load_call_count);
    LOG_HOOKS_DEBUG("  COsiris::Event: %d calls", event_call_count);

    // Log function cache summary
    LOG_OSIRIS_INFO("Osiris functions: %d cached, %d unique IDs observed",
                osi_func_get_cache_count(), osi_func_get_seen_count());

    // Remove network hooks (ExtenderProtocol from ProtocolList)
    net_hooks_remove();

    // Shutdown ImGui Metal backend
    imgui_metal_shutdown();

    // Shutdown Lua
    shutdown_lua();
}
