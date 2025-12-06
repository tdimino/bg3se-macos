/**
 * BG3SE-macOS - PersistentVars Module Implementation
 *
 * Provides file-based persistence for mod variables.
 * Storage: ~/Library/Application Support/BG3SE/persistentvars/{ModTable}.json
 */

#include "lua_persistentvars.h"
#include "lua_json.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

// ============================================================================
// Constants
// ============================================================================

#define PERSIST_DIR_NAME "persistentvars"
#define PERSIST_SAVE_INTERVAL_MS 30000  // Auto-save every 30 seconds
#define PERSIST_MAX_FILE_SIZE (10 * 1024 * 1024)  // 10MB max per mod

// ============================================================================
// Static State
// ============================================================================

static char s_persistDir[PATH_MAX] = {0};
static int s_initialized = 0;
static int s_loaded = 0;
static int s_dirty = 0;
static uint64_t s_lastSaveTime = 0;

// ============================================================================
// Helper: Get monotonic time in milliseconds
// ============================================================================

#include <mach/mach_time.h>

static uint64_t get_monotonic_ms(void) {
    static mach_timebase_info_data_t s_timebase = {0};
    if (s_timebase.denom == 0) {
        mach_timebase_info(&s_timebase);
    }
    uint64_t now = mach_absolute_time();
    return (now * s_timebase.numer) / (s_timebase.denom * 1000000ULL);
}

// ============================================================================
// Helper: Ensure directory exists
// ============================================================================

static int ensure_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    return mkdir(path, 0755);
}

// ============================================================================
// Helper: Get BG3SE support directory
// ============================================================================

static const char *get_support_dir(void) {
    static char s_supportDir[PATH_MAX] = {0};
    if (s_supportDir[0] == '\0') {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(s_supportDir, sizeof(s_supportDir),
                     "%s/Library/Application Support/BG3SE", home);
        }
    }
    return s_supportDir;
}

// ============================================================================
// Helper: Atomic file write (temp + rename)
// ============================================================================

static int atomic_write_file(const char *path, const char *content, size_t len) {
    char temp_path[PATH_MAX];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    FILE *f = fopen(temp_path, "w");
    if (!f) {
        log_message("[PersistentVars] Failed to create temp file: %s (%s)",
                    temp_path, strerror(errno));
        return -1;
    }

    size_t written = fwrite(content, 1, len, f);
    fclose(f);

    if (written != len) {
        log_message("[PersistentVars] Write incomplete: %zu/%zu bytes", written, len);
        unlink(temp_path);
        return -1;
    }

    // Atomic rename
    if (rename(temp_path, path) != 0) {
        log_message("[PersistentVars] Rename failed: %s -> %s (%s)",
                    temp_path, path, strerror(errno));
        unlink(temp_path);
        return -1;
    }

    return 0;
}

// ============================================================================
// Helper: Read file contents
// ============================================================================

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > PERSIST_MAX_FILE_SIZE) {
        fclose(f);
        return NULL;
    }

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }

    size_t read_size = fread(content, 1, size, f);
    fclose(f);

    content[read_size] = '\0';
    if (out_len) *out_len = read_size;

    return content;
}

// ============================================================================
// Helper: Get ModTable from filename (strip .json extension)
// ============================================================================

static void get_modtable_from_filename(const char *filename, char *out, size_t out_size) {
    size_t len = strlen(filename);
    if (len > 5 && strcmp(filename + len - 5, ".json") == 0) {
        size_t copy_len = len - 5;
        if (copy_len >= out_size) copy_len = out_size - 1;
        memcpy(out, filename, copy_len);
        out[copy_len] = '\0';
    } else {
        strncpy(out, filename, out_size - 1);
        out[out_size - 1] = '\0';
    }
}

// ============================================================================
// Helper: Sanitize ModTable name for filename
// ============================================================================

static void sanitize_filename(const char *modtable, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; modtable[i] && j < out_size - 1; i++) {
        char c = modtable[i];
        // Allow alphanumeric, underscore, dash
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-') {
            out[j++] = c;
        } else if (c == ' ') {
            out[j++] = '_';  // Replace spaces with underscores
        }
        // Skip other characters
    }
    out[j] = '\0';
}

// ============================================================================
// Initialization
// ============================================================================

void persist_init(void) {
    if (s_initialized) return;

    const char *support = get_support_dir();
    if (!support || support[0] == '\0') {
        log_message("[PersistentVars] Failed to get support directory");
        return;
    }

    // Ensure support directory exists
    if (ensure_directory(support) != 0) {
        log_message("[PersistentVars] Failed to create support dir: %s", support);
        return;
    }

    // Create persistentvars subdirectory
    snprintf(s_persistDir, sizeof(s_persistDir), "%s/%s", support, PERSIST_DIR_NAME);
    if (ensure_directory(s_persistDir) != 0) {
        log_message("[PersistentVars] Failed to create persist dir: %s", s_persistDir);
        return;
    }

    s_initialized = 1;
    s_lastSaveTime = get_monotonic_ms();
    log_message("[PersistentVars] Initialized: %s", s_persistDir);
}

// ============================================================================
// Core: Restore all persistent variables
// ============================================================================

void persist_restore_all(lua_State *L) {
    if (!s_initialized) {
        persist_init();
        if (!s_initialized) return;
    }

    // Get global Mods table
    lua_getglobal(L, "Mods");
    if (!lua_istable(L, -1)) {
        log_message("[PersistentVars] Mods table not found - creating empty table");
        lua_pop(L, 1);
        lua_newtable(L);
        lua_setglobal(L, "Mods");
        lua_getglobal(L, "Mods");
    }
    int mods_idx = lua_gettop(L);

    // Iterate over JSON files in persist directory
    DIR *dir = opendir(s_persistDir);
    if (!dir) {
        log_message("[PersistentVars] No persist directory - nothing to restore");
        lua_pop(L, 1);
        s_loaded = 1;
        return;
    }

    int restored_count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        // Skip non-JSON files
        size_t name_len = strlen(entry->d_name);
        if (name_len < 6 || strcmp(entry->d_name + name_len - 5, ".json") != 0) {
            continue;
        }

        // Get ModTable name from filename
        char modtable[256];
        get_modtable_from_filename(entry->d_name, modtable, sizeof(modtable));

        // Build full path
        char filepath[PATH_MAX];
        snprintf(filepath, sizeof(filepath), "%s/%s", s_persistDir, entry->d_name);

        // Read file content
        size_t json_len;
        char *json = read_file(filepath, &json_len);
        if (!json) {
            log_message("[PersistentVars] Failed to read: %s", filepath);
            continue;
        }

        // Parse JSON
        const char *result = json_parse_value(L, json);
        if (!result || !lua_istable(L, -1)) {
            log_message("[PersistentVars] Failed to parse JSON for mod: %s", modtable);
            if (lua_gettop(L) > mods_idx) {
                lua_pop(L, 1);  // Pop the failed parse result
            }
            free(json);
            continue;
        }

        // Get or create Mods[modtable] table
        lua_getfield(L, mods_idx, modtable);
        if (!lua_istable(L, -1)) {
            lua_pop(L, 1);  // Pop nil
            lua_newtable(L);
            lua_pushvalue(L, -1);  // Dup for setfield
            lua_setfield(L, mods_idx, modtable);
        }

        // Set PersistentVars (parsed table is at -2, mod table at -1)
        lua_pushvalue(L, -2);  // Push parsed table
        lua_setfield(L, -2, "PersistentVars");

        lua_pop(L, 2);  // Pop mod table and parsed table
        free(json);

        log_message("[PersistentVars] Restored: %s (%zu bytes)", modtable, json_len);
        restored_count++;
    }

    closedir(dir);
    lua_pop(L, 1);  // Pop Mods table

    s_loaded = 1;
    s_dirty = 0;  // Just loaded, not dirty yet
    log_message("[PersistentVars] Restore complete: %d mods", restored_count);
}

// ============================================================================
// Core: Save all persistent variables
// ============================================================================

void persist_save_all(lua_State *L) {
    if (!s_initialized) {
        persist_init();
        if (!s_initialized) return;
    }

    // Get global Mods table
    lua_getglobal(L, "Mods");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    int mods_idx = lua_gettop(L);

    int saved_count = 0;

    // Iterate over Mods table
    lua_pushnil(L);
    while (lua_next(L, mods_idx) != 0) {
        // Stack: -2 = key (ModTable name), -1 = value (mod table)

        if (!lua_isstring(L, -2) || !lua_istable(L, -1)) {
            lua_pop(L, 1);  // Pop value, keep key for next iteration
            continue;
        }

        const char *modtable = lua_tostring(L, -2);
        int mod_idx = lua_gettop(L);

        // Check if PersistentVars exists
        lua_getfield(L, mod_idx, "PersistentVars");
        if (!lua_istable(L, -1)) {
            lua_pop(L, 2);  // Pop nil and mod table
            continue;
        }

        // Stringify PersistentVars
        luaL_Buffer b;
        luaL_buffinit(L, &b);
        json_stringify_value(L, lua_gettop(L), &b);
        luaL_pushresult(&b);

        const char *json = lua_tostring(L, -1);
        size_t json_len = lua_rawlen(L, -1);

        // Sanitize ModTable name for filename
        char safe_name[256];
        sanitize_filename(modtable, safe_name, sizeof(safe_name));

        if (safe_name[0] == '\0') {
            log_message("[PersistentVars] Invalid ModTable name, skipping: %s", modtable);
            lua_pop(L, 3);  // Pop json string, PersistentVars, mod table
            continue;
        }

        // Build filepath
        char filepath[PATH_MAX];
        snprintf(filepath, sizeof(filepath), "%s/%s.json", s_persistDir, safe_name);

        // Write atomically
        if (atomic_write_file(filepath, json, json_len) == 0) {
            log_message("[PersistentVars] Saved: %s (%zu bytes)", safe_name, json_len);
            saved_count++;
        } else {
            log_message("[PersistentVars] Failed to save: %s", safe_name);
        }

        lua_pop(L, 3);  // Pop json string, PersistentVars, mod table
    }

    lua_pop(L, 1);  // Pop Mods table

    s_dirty = 0;
    s_lastSaveTime = get_monotonic_ms();

    if (saved_count > 0) {
        log_message("[PersistentVars] Save complete: %d mods", saved_count);
    }
}

// ============================================================================
// Periodic save check
// ============================================================================

void persist_tick(lua_State *L) {
    if (!s_initialized || !s_dirty) return;

    uint64_t now = get_monotonic_ms();
    if (now - s_lastSaveTime >= PERSIST_SAVE_INTERVAL_MS) {
        persist_save_all(L);
    }
}

// ============================================================================
// State queries
// ============================================================================

int persist_is_loaded(void) {
    return s_loaded;
}

void persist_mark_dirty(void) {
    s_dirty = 1;
}

// ============================================================================
// Lua API: Ext.Vars.SyncPersistentVars()
// ============================================================================

static int lua_vars_sync(lua_State *L) {
    log_message("[PersistentVars] SyncPersistentVars() called");
    persist_save_all(L);
    lua_pushboolean(L, 1);
    return 1;
}

// ============================================================================
// Lua API: Ext.Vars.IsPersistentVarsLoaded()
// ============================================================================

static int lua_vars_is_loaded(lua_State *L) {
    lua_pushboolean(L, s_loaded);
    return 1;
}

// ============================================================================
// Lua API: Ext.Vars.ReloadPersistentVars()
// ============================================================================

static int lua_vars_reload(lua_State *L) {
    log_message("[PersistentVars] ReloadPersistentVars() called");
    s_loaded = 0;
    persist_restore_all(L);
    lua_pushboolean(L, s_loaded);
    return 1;
}

// ============================================================================
// Lua API: Ext.Vars.MarkDirty() - for testing
// ============================================================================

static int lua_vars_mark_dirty(lua_State *L) {
    (void)L;  // unused
    persist_mark_dirty();
    return 0;
}

// ============================================================================
// Registration
// ============================================================================

void lua_persistentvars_register(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Vars table
    lua_newtable(L);

    lua_pushcfunction(L, lua_vars_sync);
    lua_setfield(L, -2, "SyncPersistentVars");

    lua_pushcfunction(L, lua_vars_is_loaded);
    lua_setfield(L, -2, "IsPersistentVarsLoaded");

    lua_pushcfunction(L, lua_vars_reload);
    lua_setfield(L, -2, "ReloadPersistentVars");

    lua_pushcfunction(L, lua_vars_mark_dirty);
    lua_setfield(L, -2, "MarkDirty");

    lua_setfield(L, ext_table_index, "Vars");

    // Initialize the module
    persist_init();

    log_message("[PersistentVars] Ext.Vars namespace registered");
}
