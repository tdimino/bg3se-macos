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
#include <dirent.h>
#include <sys/stat.h>
#include <zlib.h>

// LZ4 decompression
#include "lz4/lz4.h"

// Dobby hooking framework
#include "Dobby/include/dobby.h"

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

// Version info
#define BG3SE_VERSION "0.9.0"
#define BG3SE_NAME "BG3SE-macOS"

// Log file for debugging
#define LOG_FILE "/tmp/bg3se_macos.log"

// Enable hooks (set to 0 to disable for testing)
#define ENABLE_HOOKS 1

// Forward declarations
static void log_message(const char *format, ...);
static void enumerate_loaded_images(void);
static void check_osiris_library(void);
static void install_hooks(void);
static void init_lua(void);
static void shutdown_lua(void);
static void detect_enabled_mods(void);

// Original function pointers (filled by Dobby)
static void *orig_InitGame = NULL;
static void *orig_Load = NULL;

// Hook call counters
static int initGame_call_count = 0;
static int load_call_count = 0;

// Track if hooks are already installed
static int hooks_installed = 0;

// Lua state
static lua_State *L = NULL;

// Module loading state
#define MAX_LOADED_MODULES 256
#define MAX_PATH_LEN 1024
static char loaded_modules[MAX_LOADED_MODULES][MAX_PATH_LEN];
static int loaded_module_count = 0;
static char current_mod_name[256] = "";
static char current_mod_lua_base[MAX_PATH_LEN] = "";  // Base path for current mod's Lua folder
static char mods_base_path[MAX_PATH_LEN] = "";

// Detected mods from modsettings.lsx
#define MAX_MODS 128
#define MAX_MOD_NAME_LEN 256
static char detected_mods[MAX_MODS][MAX_MOD_NAME_LEN];
static int detected_mod_count = 0;

// Detected SE mods (mods with ScriptExtender/Config.json containing "Lua")
static char se_mods[MAX_MODS][MAX_MOD_NAME_LEN];
static int se_mod_count = 0;

// Current PAK file for mod loading (used by Ext.Require)
static char current_mod_pak_path[MAX_PATH_LEN] = "";

// ============================================================================
// PAK File Reading (LSPK v18 format)
// ============================================================================

// LSPK signature: "LSPK" = 0x4B50534C
#define LSPK_SIGNATURE 0x4B50534C
#define LSPK_ENTRY_SIZE 272

// PAK file entry
typedef struct {
    char name[256];
    uint64_t offset;
    uint8_t archive_part;
    uint8_t compression;  // 0=none, 1=zlib, 2=LZ4
    uint32_t disk_size;
    uint32_t uncompressed_size;
} PakEntry;

// PAK file handle
typedef struct {
    FILE *file;
    uint32_t version;
    uint64_t file_list_offset;
    uint32_t file_list_size;
    uint32_t num_files;
    PakEntry *entries;
} PakFile;

/**
 * Open a PAK file and read its header and file list
 * Returns NULL on failure
 */
static PakFile *pak_open(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    // Read header (40 bytes)
    uint8_t header[40];
    if (fread(header, 1, 40, f) != 40) {
        fclose(f);
        return NULL;
    }

    // Check signature
    uint32_t signature;
    memcpy(&signature, header, 4);
    if (signature != LSPK_SIGNATURE) {
        fclose(f);
        return NULL;
    }

    // Parse header
    uint32_t version;
    uint64_t file_list_offset;
    uint32_t file_list_size;

    memcpy(&version, header + 4, 4);
    memcpy(&file_list_offset, header + 8, 8);
    memcpy(&file_list_size, header + 16, 4);

    // Seek to file list
    fseek(f, file_list_offset, SEEK_SET);

    // Read file count and compressed size
    uint32_t num_files, compressed_size;
    if (fread(&num_files, 4, 1, f) != 1 || fread(&compressed_size, 4, 1, f) != 1) {
        fclose(f);
        return NULL;
    }

    // Read compressed file list
    uint8_t *compressed_data = (uint8_t *)malloc(compressed_size);
    if (!compressed_data) {
        fclose(f);
        return NULL;
    }

    if (fread(compressed_data, 1, compressed_size, f) != compressed_size) {
        free(compressed_data);
        fclose(f);
        return NULL;
    }

    // Decompress file list (LZ4)
    uint32_t uncompressed_size = num_files * LSPK_ENTRY_SIZE;
    uint8_t *decompressed = (uint8_t *)malloc(uncompressed_size);
    if (!decompressed) {
        free(compressed_data);
        fclose(f);
        return NULL;
    }

    int result = LZ4_decompress_safe((const char *)compressed_data, (char *)decompressed,
                                      compressed_size, uncompressed_size);
    free(compressed_data);

    if (result < 0) {
        free(decompressed);
        fclose(f);
        return NULL;
    }

    // Parse entries
    PakEntry *entries = (PakEntry *)calloc(num_files, sizeof(PakEntry));
    if (!entries) {
        free(decompressed);
        fclose(f);
        return NULL;
    }

    for (uint32_t i = 0; i < num_files; i++) {
        uint8_t *entry_data = decompressed + (i * LSPK_ENTRY_SIZE);

        // Name: 256 bytes, null-terminated
        memcpy(entries[i].name, entry_data, 255);
        entries[i].name[255] = '\0';

        // Offset: 48-bit value (bytes 256-261)
        uint32_t offset_lo;
        uint16_t offset_hi;
        memcpy(&offset_lo, entry_data + 256, 4);
        memcpy(&offset_hi, entry_data + 260, 2);
        entries[i].offset = offset_lo | ((uint64_t)offset_hi << 32);

        entries[i].archive_part = entry_data[262];
        entries[i].compression = entry_data[263] & 0x0F;

        memcpy(&entries[i].disk_size, entry_data + 264, 4);
        memcpy(&entries[i].uncompressed_size, entry_data + 268, 4);
    }

    free(decompressed);

    // Create PakFile struct
    PakFile *pak = (PakFile *)malloc(sizeof(PakFile));
    if (!pak) {
        free(entries);
        fclose(f);
        return NULL;
    }

    pak->file = f;
    pak->version = version;
    pak->file_list_offset = file_list_offset;
    pak->file_list_size = file_list_size;
    pak->num_files = num_files;
    pak->entries = entries;

    return pak;
}

/**
 * Close a PAK file and free resources
 */
static void pak_close(PakFile *pak) {
    if (pak) {
        if (pak->file) fclose(pak->file);
        if (pak->entries) free(pak->entries);
        free(pak);
    }
}

/**
 * Find an entry in a PAK file by path
 * Returns entry index or -1 if not found
 */
static int pak_find_entry(PakFile *pak, const char *path) {
    if (!pak || !path) return -1;

    for (uint32_t i = 0; i < pak->num_files; i++) {
        if (strcmp(pak->entries[i].name, path) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Read a file from a PAK archive
 * Returns allocated buffer with file contents, or NULL on failure
 * Caller must free the returned buffer
 * Sets *out_size to the uncompressed size
 */
static char *pak_read_file(PakFile *pak, int entry_idx, size_t *out_size) {
    if (!pak || entry_idx < 0 || entry_idx >= (int)pak->num_files) return NULL;

    PakEntry *entry = &pak->entries[entry_idx];

    // Seek to file data
    fseek(pak->file, entry->offset, SEEK_SET);

    // Read compressed/raw data
    uint8_t *disk_data = (uint8_t *)malloc(entry->disk_size);
    if (!disk_data) return NULL;

    if (fread(disk_data, 1, entry->disk_size, pak->file) != entry->disk_size) {
        free(disk_data);
        return NULL;
    }

    char *content = NULL;

    if (entry->compression == 0) {
        // Uncompressed
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            memcpy(content, disk_data, entry->uncompressed_size);
            content[entry->uncompressed_size] = '\0';
            if (out_size) *out_size = entry->uncompressed_size;
        }
    } else if (entry->compression == 1) {
        // zlib
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            uLongf dest_len = entry->uncompressed_size;
            if (uncompress((Bytef *)content, &dest_len, disk_data, entry->disk_size) == Z_OK) {
                content[dest_len] = '\0';
                if (out_size) *out_size = dest_len;
            } else {
                free(content);
                content = NULL;
            }
        }
    } else if (entry->compression == 2) {
        // LZ4
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            int result = LZ4_decompress_safe((const char *)disk_data, content,
                                              entry->disk_size, entry->uncompressed_size);
            if (result > 0) {
                content[result] = '\0';
                if (out_size) *out_size = result;
            } else {
                free(content);
                content = NULL;
            }
        }
    }

    free(disk_data);
    return content;
}

/**
 * Check if a PAK file contains a specific file path
 */
static int pak_contains_file(PakFile *pak, const char *path) {
    return pak_find_entry(pak, path) >= 0;
}

/**
 * Check if a PAK file contains ScriptExtender/Config.json with "Lua" feature
 */
static int pak_has_script_extender(const char *pak_path, const char *mod_name) {
    PakFile *pak = pak_open(pak_path);
    if (!pak) return 0;

    // Build path to Config.json
    char config_path[512];
    snprintf(config_path, sizeof(config_path),
             "Mods/%s/ScriptExtender/Config.json", mod_name);

    int entry_idx = pak_find_entry(pak, config_path);
    if (entry_idx < 0) {
        pak_close(pak);
        return 0;
    }

    // Read and check for "Lua"
    size_t size;
    char *content = pak_read_file(pak, entry_idx, &size);
    pak_close(pak);

    if (!content) return 0;

    int has_lua = (strstr(content, "\"Lua\"") != NULL);
    free(content);

    return has_lua;
}

/**
 * Find the PAK file containing a mod in the Mods folder
 * Returns 1 if found and sets pak_path_out, 0 if not found
 */
static int find_mod_pak(const char *mod_name, char *pak_path_out, size_t pak_path_size) {
    const char *home = getenv("HOME");
    if (!home) return 0;

    char mods_dir[MAX_PATH_LEN];
    snprintf(mods_dir, sizeof(mods_dir),
             "%s/Documents/Larian Studios/Baldur's Gate 3/Mods", home);

    DIR *dir = opendir(mods_dir);
    if (!dir) return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);
        if (name_len > 4 && strcasecmp(entry->d_name + name_len - 4, ".pak") == 0) {
            char pak_path[MAX_PATH_LEN];
            snprintf(pak_path, sizeof(pak_path), "%s/%s", mods_dir, entry->d_name);

            // Check if this PAK contains our mod
            PakFile *pak = pak_open(pak_path);
            if (pak) {
                // Look for any file with our mod name in the path
                char mod_prefix[512];
                snprintf(mod_prefix, sizeof(mod_prefix), "Mods/%s/", mod_name);

                for (uint32_t i = 0; i < pak->num_files; i++) {
                    if (strncmp(pak->entries[i].name, mod_prefix, strlen(mod_prefix)) == 0) {
                        pak_close(pak);
                        closedir(dir);
                        strncpy(pak_path_out, pak_path, pak_path_size - 1);
                        pak_path_out[pak_path_size - 1] = '\0';
                        return 1;
                    }
                }
                pak_close(pak);
            }
        }
    }

    closedir(dir);
    return 0;
}

/**
 * Load and execute a Lua file from a PAK archive
 * Returns 1 on success, 0 on failure
 */
static int load_lua_from_pak(lua_State *L, const char *pak_path, const char *lua_path) {
    PakFile *pak = pak_open(pak_path);
    if (!pak) return 0;

    int entry_idx = pak_find_entry(pak, lua_path);
    if (entry_idx < 0) {
        pak_close(pak);
        return 0;
    }

    size_t size;
    char *content = pak_read_file(pak, entry_idx, &size);
    pak_close(pak);

    if (!content) return 0;

    // Execute the Lua code
    if (luaL_dostring(L, content) != LUA_OK) {
        const char *error = lua_tostring(L, -1);
        log_message("[Lua] PAK load error (%s): %s", lua_path, error);
        lua_pop(L, 1);
        free(content);
        return 0;
    }

    free(content);
    log_message("[Lua] Loaded from PAK: %s", lua_path);
    return 1;
}

/**
 * Write to both syslog and our log file
 */
static void log_message(const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Write to syslog
    syslog(LOG_ERR, "[%s] %s", BG3SE_NAME, buffer);

    // Write to log file
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, buffer);
        fclose(f);
    }
}

// ============================================================================
// Mod Detection
// ============================================================================

/**
 * Check if a file contains a specific string
 * Returns 1 if found, 0 if not found or file doesn't exist
 */
static int file_contains_string(const char *filepath, const char *search_str) {
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024) {  // Sanity check: max 1MB
        fclose(f);
        return 0;
    }

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        return 0;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    int found = (strstr(content, search_str) != NULL);
    free(content);
    return found;
}

/**
 * Check if a mod has ScriptExtender support by looking for Config.json
 * with "Lua" in FeatureFlags. Checks multiple possible locations.
 * Returns 1 if found, 0 if not an SE mod
 */
static int check_mod_has_script_extender(const char *mod_name) {
    char config_path[MAX_PATH_LEN];

    // Location 1: Extracted mod in /tmp/<ModName>_extracted/
    snprintf(config_path, sizeof(config_path),
             "/tmp/%s_extracted/Mods/%s/ScriptExtender/Config.json",
             mod_name, mod_name);
    if (file_contains_string(config_path, "\"Lua\"")) {
        log_message("[SE] Found Config.json with Lua for %s at: %s", mod_name, config_path);
        return 1;
    }

    // Location 2: Short extracted name (e.g., mrc_extracted for MoreReactiveCompanions_Configurable)
    // Try a few common short names
    const char *short_names[] = {"mrc", "se", "mod", NULL};
    for (int i = 0; short_names[i] != NULL; i++) {
        snprintf(config_path, sizeof(config_path),
                 "/tmp/%s_extracted/Mods/%s/ScriptExtender/Config.json",
                 short_names[i], mod_name);
        if (file_contains_string(config_path, "\"Lua\"")) {
            log_message("[SE] Found Config.json with Lua for %s at: %s", mod_name, config_path);
            return 1;
        }
    }

    // Location 3: User's Mods folder (unpacked mod)
    const char *home = getenv("HOME");
    if (home) {
        snprintf(config_path, sizeof(config_path),
                 "%s/Documents/Larian Studios/Baldur's Gate 3/Mods/%s/ScriptExtender/Config.json",
                 home, mod_name);
        if (file_contains_string(config_path, "\"Lua\"")) {
            log_message("[SE] Found Config.json with Lua for %s at: %s", mod_name, config_path);
            return 1;
        }
    }

    // Location 4: PAK file in Mods folder
    // Scan for PAK files that might contain this mod
    if (home) {
        char mods_dir[MAX_PATH_LEN];
        snprintf(mods_dir, sizeof(mods_dir),
                 "%s/Documents/Larian Studios/Baldur's Gate 3/Mods", home);

        DIR *dir = opendir(mods_dir);
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                // Check if it's a PAK file
                size_t name_len = strlen(entry->d_name);
                if (name_len > 4 && strcasecmp(entry->d_name + name_len - 4, ".pak") == 0) {
                    char pak_path[MAX_PATH_LEN];
                    snprintf(pak_path, sizeof(pak_path), "%s/%s", mods_dir, entry->d_name);

                    if (pak_has_script_extender(pak_path, mod_name)) {
                        log_message("[SE] Found SE mod %s in PAK: %s", mod_name, pak_path);
                        closedir(dir);
                        return 1;
                    }
                }
            }
            closedir(dir);
        }
    }

    return 0;
}

/**
 * Parse modsettings.lsx and detect enabled mods
 * Also identifies which mods have ScriptExtender support
 * The file is XML-based, we do simple string parsing to extract mod names
 */
static void detect_enabled_mods(void) {
    // Reset detected mods
    detected_mod_count = 0;
    se_mod_count = 0;

    // Build path to modsettings.lsx
    const char *home = getenv("HOME");
    if (!home) {
        log_message("Could not get HOME environment variable");
        return;
    }

    char path[1024];
    snprintf(path, sizeof(path),
             "%s/Documents/Larian Studios/Baldur's Gate 3/PlayerProfiles/Public/modsettings.lsx",
             home);

    FILE *f = fopen(path, "r");
    if (!f) {
        log_message("Could not open modsettings.lsx at: %s", path);
        return;
    }

    // Read entire file
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        log_message("Out of memory reading modsettings.lsx");
        return;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    // Count and extract mod names
    // Look for: attribute id="Name" type="LSString" value="ModName"
    log_message("=== Enabled Mods ===");

    int mod_count = 0;
    char *ptr = content;
    const char *name_marker = "attribute id=\"Name\" type=\"LSString\" value=\"";
    size_t marker_len = strlen(name_marker);

    while ((ptr = strstr(ptr, name_marker)) != NULL) {
        ptr += marker_len;

        // Find the closing quote
        char *end = strchr(ptr, '"');
        if (end) {
            size_t name_len = end - ptr;
            if (name_len < MAX_MOD_NAME_LEN && detected_mod_count < MAX_MODS) {
                char mod_name[MAX_MOD_NAME_LEN];
                strncpy(mod_name, ptr, name_len);
                mod_name[name_len] = '\0';

                // Store in detected mods array
                strncpy(detected_mods[detected_mod_count], mod_name, MAX_MOD_NAME_LEN - 1);
                detected_mods[detected_mod_count][MAX_MOD_NAME_LEN - 1] = '\0';
                detected_mod_count++;

                mod_count++;
                // Skip GustavX as it's the base game, but still count it
                if (strcmp(mod_name, "GustavX") == 0) {
                    log_message("  [%d] %s (base game)", mod_count, mod_name);
                } else {
                    log_message("  [%d] %s", mod_count, mod_name);
                }
            }
            ptr = end;
        }
    }

    log_message("Total mods: %d (%d user mods)", mod_count, mod_count > 0 ? mod_count - 1 : 0);
    log_message("====================");

    free(content);

    // Now check which mods have Script Extender support
    log_message("=== Scanning for SE Mods ===");
    for (int i = 0; i < detected_mod_count; i++) {
        // Skip base game
        if (strcmp(detected_mods[i], "GustavX") == 0) continue;

        if (check_mod_has_script_extender(detected_mods[i])) {
            if (se_mod_count < MAX_MODS) {
                strncpy(se_mods[se_mod_count], detected_mods[i], MAX_MOD_NAME_LEN - 1);
                se_mods[se_mod_count][MAX_MOD_NAME_LEN - 1] = '\0';
                se_mod_count++;
                log_message("  [SE] %s", detected_mods[i]);
            }
        }
    }

    if (se_mod_count == 0) {
        log_message("  No SE mods detected (ensure mods are extracted to /tmp/)");
    } else {
        log_message("Total SE mods: %d", se_mod_count);
    }
    log_message("============================");
}

// ============================================================================
// Lua API: Ext namespace functions
// ============================================================================

/**
 * Ext.Print(...) - Print to BG3SE log
 */
static int lua_ext_print(lua_State *L) {
    int n = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);

    for (int i = 1; i <= n; i++) {
        size_t len;
        const char *s = luaL_tolstring(L, i, &len);
        if (i > 1) luaL_addchar(&b, '\t');
        luaL_addlstring(&b, s, len);
        lua_pop(L, 1);  // pop the string from luaL_tolstring
    }

    luaL_pushresult(&b);
    const char *msg = lua_tostring(L, -1);
    log_message("[Lua] %s", msg);

    return 0;
}

/**
 * Ext.GetVersion() - Return BG3SE version
 */
static int lua_ext_getversion(lua_State *L) {
    lua_pushstring(L, BG3SE_VERSION);
    return 1;
}

/**
 * Ext.IsServer() - Check if running on server context
 */
static int lua_ext_isserver(lua_State *L) {
    // For now, always return false (client-side)
    lua_pushboolean(L, 0);
    return 1;
}

/**
 * Ext.IsClient() - Check if running on client context
 */
static int lua_ext_isclient(lua_State *L) {
    // For now, always return true (client-side)
    lua_pushboolean(L, 1);
    return 1;
}

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

    // Try filesystem first (for extracted mods)
    if (strlen(current_mod_lua_base) > 0) {
        // Build full path using the base path from where bootstrap was loaded
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", current_mod_lua_base, path);

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
    if (strlen(current_mod_pak_path) > 0 && strlen(current_mod_name) > 0) {
        char pak_lua_path[MAX_PATH_LEN];
        snprintf(pak_lua_path, sizeof(pak_lua_path),
                 "Mods/%s/ScriptExtender/Lua/%s", current_mod_name, path);

        // Check if already loaded (use PAK path as key)
        char cache_key[MAX_PATH_LEN];
        snprintf(cache_key, sizeof(cache_key), "pak:%s:%s", current_mod_pak_path, pak_lua_path);

        if (is_module_loaded(cache_key)) {
            log_message("[Lua] Module already loaded from PAK: %s", path);
            lua_pushnil(L);
            return 1;
        }

        if (load_lua_from_pak(L, current_mod_pak_path, pak_lua_path)) {
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
    if (strlen(current_mod_lua_base) > 0) {
        log_message("[Lua]   Tried filesystem: %s/%s", current_mod_lua_base, path);
    }
    if (strlen(current_mod_pak_path) > 0) {
        log_message("[Lua]   Tried PAK: %s (Mods/%s/ScriptExtender/Lua/%s)",
                    current_mod_pak_path, current_mod_name, path);
    }

    lua_pushnil(L);
    return 1;
}

// Ext.IO namespace
static int lua_ext_io_loadfile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    log_message("[Lua] Ext.IO.LoadFile('%s')", path);

    FILE *f = fopen(path, "r");
    if (!f) {
        lua_pushnil(L);
        lua_pushstring(L, "File not found");
        return 2;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        lua_pushnil(L);
        lua_pushstring(L, "Out of memory");
        return 2;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    lua_pushstring(L, content);
    free(content);
    return 1;
}

static int lua_ext_io_savefile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    const char *content = luaL_checkstring(L, 2);
    log_message("[Lua] Ext.IO.SaveFile('%s')", path);

    FILE *f = fopen(path, "w");
    if (!f) {
        lua_pushboolean(L, 0);
        return 1;
    }

    fputs(content, f);
    fclose(f);

    lua_pushboolean(L, 1);
    return 1;
}

// ============================================================================
// Simple JSON Parser
// ============================================================================

// Forward declarations for recursive parsing
static const char *json_parse_value(lua_State *L, const char *json);
static const char *json_skip_whitespace(const char *json);

static const char *json_skip_whitespace(const char *json) {
    while (*json && (*json == ' ' || *json == '\t' || *json == '\n' || *json == '\r')) {
        json++;
    }
    return json;
}

static const char *json_parse_string(lua_State *L, const char *json) {
    if (*json != '"') return NULL;
    json++;  // skip opening quote

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    while (*json && *json != '"') {
        if (*json == '\\' && json[1]) {
            json++;
            switch (*json) {
                case '"': luaL_addchar(&b, '"'); break;
                case '\\': luaL_addchar(&b, '\\'); break;
                case '/': luaL_addchar(&b, '/'); break;
                case 'b': luaL_addchar(&b, '\b'); break;
                case 'f': luaL_addchar(&b, '\f'); break;
                case 'n': luaL_addchar(&b, '\n'); break;
                case 'r': luaL_addchar(&b, '\r'); break;
                case 't': luaL_addchar(&b, '\t'); break;
                default: luaL_addchar(&b, *json); break;
            }
        } else {
            luaL_addchar(&b, *json);
        }
        json++;
    }

    if (*json != '"') return NULL;
    luaL_pushresult(&b);
    return json + 1;  // skip closing quote
}

static const char *json_parse_number(lua_State *L, const char *json) {
    const char *start = json;
    if (*json == '-') json++;
    while (*json >= '0' && *json <= '9') json++;
    if (*json == '.') {
        json++;
        while (*json >= '0' && *json <= '9') json++;
    }
    if (*json == 'e' || *json == 'E') {
        json++;
        if (*json == '+' || *json == '-') json++;
        while (*json >= '0' && *json <= '9') json++;
    }

    char *endptr;
    double num = strtod(start, &endptr);
    lua_pushnumber(L, num);
    return json;
}

static const char *json_parse_object(lua_State *L, const char *json) {
    if (*json != '{') return NULL;
    json = json_skip_whitespace(json + 1);

    lua_newtable(L);

    if (*json == '}') return json + 1;

    while (1) {
        json = json_skip_whitespace(json);
        if (*json != '"') return NULL;

        // Parse key
        json = json_parse_string(L, json);
        if (!json) return NULL;

        json = json_skip_whitespace(json);
        if (*json != ':') return NULL;
        json = json_skip_whitespace(json + 1);

        // Parse value
        json = json_parse_value(L, json);
        if (!json) return NULL;

        // Set table[key] = value
        lua_settable(L, -3);

        json = json_skip_whitespace(json);
        if (*json == '}') return json + 1;
        if (*json != ',') return NULL;
        json++;
    }
}

static const char *json_parse_array(lua_State *L, const char *json) {
    if (*json != '[') return NULL;
    json = json_skip_whitespace(json + 1);

    lua_newtable(L);
    int index = 1;

    if (*json == ']') return json + 1;

    while (1) {
        json = json_skip_whitespace(json);
        json = json_parse_value(L, json);
        if (!json) return NULL;

        lua_rawseti(L, -2, index++);

        json = json_skip_whitespace(json);
        if (*json == ']') return json + 1;
        if (*json != ',') return NULL;
        json++;
    }
}

static const char *json_parse_value(lua_State *L, const char *json) {
    json = json_skip_whitespace(json);

    if (*json == '"') {
        return json_parse_string(L, json);
    } else if (*json == '{') {
        return json_parse_object(L, json);
    } else if (*json == '[') {
        return json_parse_array(L, json);
    } else if (*json == 't' && strncmp(json, "true", 4) == 0) {
        lua_pushboolean(L, 1);
        return json + 4;
    } else if (*json == 'f' && strncmp(json, "false", 5) == 0) {
        lua_pushboolean(L, 0);
        return json + 5;
    } else if (*json == 'n' && strncmp(json, "null", 4) == 0) {
        lua_pushnil(L);
        return json + 4;
    } else if (*json == '-' || (*json >= '0' && *json <= '9')) {
        return json_parse_number(L, json);
    }

    return NULL;
}

// Ext.Json namespace
static int lua_ext_json_parse(lua_State *L) {
    const char *json = luaL_checkstring(L, 1);
    log_message("[Lua] Ext.Json.Parse called (len: %zu)", strlen(json));

    const char *result = json_parse_value(L, json);
    if (!result) {
        lua_pushnil(L);
        log_message("[Lua] Ext.Json.Parse failed");
    }
    return 1;
}

static int lua_ext_json_stringify(lua_State *L);  // Forward declaration

static void json_stringify_value(lua_State *L, int index, luaL_Buffer *b);

static void json_stringify_table(lua_State *L, int index, luaL_Buffer *b) {
    // Check if it's an array (sequential integer keys starting from 1)
    int is_array = 1;
    int max_index = 0;

    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
        if (lua_type(L, -2) != LUA_TNUMBER || lua_tointeger(L, -2) != max_index + 1) {
            is_array = 0;
        }
        max_index++;
        lua_pop(L, 1);
    }

    if (is_array && max_index > 0) {
        luaL_addchar(b, '[');
        for (int i = 1; i <= max_index; i++) {
            if (i > 1) luaL_addchar(b, ',');
            lua_rawgeti(L, index, i);
            json_stringify_value(L, lua_gettop(L), b);
            lua_pop(L, 1);
        }
        luaL_addchar(b, ']');
    } else {
        luaL_addchar(b, '{');
        int first = 1;
        lua_pushnil(L);
        while (lua_next(L, index) != 0) {
            if (!first) luaL_addchar(b, ',');
            first = 0;

            // Key
            luaL_addchar(b, '"');
            if (lua_type(L, -2) == LUA_TSTRING) {
                luaL_addstring(b, lua_tostring(L, -2));
            } else {
                lua_pushvalue(L, -2);
                luaL_addstring(b, lua_tostring(L, -1));
                lua_pop(L, 1);
            }
            luaL_addchar(b, '"');
            luaL_addchar(b, ':');

            // Value
            json_stringify_value(L, lua_gettop(L), b);
            lua_pop(L, 1);
        }
        luaL_addchar(b, '}');
    }
}

static void json_stringify_value(lua_State *L, int index, luaL_Buffer *b) {
    int t = lua_type(L, index);
    switch (t) {
        case LUA_TSTRING: {
            const char *s = lua_tostring(L, index);
            luaL_addchar(b, '"');
            while (*s) {
                if (*s == '"' || *s == '\\') {
                    luaL_addchar(b, '\\');
                }
                luaL_addchar(b, *s);
                s++;
            }
            luaL_addchar(b, '"');
            break;
        }
        case LUA_TNUMBER: {
            char buf[64];
            snprintf(buf, sizeof(buf), "%g", lua_tonumber(L, index));
            luaL_addstring(b, buf);
            break;
        }
        case LUA_TBOOLEAN:
            luaL_addstring(b, lua_toboolean(L, index) ? "true" : "false");
            break;
        case LUA_TTABLE:
            json_stringify_table(L, index, b);
            break;
        case LUA_TNIL:
        default:
            luaL_addstring(b, "null");
            break;
    }
}

static int lua_ext_json_stringify(lua_State *L) {
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    json_stringify_value(L, 1, &b);
    luaL_pushresult(&b);
    return 1;
}

/**
 * Register the Ext API in Lua
 */
static void register_ext_api(lua_State *L) {
    // Create Ext table
    lua_newtable(L);

    // Basic functions
    lua_pushcfunction(L, lua_ext_print);
    lua_setfield(L, -2, "Print");

    lua_pushcfunction(L, lua_ext_getversion);
    lua_setfield(L, -2, "GetVersion");

    lua_pushcfunction(L, lua_ext_isserver);
    lua_setfield(L, -2, "IsServer");

    lua_pushcfunction(L, lua_ext_isclient);
    lua_setfield(L, -2, "IsClient");

    lua_pushcfunction(L, lua_ext_require);
    lua_setfield(L, -2, "Require");

    // Create Ext.IO table
    lua_newtable(L);
    lua_pushcfunction(L, lua_ext_io_loadfile);
    lua_setfield(L, -2, "LoadFile");
    lua_pushcfunction(L, lua_ext_io_savefile);
    lua_setfield(L, -2, "SaveFile");
    lua_setfield(L, -2, "IO");

    // Create Ext.Json table
    lua_newtable(L);
    lua_pushcfunction(L, lua_ext_json_parse);
    lua_setfield(L, -2, "Parse");
    lua_pushcfunction(L, lua_ext_json_stringify);
    lua_setfield(L, -2, "Stringify");
    lua_setfield(L, -2, "Json");

    // Set Ext as global
    lua_setglobal(L, "Ext");

    log_message("Ext API registered in Lua");
}

// ============================================================================
// Ext.Osiris namespace - Event listener registration
// ============================================================================

// Storage for registered Osiris listeners
#define MAX_OSIRIS_LISTENERS 64
typedef struct {
    char event_name[128];
    int arity;
    char timing[16];  // "before" or "after"
    int callback_ref;  // Lua registry reference
} OsirisListener;

static OsirisListener osiris_listeners[MAX_OSIRIS_LISTENERS];
static int osiris_listener_count = 0;

/**
 * Ext.Osiris.RegisterListener(event, arity, timing, callback)
 * Registers a callback for an Osiris event
 */
static int lua_ext_osiris_registerlistener(lua_State *L) {
    const char *event = luaL_checkstring(L, 1);
    int arity = (int)luaL_checkinteger(L, 2);
    const char *timing = luaL_checkstring(L, 3);
    luaL_checktype(L, 4, LUA_TFUNCTION);

    if (osiris_listener_count >= MAX_OSIRIS_LISTENERS) {
        log_message("[Lua] Warning: Max Osiris listeners reached");
        return 0;
    }

    // Store the listener
    OsirisListener *listener = &osiris_listeners[osiris_listener_count];
    strncpy(listener->event_name, event, sizeof(listener->event_name) - 1);
    listener->arity = arity;
    strncpy(listener->timing, timing, sizeof(listener->timing) - 1);

    // Store callback reference in Lua registry
    lua_pushvalue(L, 4);  // Push the function
    listener->callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    osiris_listener_count++;

    log_message("[Lua] Registered Osiris listener: %s (arity=%d, timing=%s)",
                event, arity, timing);

    return 0;
}

/**
 * Register Ext.Osiris namespace
 */
static void register_ext_osiris(lua_State *L) {
    // Get Ext table
    lua_getglobal(L, "Ext");

    // Create Ext.Osiris table
    lua_newtable(L);

    lua_pushcfunction(L, lua_ext_osiris_registerlistener);
    lua_setfield(L, -2, "RegisterListener");

    lua_setfield(L, -2, "Osiris");

    lua_pop(L, 1);  // Pop Ext table

    log_message("Ext.Osiris API registered");
}

// ============================================================================
// Osi namespace - Osiris function bindings (stubs)
// ============================================================================

/**
 * GetHostCharacter() - Returns the host player's character UUID
 * For now returns a placeholder string
 */
static int lua_gethostcharacter(lua_State *L) {
    // Return a placeholder - in real implementation this would call Osiris
    lua_pushstring(L, "S_Player_Tav_00000000-0000-0000-0000-000000000000");
    log_message("[Lua] GetHostCharacter() called (stub)");
    return 1;
}

/**
 * Osi.IsTagged(character, tag) - Check if character has a tag
 * Stub: always returns false
 */
static int lua_osi_istagged(lua_State *L) {
    const char *character = luaL_checkstring(L, 1);
    const char *tag = luaL_checkstring(L, 2);
    log_message("[Lua] Osi.IsTagged('%s', '%s') called (stub)", character, tag);
    lua_pushboolean(L, 0);  // Always return false for now
    return 1;
}

/**
 * Osi.GetDistanceTo(char1, char2) - Get distance between characters
 * Stub: always returns 0
 */
static int lua_osi_getdistanceto(lua_State *L) {
    const char *char1 = luaL_checkstring(L, 1);
    const char *char2 = luaL_checkstring(L, 2);
    log_message("[Lua] Osi.GetDistanceTo('%s', '%s') called (stub)", char1, char2);
    lua_pushnumber(L, 0.0);
    return 1;
}

/**
 * Osi.DialogGetNumberOfInvolvedPlayers(instance_id) - Get player count in dialog
 * Stub: always returns 1
 */
static int lua_osi_dialoggetnumberofinvolvedplayers(lua_State *L) {
    log_message("[Lua] Osi.DialogGetNumberOfInvolvedPlayers() called (stub)");
    lua_pushinteger(L, 1);
    return 1;
}

/**
 * Osi.SpeakerGetDialog(character, index) - Get dialog resource
 * Stub: returns empty string
 */
static int lua_osi_speakergetdialog(lua_State *L) {
    log_message("[Lua] Osi.SpeakerGetDialog() called (stub)");
    lua_pushstring(L, "");
    return 1;
}

/**
 * Osi.DialogRequestStop(character) - Stop a dialog
 * Stub: does nothing
 */
static int lua_osi_dialogrequeststop(lua_State *L) {
    (void)L;  // Unused parameter
    log_message("[Lua] Osi.DialogRequestStop() called (stub)");
    return 0;
}

/**
 * Osi.QRY_StartDialog_Fixed(resource, character) - Start a dialog
 * Stub: returns false
 */
static int lua_osi_qry_startdialog_fixed(lua_State *L) {
    log_message("[Lua] Osi.QRY_StartDialog_Fixed() called (stub)");
    lua_pushboolean(L, 0);
    return 1;
}

/**
 * DB_Players database accessor
 * Creates a table with a :Get() method that returns player list
 */
static int lua_osi_db_players_get(lua_State *L) {
    log_message("[Lua] Osi.DB_Players:Get() called (stub)");

    // Return an empty table for now (no players)
    lua_newtable(L);

    // In a real implementation, this would return a table of player UUIDs:
    // { {"UUID1"}, {"UUID2"}, ... }

    return 1;
}

/**
 * Register Osi namespace with stub functions
 */
static void register_osi_namespace(lua_State *L) {
    // Create Osi table
    lua_newtable(L);

    // Basic Osiris functions
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

    // Set Osi as global
    lua_setglobal(L, "Osi");

    // Also register GetHostCharacter as a global function
    lua_pushcfunction(L, lua_gethostcharacter);
    lua_setglobal(L, "GetHostCharacter");

    log_message("Osi namespace registered (stubs)");
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

    // Set current mod name for Ext.Require
    strncpy(current_mod_name, mod_name, sizeof(current_mod_name) - 1);
    current_mod_name[sizeof(current_mod_name) - 1] = '\0';

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
        // Set base path BEFORE loading so Ext.Require works during bootstrap
        strncpy(current_mod_lua_base, lua_base, sizeof(current_mod_lua_base) - 1);
        log_message("[Lua] Set mod Lua base: %s", current_mod_lua_base);
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
        strncpy(current_mod_lua_base, lua_base, sizeof(current_mod_lua_base) - 1);
        log_message("[Lua] Set mod Lua base: %s", current_mod_lua_base);
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
        strncpy(current_mod_lua_base, lua_base, sizeof(current_mod_lua_base) - 1);
        log_message("[Lua] Set mod Lua base: %s", current_mod_lua_base);
        if (try_load_lua_file(L, full_path)) {
            log_message("[Lua] Loaded %s %s", mod_name, bootstrap_file);
            return 1;
        }
    }

    // Try loading from PAK file in Mods folder
    char pak_path[MAX_PATH_LEN];
    if (find_mod_pak(mod_name, pak_path, sizeof(pak_path))) {
        char pak_lua_path[MAX_PATH_LEN];
        snprintf(pak_lua_path, sizeof(pak_lua_path),
                 "Mods/%s/ScriptExtender/Lua/%s", mod_name, bootstrap_file);

        log_message("[Lua] Trying to load %s from PAK: %s", bootstrap_file, pak_path);

        // Store current PAK path for Ext.Require to use
        strncpy(current_mod_pak_path, pak_path, sizeof(current_mod_pak_path) - 1);
        current_mod_pak_path[sizeof(current_mod_pak_path) - 1] = '\0';

        // Clear filesystem base path since we're loading from PAK
        current_mod_lua_base[0] = '\0';

        if (load_lua_from_pak(L, pak_path, pak_lua_path)) {
            log_message("[Lua] Loaded %s %s from PAK", mod_name, bootstrap_file);
            return 1;
        }

        // Clear PAK path on failure
        current_mod_pak_path[0] = '\0';
    }

    // Clear mod name if not found
    current_mod_name[0] = '\0';

    log_message("[Lua] Bootstrap not found for mod: %s (%s)", mod_name, bootstrap_file);
    return 0;
}

/**
 * Load all mod bootstraps for SE-enabled mods
 * Uses the dynamically detected se_mods[] array populated by detect_enabled_mods()
 */
static void load_mod_scripts(lua_State *L) {
    log_message("=== Loading Mod Scripts ===");

    // Initialize the mods base path
    init_mods_base_path();

    // Check if we have any SE mods detected
    if (se_mod_count == 0) {
        log_message("[Lua] No SE mods detected to load");
        log_message("=== Mod Script Loading Complete ===");
        return;
    }

    log_message("[Lua] Loading %d detected SE mod(s)...", se_mod_count);

    for (int i = 0; i < se_mod_count; i++) {
        const char *mod_name = se_mods[i];
        log_message("[Lua] Attempting to load SE mod: %s", mod_name);

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

    // Register Ext.Osiris namespace
    register_ext_osiris(L);

    // Register Osi namespace (stub functions)
    register_osi_namespace(L);

    // Register global debug functions
    register_global_functions(L);

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

    // Call original
    if (orig_InitGame) {
        ((void (*)(void*))orig_InitGame)(thisPtr);
    }

    log_message(">>> COsiris::InitGame returned");

    // Notify Lua that Osiris is initialized
    if (L) {
        luaL_dostring(L, "Ext.Print('Osiris initialized!')");

        // Load mod scripts after Osiris is initialized (only once)
        if (!mod_scripts_loaded) {
            mod_scripts_loaded = 1;
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

        // Load mod scripts after save is loaded (if not already loaded)
        // This handles the case where InitGame wasn't called (loading existing save)
        if (!mod_scripts_loaded) {
            mod_scripts_loaded = 1;
            load_mod_scripts(L);
        }
    }

    return result;
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
 * Install Dobby hooks on Osiris functions
 */
static void install_hooks(void) {
#if ENABLE_HOOKS
    // Only install hooks once
    if (hooks_installed) {
        log_message("Hooks already installed, skipping");
        return;
    }

    log_message("Installing Dobby hooks...");

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

    // Get function addresses (C++ mangled names)
    void *initGameAddr = dlsym(osiris, "_ZN7COsiris8InitGameEv");
    void *loadAddr = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");

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

    log_message("Hooks installed: %d/2", hook_count);
    hooks_installed = 1;
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
    // Clear log file
    FILE *f = fopen(LOG_FILE, "w");
    if (f) {
        fprintf(f, "=== %s v%s ===\n", BG3SE_NAME, BG3SE_VERSION);
        fprintf(f, "Injection timestamp: %ld\n", (long)time(NULL));
        fprintf(f, "Process ID: %d\n", getpid());
        fclose(f);
    }

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
    detect_enabled_mods();

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

    // Shutdown Lua
    shutdown_lua();
}
