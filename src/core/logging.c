/**
 * BG3SE-macOS - Structured Logging Implementation
 *
 * Multi-level, module-aware logging with JSON and human-readable output.
 */

#include "logging.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  // strcasecmp
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>

// ============================================================================
// ANSI Color Codes
// ============================================================================

#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_DIM        "\033[2m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_WHITE      "\033[37m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_RED        "\033[31m"
#define ANSI_BOLD_RED   "\033[1;31m"

// ============================================================================
// String Tables
// ============================================================================

static const char* g_level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "NONE"
};

static const char* g_level_short[] = {
    "DBG", "INF", "WRN", "ERR", "---"
};

static const char* g_module_names[] = {
    "Core",     // LOG_MODULE_CORE
    "Console",  // LOG_MODULE_CONSOLE
    "Lua",      // LOG_MODULE_LUA
    "Osiris",   // LOG_MODULE_OSIRIS
    "Entity",   // LOG_MODULE_ENTITY
    "Events",   // LOG_MODULE_EVENTS
    "Stats",    // LOG_MODULE_STATS
    "Timer",    // LOG_MODULE_TIMER
    "Hooks",    // LOG_MODULE_HOOKS
    "Mod",      // LOG_MODULE_MOD
    "Memory",   // LOG_MODULE_MEMORY
    "Persist",  // LOG_MODULE_PERSIST
    "Game",     // LOG_MODULE_GAME
    "Input",    // LOG_MODULE_INPUT
    "ImGui"     // LOG_MODULE_IMGUI
};

static const char* g_level_colors[] = {
    ANSI_CYAN,      // DEBUG
    ANSI_WHITE,     // INFO
    ANSI_YELLOW,    // WARN
    ANSI_BOLD_RED,  // ERROR
    ANSI_WHITE      // NONE
};

// ============================================================================
// Configuration State
// ============================================================================

#define LOG_MAX_CALLBACKS 8

typedef struct {
    LogCallback callback;
    void* userdata;
    LogLevel min_level;
    uint32_t module_mask;
    bool active;
} LogCallbackEntry;

typedef struct {
    LogLevel global_level;
    int module_levels[LOG_MODULE_MAX];  // -1 = inherit from global
    uint32_t output_flags;
    LogFormat format;
    bool color_enabled;
    bool initialized;
    LogCallbackEntry callbacks[LOG_MAX_CALLBACKS];
    pthread_mutex_t mutex;
} LogConfig;

static LogConfig g_config = {
    .global_level = LOG_LEVEL_DEBUG,  // DEBUG enabled by default during development
    .output_flags = LOG_OUTPUT_FILE | LOG_OUTPUT_SYSLOG,
    .format = LOG_FORMAT_HUMAN,
    .color_enabled = true,
    .initialized = false
};

// Persistent file handle for log file (performance optimization)
static FILE *g_log_file = NULL;
static char g_session_log_path[512] = {0};

// ============================================================================
// Data Directory Management (from original logging.c)
// ============================================================================

static char g_DataDir[512] = {0};
static char g_LogsDir[512] = {0};
static char g_DataPath[512] = {0};
static pthread_once_t g_DataDirOnce = PTHREAD_ONCE_INIT;

static void init_data_dir(void) {
    const char *home = getenv("HOME");

    // Try to create in ~/Library/Application Support/BG3SE/
    if (home && home[0] != '\0') {
        snprintf(g_DataDir, sizeof(g_DataDir),
                 "%s/Library/Application Support/%s",
                 home, BG3SE_DATA_DIR_NAME);

        // Create directory hierarchy
        char path[512];
        snprintf(path, sizeof(path), "%s/Library", home);
        mkdir(path, 0755);

        snprintf(path, sizeof(path), "%s/Library/Application Support", home);
        mkdir(path, 0755);

        if (mkdir(g_DataDir, 0755) == 0 || errno == EEXIST) {
            // Create logs subdirectory for session-based logs
            snprintf(g_LogsDir, sizeof(g_LogsDir), "%s/logs", g_DataDir);
            mkdir(g_LogsDir, 0755);
            return;
        }
    }

    // Fallback to /tmp/BG3SE/
    snprintf(g_DataDir, sizeof(g_DataDir), "/tmp/%s", BG3SE_DATA_DIR_NAME);
    mkdir(g_DataDir, 0755);

    // Create logs subdirectory
    snprintf(g_LogsDir, sizeof(g_LogsDir), "%s/logs", g_DataDir);
    mkdir(g_LogsDir, 0755);
}

const char *bg3se_get_data_dir(void) {
    pthread_once(&g_DataDirOnce, init_data_dir);
    return g_DataDir;
}

const char *bg3se_get_data_path(const char *filename) {
    pthread_once(&g_DataDirOnce, init_data_dir);
    snprintf(g_DataPath, sizeof(g_DataPath), "%s/%s", g_DataDir, filename);
    return g_DataPath;
}

// ============================================================================
// Utility Functions
// ============================================================================

const char* log_level_name(LogLevel level) {
    if (level >= 0 && level <= LOG_LEVEL_NONE) {
        return g_level_names[level];
    }
    return "UNKNOWN";
}

const char* log_level_short(LogLevel level) {
    if (level >= 0 && level <= LOG_LEVEL_NONE) {
        return g_level_short[level];
    }
    return "???";
}

const char* log_module_name(LogModule module) {
    if (module >= 0 && module < LOG_MODULE_MAX) {
        return g_module_names[module];
    }
    return "Unknown";
}

LogLevel log_level_from_string(const char* str) {
    if (!str) return LOG_LEVEL_INFO;
    if (strcasecmp(str, "DEBUG") == 0 || strcasecmp(str, "DBG") == 0) return LOG_LEVEL_DEBUG;
    if (strcasecmp(str, "INFO") == 0 || strcasecmp(str, "INF") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(str, "WARN") == 0 || strcasecmp(str, "WRN") == 0 || strcasecmp(str, "WARNING") == 0) return LOG_LEVEL_WARN;
    if (strcasecmp(str, "ERROR") == 0 || strcasecmp(str, "ERR") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(str, "NONE") == 0 || strcasecmp(str, "OFF") == 0) return LOG_LEVEL_NONE;
    return LOG_LEVEL_INFO;
}

LogModule log_module_from_string(const char* str) {
    if (!str) return LOG_MODULE_CORE;
    for (int i = 0; i < LOG_MODULE_MAX; i++) {
        if (strcasecmp(str, g_module_names[i]) == 0) {
            return (LogModule)i;
        }
    }
    return LOG_MODULE_CORE;
}

// ============================================================================
// Environment Variable Parsing
// ============================================================================

static void parse_env_config(void) {
    // BG3SE_LOG_LEVEL=DEBUG|INFO|WARN|ERROR
    const char* level_str = getenv("BG3SE_LOG_LEVEL");
    if (level_str) {
        g_config.global_level = log_level_from_string(level_str);
    }

    // BG3SE_LOG_FORMAT=human|json
    const char* format_str = getenv("BG3SE_LOG_FORMAT");
    if (format_str) {
        if (strcasecmp(format_str, "json") == 0) {
            g_config.format = LOG_FORMAT_JSON;
        } else {
            g_config.format = LOG_FORMAT_HUMAN;
        }
    }

    // BG3SE_LOG_COLOR=0|1
    const char* color_str = getenv("BG3SE_LOG_COLOR");
    if (color_str) {
        g_config.color_enabled = (color_str[0] == '1' || strcasecmp(color_str, "true") == 0);
    }

    // BG3SE_LOG_OUTPUT=file,syslog,console
    const char* output_str = getenv("BG3SE_LOG_OUTPUT");
    if (output_str) {
        g_config.output_flags = 0;
        if (strstr(output_str, "file")) g_config.output_flags |= LOG_OUTPUT_FILE;
        if (strstr(output_str, "syslog")) g_config.output_flags |= LOG_OUTPUT_SYSLOG;
        if (strstr(output_str, "console") || strstr(output_str, "stdout")) g_config.output_flags |= LOG_OUTPUT_CONSOLE;
    }

    // BG3SE_LOG_MODULES=Stats:DEBUG,Lua:INFO
    const char* modules_str = getenv("BG3SE_LOG_MODULES");
    if (modules_str) {
        char buf[256];
        strncpy(buf, modules_str, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        char* saveptr = NULL;
        char* token = strtok_r(buf, ",", &saveptr);
        while (token) {
            // Parse "Module:Level"
            char* colon = strchr(token, ':');
            if (colon) {
                *colon = '\0';
                const char* mod_name = token;
                const char* lvl_name = colon + 1;
                LogModule mod = log_module_from_string(mod_name);
                LogLevel lvl = log_level_from_string(lvl_name);
                g_config.module_levels[mod] = lvl;
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

void log_init(void) {
    if (g_config.initialized) return;

    pthread_mutex_init(&g_config.mutex, NULL);

    // Initialize module levels to inherit from global (-1)
    for (int i = 0; i < LOG_MODULE_MAX; i++) {
        g_config.module_levels[i] = -1;
    }

    // Initialize callbacks
    for (int i = 0; i < LOG_MAX_CALLBACKS; i++) {
        g_config.callbacks[i].active = false;
    }

    // Parse environment variables
    parse_env_config();

    g_config.initialized = true;

    // Generate session-based log filename: logs/bg3se_YYYY-MM-DD_HH-MM-SS.log
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Ensure logs directory exists
    pthread_once(&g_DataDirOnce, init_data_dir);

    snprintf(g_session_log_path, sizeof(g_session_log_path),
             "%s/bg3se_%04d-%02d-%02d_%02d-%02d-%02d.log",
             g_LogsDir,
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);

    // Open session log file (new file each session)
    g_log_file = fopen(g_session_log_path, "w");
    if (g_log_file) {
        // Set line buffering for timely writes without too much overhead
        setvbuf(g_log_file, NULL, _IOLBF, 0);

        // Write log header
        if (g_config.format == LOG_FORMAT_JSON) {
            fprintf(g_log_file, "{\"type\":\"header\",\"ts\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\",\"name\":\"%s\",\"version\":\"%s\"}\n",
                    t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                    t->tm_hour, t->tm_min, t->tm_sec,
                    BG3SE_NAME, BG3SE_VERSION);
        } else {
            fprintf(g_log_file, "========================================\n");
            fprintf(g_log_file, "=== %s v%s ===\n", BG3SE_NAME, BG3SE_VERSION);
            fprintf(g_log_file, "Session: %04d-%02d-%02d %02d:%02d:%02d\n",
                    t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                    t->tm_hour, t->tm_min, t->tm_sec);
            fprintf(g_log_file, "Log file: %s\n", g_session_log_path);
            fprintf(g_log_file, "Log level: %s\n", log_level_name(g_config.global_level));
            fprintf(g_log_file, "========================================\n");
        }
    }

    // Also create a symlink to the latest log for easy access
    char latest_link[512];
    snprintf(latest_link, sizeof(latest_link), "%s/latest.log", g_LogsDir);
    unlink(latest_link);  // Remove old symlink
    symlink(g_session_log_path, latest_link);
}

void log_shutdown(void) {
    if (!g_config.initialized) return;

    // Close persistent log file handle
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    pthread_mutex_destroy(&g_config.mutex);
    g_config.initialized = false;
}

// ============================================================================
// Configuration Accessors
// ============================================================================

void log_set_global_level(LogLevel level) {
    pthread_mutex_lock(&g_config.mutex);
    g_config.global_level = level;
    pthread_mutex_unlock(&g_config.mutex);
}

LogLevel log_get_global_level(void) {
    return g_config.global_level;
}

void log_set_module_level(LogModule module, LogLevel level) {
    if (module < 0 || module >= LOG_MODULE_MAX) return;
    pthread_mutex_lock(&g_config.mutex);
    g_config.module_levels[module] = level;
    pthread_mutex_unlock(&g_config.mutex);
}

LogLevel log_get_module_level(LogModule module) {
    if (module < 0 || module >= LOG_MODULE_MAX) return g_config.global_level;
    int mod_level = g_config.module_levels[module];
    if (mod_level < 0) return g_config.global_level;
    return (LogLevel)mod_level;
}

void log_set_output_flags(uint32_t flags) {
    pthread_mutex_lock(&g_config.mutex);
    g_config.output_flags = flags;
    pthread_mutex_unlock(&g_config.mutex);
}

uint32_t log_get_output_flags(void) {
    return g_config.output_flags;
}

void log_set_format(LogFormat format) {
    pthread_mutex_lock(&g_config.mutex);
    g_config.format = format;
    pthread_mutex_unlock(&g_config.mutex);
}

LogFormat log_get_format(void) {
    return g_config.format;
}

void log_set_color_enabled(bool enabled) {
    pthread_mutex_lock(&g_config.mutex);
    g_config.color_enabled = enabled;
    pthread_mutex_unlock(&g_config.mutex);
}

bool log_get_color_enabled(void) {
    return g_config.color_enabled;
}

// ============================================================================
// Callback Management
// ============================================================================

int log_register_callback(LogCallback callback, void* userdata,
                          LogLevel min_level, uint32_t module_mask) {
    if (!callback) return -1;

    pthread_mutex_lock(&g_config.mutex);
    for (int i = 0; i < LOG_MAX_CALLBACKS; i++) {
        if (!g_config.callbacks[i].active) {
            g_config.callbacks[i].callback = callback;
            g_config.callbacks[i].userdata = userdata;
            g_config.callbacks[i].min_level = min_level;
            g_config.callbacks[i].module_mask = module_mask;
            g_config.callbacks[i].active = true;
            pthread_mutex_unlock(&g_config.mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&g_config.mutex);
    return -1;
}

void log_unregister_callback(int callback_id) {
    if (callback_id < 0 || callback_id >= LOG_MAX_CALLBACKS) return;
    pthread_mutex_lock(&g_config.mutex);
    g_config.callbacks[callback_id].active = false;
    pthread_mutex_unlock(&g_config.mutex);
}

// ============================================================================
// Debug Callback (VS Code Debugger Support - Issue #42)
// ============================================================================

static DebugLogCallback g_debug_callback = NULL;

void log_set_debug_callback(DebugLogCallback callback) {
    g_debug_callback = callback;
}

DebugLogCallback log_get_debug_callback(void) {
    return g_debug_callback;
}

// ============================================================================
// Level Check (for lazy formatting)
// ============================================================================

bool log_should_write(LogLevel level, LogModule module) {
    // Quick check without lock for performance
    int mod_level = g_config.module_levels[module];
    LogLevel effective = (mod_level < 0) ? g_config.global_level : (LogLevel)mod_level;
    return level >= effective;
}

// ============================================================================
// JSON Escaping
// ============================================================================

static void json_escape_string(char* dest, size_t dest_size, const char* src) {
    size_t di = 0;
    for (size_t si = 0; src[si] && di < dest_size - 1; si++) {
        char c = src[si];
        if (c == '"' || c == '\\') {
            if (di + 2 >= dest_size) break;
            dest[di++] = '\\';
            dest[di++] = c;
        } else if (c == '\n') {
            if (di + 2 >= dest_size) break;
            dest[di++] = '\\';
            dest[di++] = 'n';
        } else if (c == '\r') {
            if (di + 2 >= dest_size) break;
            dest[di++] = '\\';
            dest[di++] = 'r';
        } else if (c == '\t') {
            if (di + 2 >= dest_size) break;
            dest[di++] = '\\';
            dest[di++] = 't';
        } else if ((unsigned char)c < 0x20) {
            // Skip other control characters
        } else {
            dest[di++] = c;
        }
    }
    dest[di] = '\0';
}

// ============================================================================
// Formatting
// ============================================================================

static void format_timestamp(char* buf, size_t size, bool iso8601) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *t = localtime(&tv.tv_sec);

    if (iso8601) {
        snprintf(buf, size, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                 t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                 t->tm_hour, t->tm_min, t->tm_sec,
                 (int)(tv.tv_usec / 1000));
    } else {
        snprintf(buf, size, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                 t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                 t->tm_hour, t->tm_min, t->tm_sec,
                 (int)(tv.tv_usec / 1000));
    }
}

static void format_human(char* buf, size_t size, LogLevel level, LogModule module,
                         const char* message, bool color) {
    char ts[32];
    format_timestamp(ts, sizeof(ts), false);

    const char* level_str = log_level_name(level);
    const char* module_str = log_module_name(module);

    if (color) {
        const char* color_code = g_level_colors[level];
        snprintf(buf, size, "%s[%s]%s %s[%-5s]%s %s[%-7s]%s %s",
                 ANSI_DIM, ts, ANSI_RESET,
                 color_code, level_str, ANSI_RESET,
                 ANSI_DIM, module_str, ANSI_RESET,
                 message);
    } else {
        snprintf(buf, size, "[%s] [%-5s] [%-7s] %s",
                 ts, level_str, module_str, message);
    }
}

static void format_json(char* buf, size_t size, LogLevel level, LogModule module,
                        const char* message) {
    char ts[32];
    format_timestamp(ts, sizeof(ts), true);

    char escaped_msg[2048];
    json_escape_string(escaped_msg, sizeof(escaped_msg), message);

    snprintf(buf, size, "{\"ts\":\"%s\",\"level\":\"%s\",\"module\":\"%s\",\"msg\":\"%s\"}",
             ts, log_level_name(level), log_module_name(module), escaped_msg);
}

// ============================================================================
// Core Write Function
// ============================================================================

void log_write_v(LogLevel level, LogModule module,
                 const char* file, int line,
                 const char* format, va_list args) {
    // Reserved for future source location feature
    (void)file;
    (void)line;

    // Early check
    if (!log_should_write(level, module)) return;

    // Format message
    char message[2048];
    vsnprintf(message, sizeof(message), format, args);

    // Format output
    char formatted[4096];
    bool use_json = (g_config.format == LOG_FORMAT_JSON);

    if (use_json) {
        format_json(formatted, sizeof(formatted), level, module, message);
    } else {
        format_human(formatted, sizeof(formatted), level, module, message, false);
    }

    // Lock for output
    pthread_mutex_lock(&g_config.mutex);

    // Write to file (uses persistent handle for performance)
    if ((g_config.output_flags & LOG_OUTPUT_FILE) && g_log_file) {
        fprintf(g_log_file, "%s\n", formatted);
        // Line buffering handles flushing automatically
    }

    // Write to syslog (map levels)
    if (g_config.output_flags & LOG_OUTPUT_SYSLOG) {
        int priority = LOG_INFO;
        switch (level) {
            case LOG_LEVEL_DEBUG: priority = LOG_DEBUG; break;
            case LOG_LEVEL_INFO:  priority = LOG_INFO; break;
            case LOG_LEVEL_WARN:  priority = LOG_WARNING; break;
            case LOG_LEVEL_ERROR: priority = LOG_ERR; break;
            default: break;
        }
        syslog(priority, "[%s] %s", BG3SE_NAME, message);
    }

    // Write to console (with colors if enabled and not JSON)
    if (g_config.output_flags & LOG_OUTPUT_CONSOLE) {
        if (use_json || !g_config.color_enabled) {
            printf("%s\n", formatted);
        } else {
            char colored[4096];
            format_human(colored, sizeof(colored), level, module, message, true);
            printf("%s\n", colored);
        }
        fflush(stdout);
    }

    // Forward to callbacks
    if (g_config.output_flags & LOG_OUTPUT_CALLBACK) {
        for (int i = 0; i < LOG_MAX_CALLBACKS; i++) {
            LogCallbackEntry* cb = &g_config.callbacks[i];
            if (cb->active && level >= cb->min_level) {
                if (cb->module_mask == 0 || (cb->module_mask & (1 << module))) {
                    cb->callback(level, module, message, cb->userdata);
                }
            }
        }
    }

    // Invoke debug callback for error messages (VS Code debugger - Issue #42)
    // This is called after releasing the mutex to avoid potential deadlock
    // if the debug callback triggers a breakpoint
    DebugLogCallback debug_cb = g_debug_callback;

    pthread_mutex_unlock(&g_config.mutex);

    // Fire debug callback outside of lock
    if (debug_cb && level >= LOG_LEVEL_ERROR) {
        debug_cb(level, module, message);
    }
}

void log_write(LogLevel level, LogModule module,
               const char* file, int line,
               const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_write_v(level, module, file, line, format, args);
    va_end(args);
}

// ============================================================================
// Backward Compatibility
// ============================================================================

void log_message(const char* format, ...) {
    // Ensure initialized
    if (!g_config.initialized) {
        log_init();
    }

    va_list args;
    va_start(args, format);
    log_write_v(LOG_LEVEL_INFO, LOG_MODULE_CORE, NULL, 0, format, args);
    va_end(args);
}
