/**
 * BG3SE-macOS - Structured Logging Module
 *
 * Multi-level, module-aware logging with JSON and human-readable output.
 *
 * Features:
 * - Log levels: DEBUG, INFO, WARN, ERROR
 * - Module filtering: per-module level overrides
 * - Output formats: Human-readable (colored) or JSON
 * - Multiple outputs: file, syslog, console (stdout)
 * - Callback system for external integration
 * - Thread-safe with lazy formatting
 *
 * Usage:
 *   LOGM_INFO(LOG_MODULE_LUA, "Loaded module %s", name);
 *   LOGM_ERROR(LOG_MODULE_STATS, "Failed to find stat %s", stat_name);
 *
 * Or use module-specific shortcuts:
 *   LOG_LUA_INFO("Loaded module %s", name);
 *   LOG_STATS_ERROR("Failed to find stat %s", stat_name);
 *
 * Note: Using LOGM_ prefix to avoid collision with syslog.h's LOG_DEBUG/LOG_INFO.
 *
 * Environment variables:
 *   BG3SE_LOG_LEVEL=DEBUG|INFO|WARN|ERROR
 *   BG3SE_LOG_FORMAT=human|json
 *   BG3SE_LOG_COLOR=0|1
 *   BG3SE_LOG_MODULES=Stats:DEBUG,Lua:INFO
 */

#ifndef BG3SE_LOGGING_H
#define BG3SE_LOGGING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Log Levels
// ============================================================================

typedef enum {
    LOG_LEVEL_DEBUG = 0,  // Verbose development info (off in release by default)
    LOG_LEVEL_INFO  = 1,  // Normal operational messages
    LOG_LEVEL_WARN  = 2,  // Potential issues, recoverable errors
    LOG_LEVEL_ERROR = 3,  // Serious errors, failures
    LOG_LEVEL_NONE  = 4   // Suppress all logging
} LogLevel;

// ============================================================================
// Log Modules
// ============================================================================

typedef enum {
    LOG_MODULE_CORE = 0,     // Core initialization, shutdown
    LOG_MODULE_CONSOLE,      // File-based console, commands
    LOG_MODULE_LUA,          // Lua state, API calls, Ext.*
    LOG_MODULE_OSIRIS,       // Osiris integration, Osi.*
    LOG_MODULE_ENTITY,       // Entity Component System
    LOG_MODULE_EVENTS,       // Event dispatch system
    LOG_MODULE_STATS,        // Stats system, Ext.Stats
    LOG_MODULE_TIMER,        // Timer system, Ext.Timer
    LOG_MODULE_HOOKS,        // Dobby hooks, pattern scanning
    LOG_MODULE_MOD,          // Mod loading, PAK files
    LOG_MODULE_MEMORY,       // Memory operations, Ext.Memory/Debug
    LOG_MODULE_PERSIST,      // PersistentVars
    LOG_MODULE_GAME,         // Game state tracking
    LOG_MODULE_INPUT,        // Input system, Ext.Input
    LOG_MODULE_IMGUI,        // ImGui overlay system
    LOG_MODULE_MAX
} LogModule;

// ============================================================================
// Output Configuration
// ============================================================================

typedef enum {
    LOG_OUTPUT_FILE     = (1 << 0),  // Write to log file
    LOG_OUTPUT_SYSLOG   = (1 << 1),  // Write to syslog
    LOG_OUTPUT_CONSOLE  = (1 << 2),  // Write to stdout (with colors if enabled)
    LOG_OUTPUT_CALLBACK = (1 << 3)   // Forward to registered callbacks
} LogOutputFlags;

typedef enum {
    LOG_FORMAT_HUMAN = 0,  // Human-readable: [timestamp] [LEVEL] [Module] message
    LOG_FORMAT_JSON  = 1   // JSON: {"ts":"...","level":"...","module":"...","msg":"..."}
} LogFormat;

// ============================================================================
// Callback System
// ============================================================================

/**
 * Callback function type for log message forwarding.
 *
 * PERFORMANCE REQUIREMENTS:
 * - Callbacks execute synchronously on the logging thread
 * - Must complete within ~100µs to avoid blocking hot paths
 * - For slow operations (network, disk): buffer messages and process async
 * - Heavy callbacks should use module_mask to filter to only needed modules
 * - Avoid allocations in callbacks when possible
 *
 * @param level    Log level of the message
 * @param module   Module that generated the message
 * @param message  Formatted message (already formatted, valid only during call)
 * @param userdata User-provided context pointer
 */
typedef void (*LogCallback)(LogLevel level, LogModule module,
                            const char* message, void* userdata);

// ============================================================================
// Initialization & Configuration
// ============================================================================

/**
 * Initialize the logging system.
 * Reads configuration from environment variables.
 * Call once at startup before any logging.
 */
void log_init(void);

/**
 * Shutdown the logging system.
 * Flushes any buffered output and cleans up resources.
 */
void log_shutdown(void);

/**
 * Set the global minimum log level.
 * Messages below this level are suppressed (unless overridden per-module).
 */
void log_set_global_level(LogLevel level);

/**
 * Get the current global log level.
 */
LogLevel log_get_global_level(void);

/**
 * Set the log level for a specific module.
 * Use LOG_LEVEL_NONE to inherit from global level.
 * @param module Module to configure
 * @param level  Level for this module (-1 = inherit global)
 */
void log_set_module_level(LogModule module, LogLevel level);

/**
 * Get the effective log level for a module.
 * Returns module-specific level if set, otherwise global level.
 */
LogLevel log_get_module_level(LogModule module);

/**
 * Set output destinations (bitmask of LogOutputFlags).
 */
void log_set_output_flags(uint32_t flags);

/**
 * Get current output flags.
 */
uint32_t log_get_output_flags(void);

/**
 * Set output format (human or JSON).
 */
void log_set_format(LogFormat format);

/**
 * Get current output format.
 */
LogFormat log_get_format(void);

/**
 * Enable or disable ANSI color output for console.
 */
void log_set_color_enabled(bool enabled);

/**
 * Check if color output is enabled.
 */
bool log_get_color_enabled(void);

// ============================================================================
// Callback Registration
// ============================================================================

/**
 * Register a callback to receive log messages.
 * @param callback   Function to call for each log message
 * @param userdata   User context passed to callback
 * @param min_level  Only forward messages >= this level
 * @param module_mask Bitmask of modules to forward (0 = all)
 * @return Callback ID (>= 0) on success, -1 on failure
 */
int log_register_callback(LogCallback callback, void* userdata,
                          LogLevel min_level, uint32_t module_mask);

/**
 * Unregister a previously registered callback.
 * @param callback_id ID returned from log_register_callback
 */
void log_unregister_callback(int callback_id);

// ============================================================================
// Debug Callback (VS Code Debugger Support - Issue #42)
// ============================================================================

/**
 * Debug callback function type.
 * Called synchronously when an error-level message is logged.
 * Intended for VS Code debugger's "breakOnGenericError" feature.
 *
 * @param level   Log level of the message
 * @param module  Module that generated the message
 * @param message Formatted message
 */
typedef void (*DebugLogCallback)(LogLevel level, LogModule module, const char* message);

/**
 * Set the debug callback for error-level messages.
 * This callback is invoked for all LOG_LEVEL_ERROR messages,
 * allowing a debugger to break when errors are logged.
 *
 * @param callback Function to call on error messages (NULL to disable)
 */
void log_set_debug_callback(DebugLogCallback callback);

/**
 * Get the current debug callback.
 */
DebugLogCallback log_get_debug_callback(void);

// ============================================================================
// Core Logging Functions
// ============================================================================

/**
 * Check if a message at the given level/module would be logged.
 * Use for expensive operations to avoid unnecessary formatting.
 */
bool log_should_write(LogLevel level, LogModule module);

/**
 * Write a log message with full context.
 * Prefer using LOG_* macros instead of calling directly.
 */
void log_write(LogLevel level, LogModule module,
               const char* file, int line,
               const char* format, ...) __attribute__((format(printf, 5, 6)));

/**
 * Write a log message (va_list version).
 */
void log_write_v(LogLevel level, LogModule module,
                 const char* file, int line,
                 const char* format, va_list args);

// ============================================================================
// Backward Compatibility
// ============================================================================

/**
 * Legacy log function (maps to LOG_INFO with LOG_MODULE_CORE).
 * Preserved for backward compatibility with existing code.
 */
void log_message(const char* format, ...) __attribute__((format(printf, 1, 2)));

// ============================================================================
// Helper Functions (from version.h)
// ============================================================================

/**
 * Get the BG3SE data directory path.
 */
const char* bg3se_get_data_dir(void);

/**
 * Get full path to a file in the data directory.
 */
const char* bg3se_get_data_path(const char* filename);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get the string name for a log level.
 */
const char* log_level_name(LogLevel level);

/**
 * Get the short string name for a log level (3 chars).
 */
const char* log_level_short(LogLevel level);

/**
 * Get the string name for a log module.
 */
const char* log_module_name(LogModule module);

/**
 * Parse a log level from string (case-insensitive).
 * @return LOG_LEVEL_INFO on unrecognized input
 */
LogLevel log_level_from_string(const char* str);

/**
 * Parse a log module from string (case-insensitive).
 * @return LOG_MODULE_CORE on unrecognized input
 */
LogModule log_module_from_string(const char* str);

// ============================================================================
// Logging Macros (Primary Interface)
// ============================================================================

// Note: Using LOGM_ prefix to avoid collision with syslog.h's LOG_DEBUG/LOG_INFO
// Using __VA_OPT__ (C23/C++20) for standards-compliant variadic macro handling
#define LOGM_DEBUG(module, fmt, ...) \
    do { if (log_should_write(LOG_LEVEL_DEBUG, module)) \
        log_write(LOG_LEVEL_DEBUG, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__); \
    } while(0)

#define LOGM_INFO(module, fmt, ...) \
    do { if (log_should_write(LOG_LEVEL_INFO, module)) \
        log_write(LOG_LEVEL_INFO, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__); \
    } while(0)

#define LOGM_WARN(module, fmt, ...) \
    do { if (log_should_write(LOG_LEVEL_WARN, module)) \
        log_write(LOG_LEVEL_WARN, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__); \
    } while(0)

#define LOGM_ERROR(module, fmt, ...) \
    do { if (log_should_write(LOG_LEVEL_ERROR, module)) \
        log_write(LOG_LEVEL_ERROR, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__); \
    } while(0)

// ============================================================================
// Module-Specific Shortcut Macros
// ============================================================================

// Core module
#define LOG_CORE_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_CORE, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_CORE_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_CORE, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_CORE_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_CORE, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_CORE_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_CORE, fmt __VA_OPT__(,) __VA_ARGS__)

// Console module
#define LOG_CONSOLE_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_CONSOLE, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_CONSOLE_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_CONSOLE, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_CONSOLE_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_CONSOLE, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_CONSOLE_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_CONSOLE, fmt __VA_OPT__(,) __VA_ARGS__)

// Lua module
#define LOG_LUA_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_LUA, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_LUA_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_LUA, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_LUA_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_LUA, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_LUA_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_LUA, fmt __VA_OPT__(,) __VA_ARGS__)

// Osiris module
#define LOG_OSIRIS_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_OSIRIS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_OSIRIS_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_OSIRIS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_OSIRIS_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_OSIRIS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_OSIRIS_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_OSIRIS, fmt __VA_OPT__(,) __VA_ARGS__)

// Entity module
#define LOG_ENTITY_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_ENTITY, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_ENTITY_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_ENTITY, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_ENTITY_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_ENTITY, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_ENTITY_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_ENTITY, fmt __VA_OPT__(,) __VA_ARGS__)

// Events module
#define LOG_EVENTS_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_EVENTS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_EVENTS_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_EVENTS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_EVENTS_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_EVENTS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_EVENTS_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_EVENTS, fmt __VA_OPT__(,) __VA_ARGS__)

// Stats module
#define LOG_STATS_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_STATS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_STATS_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_STATS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_STATS_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_STATS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_STATS_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_STATS, fmt __VA_OPT__(,) __VA_ARGS__)

// Timer module
#define LOG_TIMER_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_TIMER, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_TIMER_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_TIMER, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_TIMER_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_TIMER, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_TIMER_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_TIMER, fmt __VA_OPT__(,) __VA_ARGS__)

// Hooks module
#define LOG_HOOKS_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_HOOKS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_HOOKS_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_HOOKS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_HOOKS_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_HOOKS, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_HOOKS_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_HOOKS, fmt __VA_OPT__(,) __VA_ARGS__)

// Mod module
#define LOG_MOD_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_MOD, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_MOD_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_MOD, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_MOD_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_MOD, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_MOD_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_MOD, fmt __VA_OPT__(,) __VA_ARGS__)

// Memory module
#define LOG_MEMORY_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_MEMORY, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_MEMORY_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_MEMORY, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_MEMORY_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_MEMORY, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_MEMORY_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_MEMORY, fmt __VA_OPT__(,) __VA_ARGS__)

// Persist module
#define LOG_PERSIST_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_PERSIST, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_PERSIST_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_PERSIST, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_PERSIST_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_PERSIST, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_PERSIST_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_PERSIST, fmt __VA_OPT__(,) __VA_ARGS__)

// Game module
#define LOG_GAME_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_GAME, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_GAME_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_GAME, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_GAME_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_GAME, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_GAME_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_GAME, fmt __VA_OPT__(,) __VA_ARGS__)

// Input module
#define LOG_INPUT_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_INPUT, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_INPUT_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_INPUT, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_INPUT_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_INPUT, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_INPUT_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_INPUT, fmt __VA_OPT__(,) __VA_ARGS__)

// ImGui module
#define LOG_IMGUI_DEBUG(fmt, ...) LOGM_DEBUG(LOG_MODULE_IMGUI, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_IMGUI_INFO(fmt, ...)  LOGM_INFO(LOG_MODULE_IMGUI, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_IMGUI_WARN(fmt, ...)  LOGM_WARN(LOG_MODULE_IMGUI, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_IMGUI_ERROR(fmt, ...) LOGM_ERROR(LOG_MODULE_IMGUI, fmt __VA_OPT__(,) __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // BG3SE_LOGGING_H
