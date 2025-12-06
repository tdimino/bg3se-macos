/**
 * console.h - BG3SE Console with file-based and socket interfaces
 *
 * Features:
 * - File-based: Poll a file, execute each line as Lua, delete file
 * - Socket-based: Unix domain socket server for real-time bidirectional I/O
 * - Multi-line mode: Accumulate lines between --[[ and ]]-- delimiters
 * - Console commands: Lines starting with ! are dispatched to registered handlers
 *
 * Socket Console Usage:
 *   # Connect with the bg3se-console client (recommended):
 *   ./bg3se-console
 *
 *   # Or connect with socat/nc:
 *   socat - UNIX-CONNECT:/tmp/bg3se.sock
 *   nc -U /tmp/bg3se.sock
 *
 * File-based Usage (fallback):
 *   echo 'Ext.Print("hello")' > ~/Library/Application\ Support/BG3SE/commands.txt
 */

#ifndef CONSOLE_H
#define CONSOLE_H

#include <lua.h>
#include <stdbool.h>

// ============================================================================
// Socket Path
// ============================================================================

#define CONSOLE_SOCKET_PATH "/tmp/bg3se.sock"

// ============================================================================
// Initialization and Polling
// ============================================================================

/**
 * Initialize the console (file-based and socket server).
 * Must be called before console_poll().
 */
void console_init(void);

/**
 * Shutdown the console (close socket, cleanup).
 */
void console_shutdown(void);

/**
 * Get the command file path (after console_init).
 */
const char *console_get_command_file(void);

/**
 * Get the socket path.
 */
const char *console_get_socket_path(void);

/**
 * Check if a client is connected to the socket.
 */
bool console_has_client(void);

/**
 * Poll for commands and execute them.
 * Call this from the game loop (e.g., fake_Event hook).
 *
 * Checks both:
 * - Socket connections (higher priority, real-time)
 * - File-based commands (fallback)
 *
 * Features:
 * - Single-line Lua execution
 * - Multi-line blocks between --[[ and ]]-- delimiters
 * - Console commands with ! prefix (dispatched to registered handlers)
 * - Comments with # prefix (outside multi-line blocks)
 */
void console_poll(lua_State *L);

// ============================================================================
// Output Forwarding
// ============================================================================

/**
 * Send output to connected console client(s).
 * Called by Ext.Print and logging system.
 *
 * @param message The message to send
 * @param is_error If true, prefix with error indicator
 */
void console_send_output(const char *message, bool is_error);

/**
 * Printf-style output to connected console client(s).
 */
void console_printf(const char *format, ...) __attribute__((format(printf, 1, 2)));

/**
 * Printf-style error output to connected console client(s).
 */
void console_error(const char *format, ...) __attribute__((format(printf, 1, 2)));

// ============================================================================
// Command Registration
// ============================================================================

/**
 * Register a console command handler (Lua C function).
 *
 * Lua signature: Ext.RegisterConsoleCommand(name, callback)
 *   - name: Command name (without the ! prefix)
 *   - callback: function(cmd, arg1, arg2, ...)
 *
 * Usage from Lua:
 *   Ext.RegisterConsoleCommand("probe", function(cmd, addr, range)
 *       Ext.Print("Probing address: " .. addr)
 *   end)
 *
 * Then in console:
 *   !probe 0x12345678 0x100
 */
int console_register_command(lua_State *L);

#endif // CONSOLE_H
