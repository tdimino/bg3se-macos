/**
 * console.h - File-based Lua console with multi-line support
 *
 * Features:
 * - Poll a file, execute each line as Lua, delete file
 * - Multi-line mode: Accumulate lines between --[[ and ]]-- delimiters
 * - Console commands: Lines starting with ! are dispatched to registered handlers
 *
 * Usage:
 *   # Single-line commands
 *   echo 'Ext.Print("hello")' > ~/Library/Application\ Support/BG3SE/commands.txt
 *
 *   # Multi-line blocks
 *   cat > ~/Library/Application\ Support/BG3SE/commands.txt << 'EOF'
 *   --[[
 *   local stat = Ext.Stats.Get("WPN_Longsword")
 *   for k,v in pairs(stat) do
 *       Ext.Print(k .. " = " .. tostring(v))
 *   end
 *   ]]--
 *   EOF
 *
 *   # Console commands
 *   echo '!help' > ~/Library/Application\ Support/BG3SE/commands.txt
 */

#ifndef CONSOLE_H
#define CONSOLE_H

#include <lua.h>

/**
 * Initialize the console (resolves command file path).
 * Must be called before console_poll().
 */
void console_init(void);

/**
 * Get the command file path (after console_init).
 */
const char *console_get_command_file(void);

/**
 * Poll for commands and execute them.
 * Call this from the game loop (e.g., fake_Event hook).
 *
 * Features:
 * - Single-line Lua execution
 * - Multi-line blocks between --[[ and ]]-- delimiters
 * - Console commands with ! prefix (dispatched to registered handlers)
 * - Comments with # prefix (outside multi-line blocks)
 *
 * Commands are read line-by-line, executed, and the file is deleted.
 */
void console_poll(lua_State *L);

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
 * Then in commands.txt:
 *   !probe 0x12345678 0x100
 */
int console_register_command(lua_State *L);

#endif // CONSOLE_H
