/**
 * console.h - File-based Lua console for live command execution
 *
 * Usage:
 *   echo 'Ext.Print("hello")' >> ~/Library/Application\ Support/BG3SE/commands.txt
 *   tail -f ~/Library/Application\ Support/BG3SE/bg3se.log
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
 * Commands are read line-by-line, executed, and the file is deleted.
 */
void console_poll(lua_State *L);

#endif // CONSOLE_H
