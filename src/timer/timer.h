/**
 * timer.h - Timer system for scheduling delayed and repeating callbacks
 *
 * Features:
 * - One-shot timers (fire once after delay)
 * - Repeating timers (fire at regular intervals)
 * - Pause/resume support
 * - High-resolution monotonic timing via mach_absolute_time
 */

#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>
#include <stdbool.h>
#include <lua.h>

// Maximum number of concurrent timers
#define TIMER_MAX_COUNT 256

// Timer handle type (returned to Lua)
typedef uint64_t TimerHandle;

// Initialize the timer system
void timer_init(void);

// Shutdown and cleanup all timers
void timer_shutdown(lua_State *L);

// Create a one-shot timer
// Returns handle, or 0 on failure
TimerHandle timer_create(lua_State *L, double delay_ms, int callback_ref, double repeat_ms);

// Cancel a timer
// Returns true if timer was found and cancelled
bool timer_cancel(lua_State *L, TimerHandle handle);

// Pause a timer
bool timer_pause(TimerHandle handle);

// Resume a paused timer
bool timer_resume(TimerHandle handle);

// Check if timer is paused
bool timer_is_paused(TimerHandle handle);

// Update timers - call from game tick
// Fires any expired timers
void timer_update(lua_State *L);

// Get monotonic time in milliseconds since process start
double timer_get_monotonic_ms(void);

// Clear all timers (call on Lua state reset)
void timer_clear_all(lua_State *L);

#endif // TIMER_H
