/**
 * timer.c - Timer system implementation
 *
 * Uses a fixed-size timer pool and a min-heap priority queue for efficient
 * "get next timer to fire" operations. Timers store Lua callback references
 * via luaL_ref to prevent garbage collection.
 */

#include "timer.h"
#include "../core/logging.h"

#include <stdlib.h>
#include <string.h>
#include <mach/mach_time.h>
#include <lauxlib.h>

// ============================================================================
// Timer Structure
// ============================================================================

typedef struct {
    double fire_time;        // Monotonic time when timer should fire (ms)
    double repeat_interval;  // 0 for one-shot, >0 for repeating (ms)
    int callback_ref;        // Lua registry reference (LUA_NOREF if inactive)
    uint32_t invoke_id;      // Incremented on pause/resume to invalidate stale queue entries
    bool paused;
    bool active;             // Slot in use
} Timer;

// ============================================================================
// Priority Queue Entry
// ============================================================================

typedef struct {
    double fire_time;
    TimerHandle handle;
    uint32_t invoke_id;      // Must match timer's invoke_id to be valid
} TimerQueueEntry;

// ============================================================================
// Static State
// ============================================================================

// Timer pool
static Timer s_timers[TIMER_MAX_COUNT];
static int s_timer_count = 0;

// Priority queue (min-heap)
#define QUEUE_MAX_SIZE 512
static TimerQueueEntry s_queue[QUEUE_MAX_SIZE];
static int s_queue_size = 0;

// Time conversion
static mach_timebase_info_data_t s_timebase_info;
static uint64_t s_start_time = 0;
static bool s_initialized = false;

// ============================================================================
// Time Functions
// ============================================================================

static void init_timebase(void) {
    if (s_initialized) return;

    mach_timebase_info(&s_timebase_info);
    s_start_time = mach_absolute_time();
    s_initialized = true;
}

double timer_get_monotonic_ms(void) {
    if (!s_initialized) init_timebase();

    uint64_t elapsed = mach_absolute_time() - s_start_time;
    // Convert to nanoseconds, then to milliseconds
    uint64_t nanos = elapsed * s_timebase_info.numer / s_timebase_info.denom;
    return (double)nanos / 1000000.0;
}

// ============================================================================
// Priority Queue (Min-Heap)
// ============================================================================

static void queue_swap(int i, int j) {
    TimerQueueEntry tmp = s_queue[i];
    s_queue[i] = s_queue[j];
    s_queue[j] = tmp;
}

static void queue_sift_up(int idx) {
    while (idx > 0) {
        int parent = (idx - 1) / 2;
        if (s_queue[idx].fire_time < s_queue[parent].fire_time) {
            queue_swap(idx, parent);
            idx = parent;
        } else {
            break;
        }
    }
}

static void queue_sift_down(int idx) {
    while (true) {
        int left = 2 * idx + 1;
        int right = 2 * idx + 2;
        int smallest = idx;

        if (left < s_queue_size && s_queue[left].fire_time < s_queue[smallest].fire_time) {
            smallest = left;
        }
        if (right < s_queue_size && s_queue[right].fire_time < s_queue[smallest].fire_time) {
            smallest = right;
        }

        if (smallest != idx) {
            queue_swap(idx, smallest);
            idx = smallest;
        } else {
            break;
        }
    }
}

static bool queue_push(double fire_time, TimerHandle handle, uint32_t invoke_id) {
    if (s_queue_size >= QUEUE_MAX_SIZE) {
        log_message("[Timer] Warning: Queue full, cannot schedule timer");
        return false;
    }

    s_queue[s_queue_size].fire_time = fire_time;
    s_queue[s_queue_size].handle = handle;
    s_queue[s_queue_size].invoke_id = invoke_id;
    queue_sift_up(s_queue_size);
    s_queue_size++;
    return true;
}

static TimerQueueEntry queue_pop(void) {
    TimerQueueEntry top = s_queue[0];
    s_queue_size--;
    if (s_queue_size > 0) {
        s_queue[0] = s_queue[s_queue_size];
        queue_sift_down(0);
    }
    return top;
}

static bool queue_empty(void) {
    return s_queue_size == 0;
}

static TimerQueueEntry queue_top(void) {
    return s_queue[0];
}

// ============================================================================
// Timer Pool
// ============================================================================

static int timer_pool_alloc(void) {
    for (int i = 0; i < TIMER_MAX_COUNT; i++) {
        if (!s_timers[i].active) {
            return i;
        }
    }
    return -1;  // Pool full
}

static Timer *timer_get(TimerHandle handle) {
    // Handles are 1-based (0 = invalid), convert to 0-based index
    if (handle == 0) return NULL;
    uint32_t idx = (uint32_t)((handle - 1) & 0xFFFFFFFF);
    if (idx >= TIMER_MAX_COUNT) return NULL;
    if (!s_timers[idx].active) return NULL;
    return &s_timers[idx];
}

// ============================================================================
// Public API
// ============================================================================

void timer_init(void) {
    init_timebase();

    // Clear timer pool
    memset(s_timers, 0, sizeof(s_timers));
    for (int i = 0; i < TIMER_MAX_COUNT; i++) {
        s_timers[i].callback_ref = LUA_NOREF;
    }
    s_timer_count = 0;

    // Clear queue
    s_queue_size = 0;

    log_message("[Timer] Timer system initialized");
}

void timer_shutdown(lua_State *L) {
    timer_clear_all(L);
    log_message("[Timer] Timer system shut down");
}

TimerHandle timer_create(lua_State *L, double delay_ms, int callback_ref, double repeat_ms) {
    int idx = timer_pool_alloc();
    if (idx < 0) {
        log_message("[Timer] Error: Timer pool exhausted (%d max)", TIMER_MAX_COUNT);
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return 0;
    }

    double now = timer_get_monotonic_ms();

    Timer *timer = &s_timers[idx];
    timer->fire_time = now + delay_ms;
    timer->repeat_interval = repeat_ms;
    timer->callback_ref = callback_ref;
    timer->invoke_id = 0;
    timer->paused = false;
    timer->active = true;
    s_timer_count++;

    // Handles are 1-based (0 = invalid/error)
    TimerHandle handle = (TimerHandle)(idx + 1);

    if (!queue_push(timer->fire_time, handle, timer->invoke_id)) {
        // Queue full, cancel the timer
        timer->active = false;
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        timer->callback_ref = LUA_NOREF;
        s_timer_count--;
        return 0;
    }

    return handle;
}

bool timer_cancel(lua_State *L, TimerHandle handle) {
    Timer *timer = timer_get(handle);
    if (!timer) return false;

    // Release Lua callback reference
    if (timer->callback_ref != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, timer->callback_ref);
        timer->callback_ref = LUA_NOREF;
    }

    timer->active = false;
    s_timer_count--;

    // Note: We don't remove from queue - the entry will be ignored when popped
    // because active=false

    return true;
}

bool timer_pause(TimerHandle handle) {
    Timer *timer = timer_get(handle);
    if (!timer || timer->paused) return false;

    double now = timer_get_monotonic_ms();

    // Store remaining time
    timer->fire_time = timer->fire_time - now;  // Store as delta
    timer->paused = true;
    timer->invoke_id++;  // Invalidate any queued entries

    return true;
}

bool timer_resume(TimerHandle handle) {
    Timer *timer = timer_get(handle);
    if (!timer || !timer->paused) return false;

    double now = timer_get_monotonic_ms();

    // Restore fire time
    timer->fire_time = now + timer->fire_time;  // fire_time was storing delta
    timer->paused = false;

    // Re-queue the timer
    if (!queue_push(timer->fire_time, handle, timer->invoke_id)) {
        log_message("[Timer] Warning: Failed to resume timer (queue full)");
        timer->paused = true;  // Restore paused state
        return false;
    }

    return true;
}

bool timer_is_paused(TimerHandle handle) {
    Timer *timer = timer_get(handle);
    return timer && timer->paused;
}

void timer_update(lua_State *L) {
    if (!L) return;

    double now = timer_get_monotonic_ms();

    while (!queue_empty() && queue_top().fire_time <= now) {
        TimerQueueEntry entry = queue_pop();
        Timer *timer = timer_get(entry.handle);

        // Validate: timer exists, active, not paused, invoke_id matches
        if (!timer || !timer->active || timer->paused ||
            timer->invoke_id != entry.invoke_id) {
            continue;  // Stale entry, skip
        }

        // Cache values BEFORE lua_pcall (callback might cancel/modify timer)
        bool is_repeating = (timer->repeat_interval > 0);
        double repeat_interval = timer->repeat_interval;
        int callback_ref = timer->callback_ref;

        // Fire callback
        lua_rawgeti(L, LUA_REGISTRYINDEX, callback_ref);
        lua_pushinteger(L, (lua_Integer)entry.handle);

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            log_message("[Timer] Callback error: %s", err ? err : "(unknown)");
            lua_pop(L, 1);
        }

        // Re-fetch timer (callback may have cancelled it or modified state)
        timer = timer_get(entry.handle);

        // Repeat or release
        if (timer && timer->active && is_repeating) {
            timer->fire_time = now + repeat_interval;
            if (!queue_push(timer->fire_time, entry.handle, timer->invoke_id)) {
                // Queue full, cancel the timer
                log_message("[Timer] Warning: Queue full during repeat, cancelling timer");
                if (timer->callback_ref != LUA_NOREF) {
                    luaL_unref(L, LUA_REGISTRYINDEX, timer->callback_ref);
                    timer->callback_ref = LUA_NOREF;
                }
                timer->active = false;
                s_timer_count--;
            }
        } else if (timer && timer->active) {
            // One-shot timer completed
            if (timer->callback_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, timer->callback_ref);
                timer->callback_ref = LUA_NOREF;
            }
            timer->active = false;
            s_timer_count--;
        }
        // If !timer || !timer->active, callback cancelled itself - already cleaned up
    }
}

void timer_clear_all(lua_State *L) {
    for (int i = 0; i < TIMER_MAX_COUNT; i++) {
        if (s_timers[i].active) {
            if (L && s_timers[i].callback_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, s_timers[i].callback_ref);
            }
            s_timers[i].callback_ref = LUA_NOREF;
            s_timers[i].active = false;
        }
    }
    s_timer_count = 0;
    s_queue_size = 0;

    log_message("[Timer] All timers cleared");
}
