/**
 * audio_manager.c - Audio Manager for BG3SE-macOS
 *
 * Provides access to the game's WwiseManager (WWise sound engine)
 * for Ext.Audio API (sound playback, state control, RTPC parameters).
 *
 * Access chain:
 *   ResourceManager::m_ptr -> ResourceManager* -> SoundManager (+???)
 *     -> WwiseManager* -> VMT calls for audio control
 *
 * Note: SoundManager offset from ResourceManager needs runtime discovery.
 * The WwiseManager VMT indices are from Windows BG3SE pattern analysis.
 */

#include "audio_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../strings/fixed_string.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// ============================================================================
// Constants and Offsets
// ============================================================================

// ResourceManager::m_ptr (shared with resource_manager.c)
#define OFFSET_RESOURCEMANAGER_PTR   0x08a8f070

// SoundManager offset within ResourceManager (needs runtime discovery)
// Placeholder - probe ResourceManager struct to find actual offset
#define RESOURCEMANAGER_SOUNDMANAGER_OFFSET  0x88  // TBD: needs runtime probe

// WwiseManager VMT indices (from Windows BG3SE analysis, need verification)
#define WWISE_VMT_POST_EVENT        5
#define WWISE_VMT_STOP              8
#define WWISE_VMT_SET_SWITCH       10
#define WWISE_VMT_SET_STATE        12
#define WWISE_VMT_SET_RTPC         14
#define WWISE_VMT_GET_RTPC         16
#define WWISE_VMT_RESET_RTPC       18
#define WWISE_VMT_PAUSE_ALL        20
#define WWISE_VMT_RESUME_ALL       22
#define WWISE_VMT_LOAD_EVENT       24
#define WWISE_VMT_UNLOAD_EVENT     26

// Well-known sound object IDs
#define SOUND_OBJECT_INVALID  0ULL
#define SOUND_OBJECT_GLOBAL   1ULL

// ============================================================================
// Module State
// ============================================================================

static struct {
    bool initialized;
    void *main_binary_base;
    void **resource_manager_ptr;
} g_audio = {0};

// ============================================================================
// Initialization
// ============================================================================

bool audio_manager_init(void *main_binary_base) {
    if (g_audio.initialized) {
        return true;
    }

    if (!main_binary_base) {
        log_message("[Audio] ERROR: main_binary_base is NULL");
        return false;
    }

    g_audio.main_binary_base = main_binary_base;
    g_audio.resource_manager_ptr = (void **)((uintptr_t)main_binary_base + OFFSET_RESOURCEMANAGER_PTR);

    log_message("[Audio] Audio manager initialized");
    log_message("[Audio]   Base: %p", main_binary_base);
    log_message("[Audio]   ResourceManager::m_ptr at offset 0x%x -> %p",
                OFFSET_RESOURCEMANAGER_PTR, (void *)g_audio.resource_manager_ptr);

    g_audio.initialized = true;
    return true;
}

bool audio_manager_ready(void) {
    if (!g_audio.initialized || !g_audio.resource_manager_ptr) {
        return false;
    }

    void *rm = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)g_audio.resource_manager_ptr, &rm)) {
        return false;
    }

    return rm != NULL;
}

// ============================================================================
// Internal Helpers
// ============================================================================

static void *get_resource_manager(void) {
    if (!g_audio.initialized || !g_audio.resource_manager_ptr) {
        return NULL;
    }

    void *rm = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)g_audio.resource_manager_ptr, &rm)) {
        return NULL;
    }

    return rm;
}

static void *get_sound_manager(void) {
    void *rm = get_resource_manager();
    if (!rm) return NULL;

    void *sm = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)rm + RESOURCEMANAGER_SOUNDMANAGER_OFFSET, &sm)) {
        return NULL;
    }

    return sm;
}

/**
 * Read a function pointer from a VMT at a given index.
 */
static void *read_vmt_entry(void *object, int index) {
    if (!object) return NULL;

    void *vmt = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)object, &vmt)) {
        return NULL;
    }

    void *func = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)vmt + (index * sizeof(void *)), &func)) {
        return NULL;
    }

    return func;
}

// ============================================================================
// Sound Object ID Resolution
// ============================================================================

uint64_t audio_resolve_sound_object(const char *name) {
    if (!name) return SOUND_OBJECT_INVALID;

    // Well-known sound objects
    if (strcasecmp(name, "Global") == 0 || strcasecmp(name, "Music") == 0) {
        return SOUND_OBJECT_GLOBAL;
    }

    // Listener objects (Listener0-Listener3)
    if (strncasecmp(name, "Listener", 8) == 0 && name[8] >= '0' && name[8] <= '3') {
        return 100ULL + (name[8] - '0');
    }

    // Ambient objects (Ambient0-Ambient3)
    if (strncasecmp(name, "Ambient", 7) == 0 && name[7] >= '0' && name[7] <= '3') {
        return 200ULL + (name[7] - '0');
    }

    // Numeric ID passed as string
    char *endptr = NULL;
    unsigned long long val = strtoull(name, &endptr, 0);
    if (endptr && *endptr == '\0' && val > 0) {
        return (uint64_t)val;
    }

    log_message("[Audio] Unknown sound object: %s", name);
    return SOUND_OBJECT_INVALID;
}

// ============================================================================
// Playback Control
// ============================================================================

typedef void (*WwisePostEventFn)(void *this_, uint64_t sound_object, const char *event_name);
typedef void (*WwiseStopFn)(void *this_, uint64_t sound_object);
typedef void (*WwisePauseAllFn)(void *this_);
typedef void (*WwiseResumeAllFn)(void *this_);

bool audio_post_event(uint64_t sound_object_id, const char *event_name) {
    if (!event_name) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        log_message("[Audio] SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_POST_EVENT);
    if (!func) {
        log_message("[Audio] PostEvent VMT entry not found");
        return false;
    }

    WwisePostEventFn post = (WwisePostEventFn)func;
    post(sm, sound_object_id, event_name);
    return true;
}

bool audio_stop(uint64_t sound_object_id) {
    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_STOP);
    if (!func) return false;

    WwiseStopFn stop = (WwiseStopFn)func;
    stop(sm, sound_object_id);
    return true;
}

bool audio_pause_all(void) {
    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_PAUSE_ALL);
    if (!func) return false;

    WwisePauseAllFn pause = (WwisePauseAllFn)func;
    pause(sm);
    return true;
}

bool audio_resume_all(void) {
    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_RESUME_ALL);
    if (!func) return false;

    WwiseResumeAllFn resume = (WwiseResumeAllFn)func;
    resume(sm);
    return true;
}

// ============================================================================
// State/Switch Control
// ============================================================================

typedef void (*WwiseSetSwitchFn)(void *this_, uint64_t sound_object,
                                  const char *switch_group, const char *state);
typedef void (*WwiseSetStateFn)(void *this_, const char *state_group, const char *state);

bool audio_set_switch(uint64_t sound_object_id, const char *switch_group, const char *state) {
    if (!switch_group || !state) return false;

    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_SET_SWITCH);
    if (!func) return false;

    WwiseSetSwitchFn set_switch = (WwiseSetSwitchFn)func;
    set_switch(sm, sound_object_id, switch_group, state);
    return true;
}

bool audio_set_state(const char *state_group, const char *state) {
    if (!state_group || !state) return false;

    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_SET_STATE);
    if (!func) return false;

    WwiseSetStateFn set_state = (WwiseSetStateFn)func;
    set_state(sm, state_group, state);
    return true;
}

// ============================================================================
// RTPC (Real-Time Parameter Control)
// ============================================================================

typedef void (*WwiseSetRtpcFn)(void *this_, uint64_t sound_object,
                                const char *name, float value);
typedef float (*WwiseGetRtpcFn)(void *this_, uint64_t sound_object, const char *name);
typedef void (*WwiseResetRtpcFn)(void *this_, uint64_t sound_object, const char *name);

bool audio_set_rtpc(uint64_t sound_object_id, const char *name, float value) {
    if (!name) return false;

    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_SET_RTPC);
    if (!func) return false;

    WwiseSetRtpcFn set = (WwiseSetRtpcFn)func;
    set(sm, sound_object_id, name, value);
    return true;
}

float audio_get_rtpc(uint64_t sound_object_id, const char *name) {
    if (!name) return 0.0f;

    void *sm = get_sound_manager();
    if (!sm) return 0.0f;

    void *func = read_vmt_entry(sm, WWISE_VMT_GET_RTPC);
    if (!func) return 0.0f;

    WwiseGetRtpcFn get = (WwiseGetRtpcFn)func;
    return get(sm, sound_object_id, name);
}

bool audio_reset_rtpc(uint64_t sound_object_id, const char *name) {
    if (!name) return false;

    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_RESET_RTPC);
    if (!func) return false;

    WwiseResetRtpcFn reset = (WwiseResetRtpcFn)func;
    reset(sm, sound_object_id, name);
    return true;
}

// ============================================================================
// Event/Bank Management
// ============================================================================

typedef void (*WwiseLoadEventFn)(void *this_, const char *event_name);
typedef void (*WwiseUnloadEventFn)(void *this_, const char *event_name);

bool audio_load_event(const char *event_name) {
    if (!event_name) return false;

    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_LOAD_EVENT);
    if (!func) return false;

    WwiseLoadEventFn load = (WwiseLoadEventFn)func;
    load(sm, event_name);
    return true;
}

bool audio_unload_event(const char *event_name) {
    if (!event_name) return false;

    void *sm = get_sound_manager();
    if (!sm) return false;

    void *func = read_vmt_entry(sm, WWISE_VMT_UNLOAD_EVENT);
    if (!func) return false;

    WwiseUnloadEventFn unload = (WwiseUnloadEventFn)func;
    unload(sm, event_name);
    return true;
}
