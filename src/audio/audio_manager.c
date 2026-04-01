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
// Additional VMT indices — TBD: verify via Ghidra for ARM64
#define WWISE_VMT_PLAY_EXTERNAL    28   /* PlayExternalSound */
#define WWISE_VMT_GET_ID_FROM_STR  30   /* GetIDFromString (SoundNameId) */
#define WWISE_VMT_LOAD_BANK        32   /* LoadBank */
#define WWISE_VMT_UNLOAD_BANK      34   /* UnloadBank */
#define WWISE_VMT_PREPARE_BANK     36   /* PrepareBank */

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

// ============================================================================
// Extended Bank/External Sound Management
// ============================================================================

/**
 * GetIDFromString — get a SoundNameId (uint32_t) from an event/bank name string.
 * Returns UINT32_MAX on failure (no valid ID found).
 *
 * On Windows: SoundNameId is a 4-byte integer returned by WwiseManager::GetIDFromString.
 * The function has simple 4-byte return so no x8 buffer needed.
 */
typedef uint32_t (*WwiseGetIdFromStringFn)(void *this_, const char *name);

static uint32_t get_sound_name_id(void *sm, const char *name) {
    void *func = read_vmt_entry(sm, WWISE_VMT_GET_ID_FROM_STR);
    if (!func) return UINT32_MAX;
    WwiseGetIdFromStringFn get_id = (WwiseGetIdFromStringFn)func;
    return get_id(sm, name);
}

/**
 * PlayExternalSound — play a sound from a file path via a Wwise event.
 *
 * Windows signature:
 *   bool PlayExternalSound(SoundObjectId obj, SoundNameId eventId,
 *                          STDString& path, uint8_t codec,
 *                          float positionSec, bool loop, void* callback)
 *
 * We pass a null-terminated C string for the path (the game reads it as an
 * LS STDString*, which begins with the char* at offset 0 on macOS/Win).
 * This relies on the STDString small-buffer optimization: strings < 16 chars
 * are stored inline. For longer paths we pass a heap pointer directly.
 * Since we cannot fully reconstruct an STDString on the stack without ABI
 * knowledge, this is a best-effort implementation that will work for simple
 * short paths. For production use, VMT indices must be verified via Ghidra.
 */
typedef bool (*WwisePlayExternalFn)(void *this_,
                                     uint64_t sound_object,
                                     uint32_t event_id,
                                     const char *path,    /* STDString* — ABI approximation */
                                     uint8_t codec,
                                     float position_sec,
                                     bool loop,
                                     void *callback);

bool audio_play_external_sound(uint64_t sound_object_id, const char *event_name,
                                const char *file_path, uint8_t codec,
                                float position_sec) {
    if (!event_name || !file_path) return false;

    // SAFETY: STDString ABI not yet verified on ARM64 macOS. Passing char* where
    // STDString& is expected works only for short strings (SSO path). Disable until
    // the ABI is confirmed via Ghidra to prevent crashes on longer file paths.
    log_message("[Audio] PlayExternalSound: disabled — STDString ABI not yet verified on ARM64");
    return false;

    void *sm = get_sound_manager();
    if (!sm) {
        log_message("[Audio] SoundManager not available for PlayExternalSound");
        return false;
    }

    uint32_t event_id = get_sound_name_id(sm, event_name);
    if (event_id == UINT32_MAX) {
        log_message("[Audio] PlayExternalSound: could not resolve event ID for '%s'", event_name);
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_PLAY_EXTERNAL);
    if (!func) {
        log_message("[Audio] PlayExternalSound VMT entry not found at index %d", WWISE_VMT_PLAY_EXTERNAL);
        return false;
    }

    WwisePlayExternalFn play = (WwisePlayExternalFn)func;
    return play(sm, sound_object_id, event_id, file_path, codec, position_sec, false, NULL);
}

/**
 * LoadBank — load a Wwise sound bank.
 *
 * Windows: LoadBank(SoundNameId& bankId, char const* bankName)
 * bankId is set by the callee. We pass a local uint32_t by address.
 */
typedef void (*WwiseLoadBankFn)(void *this_, uint32_t *out_bank_id, const char *bank_name);

bool audio_load_bank(const char *bank_name) {
    if (!bank_name) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        log_message("[Audio] SoundManager not available for LoadBank");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_LOAD_BANK);
    if (!func) {
        log_message("[Audio] LoadBank VMT entry not found at index %d", WWISE_VMT_LOAD_BANK);
        return false;
    }

    uint32_t bank_id = UINT32_MAX;
    WwiseLoadBankFn load = (WwiseLoadBankFn)func;
    load(sm, &bank_id, bank_name);
    return bank_id != UINT32_MAX;
}

/**
 * UnloadBank — unload a Wwise sound bank.
 *
 * Windows: UnloadBank(SoundNameId bankId)
 */
typedef bool (*WwiseUnloadBankFn)(void *this_, uint32_t bank_id);

bool audio_unload_bank(const char *bank_name) {
    if (!bank_name) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        log_message("[Audio] SoundManager not available for UnloadBank");
        return false;
    }

    uint32_t bank_id = get_sound_name_id(sm, bank_name);
    if (bank_id == UINT32_MAX) {
        log_message("[Audio] UnloadBank: could not resolve bank ID for '%s'", bank_name);
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_UNLOAD_BANK);
    if (!func) {
        log_message("[Audio] UnloadBank VMT entry not found at index %d", WWISE_VMT_UNLOAD_BANK);
        return false;
    }

    WwiseUnloadBankFn unload = (WwiseUnloadBankFn)func;
    return unload(sm, bank_id);
}

/**
 * PrepareBank — pre-load bank metadata for streaming.
 * Same signature as LoadBank: callee sets bankId.
 */
bool audio_prepare_bank(const char *bank_name) {
    if (!bank_name) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        log_message("[Audio] SoundManager not available for PrepareBank");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_PREPARE_BANK);
    if (!func) {
        log_message("[Audio] PrepareBank VMT entry not found at index %d", WWISE_VMT_PREPARE_BANK);
        return false;
    }

    uint32_t bank_id = UINT32_MAX;
    WwiseLoadBankFn prepare = (WwiseLoadBankFn)func;
    prepare(sm, &bank_id, bank_name);
    return bank_id != UINT32_MAX;
}

/**
 * UnprepareBank — release prepared bank metadata.
 * Windows implementation calls UnloadBank internally (same as UnloadBank).
 */
bool audio_unprepare_bank(const char *bank_name) {
    /* Windows BG3SE UnprepareBank calls UnloadBank internally */
    return audio_unload_bank(bank_name);
}
