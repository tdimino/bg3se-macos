/**
 * audio_manager.c - Audio Manager for BG3SE-macOS
 *
 * Provides access to the game's WwiseManager (WWise sound engine)
 * for Ext.Audio API (sound playback, state control, RTPC parameters).
 *
 * Access chain:
 *   ResourceManager::m_ptr -> ResourceManager* -> +0x90 -> ww::WwiseManager*
 *     -> virtual calls (slot indices below)
 *
 * Every call first checks the object's vtable against the version's
 * `wwise_manager_vtable`; anything else refuses instead of calling.
 */

#include "audio_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../core/offset_table.h"
#include "../strings/fixed_string.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// ============================================================================
// Constants and Offsets
// ============================================================================

// ww::WwiseManager within ResourceManager. On 4.1.1.7398727 the object at
// +0x90 has the WwiseManager vtable; the one at +0x88 has no image vtable.
#define RESOURCEMANAGER_SOUNDMANAGER_OFFSET  0x90

// ww::WwiseManager vtable slots, read from the live vtable on 4.1.1.7398727
// and named with nm (argument lists match Windows BG3SE Sound.h):
#define WWISE_VMT_SET_SWITCH       20   /* SetSwitch(group, state, object) */
#define WWISE_VMT_SET_STATE        21   /* SetState(group, state) */
#define WWISE_VMT_SET_RTPC         22   /* SetRTPCValue(object, name, value, bypass) */
#define WWISE_VMT_GET_RTPC         23   /* GetRTPCValue(object, name) */
#define WWISE_VMT_RESET_RTPC       24   /* ResetRTPCValue(object, name) */
#define WWISE_VMT_STOP             29   /* StopSounds(object, transitionMs) */
#define WWISE_VMT_PAUSE_ALL        35   /* PauseAllSound() */
#define WWISE_VMT_RESUME_ALL       36   /* ResumeAllSound() */
#define WWISE_VMT_LOAD_EVENT       56   /* LoadEvent_Blocking(name) */
#define WWISE_VMT_UNLOAD_EVENT     57   /* UnloadEvent_Blocking(name) */
#define WWISE_VMT_POST_EVENT       78   /* PostEventInternal(object, name, seek, getPlayPos, callback) */

// Wwise AKRESULT value used by the game's ww::WwiseManager wrappers.
#define AK_SUCCESS 1

// Well-known sound object IDs
#define SOUND_OBJECT_INVALID  0ULL
#define SOUND_OBJECT_GLOBAL   1ULL

// ============================================================================
// ls::STDString Construction (verified via Ghidra — see STDSTRING_ABI.md)
// ============================================================================

// 16-byte libc++ layout with ls::StringAllocator. SSO threshold = 14 chars.
typedef struct {
    union {
        struct { char *data; uint32_t size; uint32_t cap_flag; } l;
        struct { char data[15]; uint8_t size_flag; } s;
    };
} LSSTDString;

typedef void (*STDStringCtorFn)(LSSTDString *this_, const char *str);

/*
 * Exported Wwise SoundEngine entry points used by the installed macOS game.
 *
 * These signatures and argument constants are mirrored from disassembly of
 * ww::WwiseManager::{Load,Unload,Prepare,Unprepare}Bank_Blocking in build
 * 4.1.1.7209685.  Resolving the exported AK symbols avoids the unverified
 * ResourceManager -> SoundManager receiver offset and guessed VMT indices.
 */
typedef uint32_t (*AkGetIdFromStringFn)(const char *name);
typedef int32_t (*AkLoadBankFn)(const char *name, uint32_t *out_bank_id,
                                uint32_t bank_type);
typedef int32_t (*AkUnloadBankFn)(uint32_t bank_id, const void *memory,
                                  uint32_t memory_size);
typedef int32_t (*AkPrepareBankByNameFn)(uint32_t preparation_type,
                                         const char *name,
                                         uint32_t bank_content,
                                         uint32_t flags);
typedef int32_t (*AkPrepareBankByIdFn)(uint32_t preparation_type,
                                       uint32_t bank_id,
                                       uint32_t bank_content,
                                       uint32_t flags);

__attribute__((unused))
static void ls_stdstring_init(LSSTDString *out, const char *str, STDStringCtorFn ctor) {
    size_t len = str ? strlen(str) : 0;
    memset(out, 0, sizeof(*out));
    if (len <= 14) {
        // SSO path — no allocation, entirely inline
        if (len > 0) memcpy(out->s.data, str, len);
        out->s.data[len] = '\0';
        out->s.size_flag = (uint8_t)len;  // bit 7 clear = short mode
    } else if (ctor) {
        // Long path — use game's constructor for MemoryManager-compatible allocation
        ctor(out, str);
    } else {
        // Fallback: truncate to SSO (14 chars). Lossy but safe.
        memcpy(out->s.data, str, 14);
        out->s.data[14] = '\0';
        out->s.size_flag = 14;
        log_message("[Audio] WARNING: STDString ctor not resolved, truncating path to 14 chars");
    }
}

// ============================================================================
// Module State
// ============================================================================

static struct {
    bool initialized;
    void *main_binary_base;
    void **resource_manager_ptr;
    STDStringCtorFn stdstring_ctor;
    AkGetIdFromStringFn ak_get_id_from_string;
    AkLoadBankFn ak_load_bank;
    AkUnloadBankFn ak_unload_bank;
    AkPrepareBankByNameFn ak_prepare_bank_by_name;
    AkPrepareBankByIdFn ak_prepare_bank_by_id;
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

    const VersionOffsets *off = offset_table_get();
    if (off && off->resource_mgr_ptr) {
        g_audio.resource_manager_ptr = (void **)offset_table_resolve(off->resource_mgr_ptr);
    } else {
        g_audio.resource_manager_ptr = NULL;
    }

    g_audio.stdstring_ctor =
        (STDStringCtorFn)offset_table_game_fn(GAME_FN_STD_STRING_CTOR);

    g_audio.ak_get_id_from_string = (AkGetIdFromStringFn)dlsym(
        RTLD_DEFAULT, "_ZN2AK11SoundEngine15GetIDFromStringEPKc");
    g_audio.ak_load_bank = (AkLoadBankFn)dlsym(
        RTLD_DEFAULT, "_ZN2AK11SoundEngine8LoadBankEPKcRjj");
    g_audio.ak_unload_bank = (AkUnloadBankFn)dlsym(
        RTLD_DEFAULT, "_ZN2AK11SoundEngine10UnloadBankEjPKvj");
    g_audio.ak_prepare_bank_by_name = (AkPrepareBankByNameFn)dlsym(
        RTLD_DEFAULT,
        "_ZN2AK11SoundEngine11PrepareBankENS0_15PreparationTypeEPKcNS0_13AkBankContentEj");
    g_audio.ak_prepare_bank_by_id = (AkPrepareBankByIdFn)dlsym(
        RTLD_DEFAULT,
        "_ZN2AK11SoundEngine11PrepareBankENS0_15PreparationTypeEjNS0_13AkBankContentEj");

    log_message("[Audio] Audio manager initialized");
    log_message("[Audio]   Base: %p", main_binary_base);
    log_message("[Audio]   ResourceManager::m_ptr -> %p", (void *)g_audio.resource_manager_ptr);
    log_message("[Audio]   STDString ctor: %p", (void *)g_audio.stdstring_ctor);
    log_message("[Audio]   Wwise bank API: getId=%p load=%p unload=%p prepareName=%p prepareId=%p",
                (void *)g_audio.ak_get_id_from_string,
                (void *)g_audio.ak_load_bank,
                (void *)g_audio.ak_unload_bank,
                (void *)g_audio.ak_prepare_bank_by_name,
                (void *)g_audio.ak_prepare_bank_by_id);

    g_audio.initialized = true;
    return true;
}

static void *get_sound_manager(void);

bool audio_manager_ready(void) {
    if (!g_audio.initialized || !g_audio.resource_manager_ptr) {
        return false;
    }

    return get_sound_manager() != NULL;
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

// The WwiseManager, or NULL unless its vtable is this version's
// ww::WwiseManager vtable (a wrong object here meant jumping to garbage).
static void *get_sound_manager(void) {
    void *rm = get_resource_manager();
    if (!rm) return NULL;

    const VersionOffsets *off = offset_table_get();
    if (!off || !off->wwise_manager_vtable) return NULL;

    void *sm = NULL;
    void *vt = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)rm + RESOURCEMANAGER_SOUNDMANAGER_OFFSET, &sm) ||
        !sm || !safe_memory_read_pointer((mach_vm_address_t)sm, &vt)) {
        return NULL;
    }
    if ((uintptr_t)vt != (uintptr_t)offset_table_resolve(off->wwise_manager_vtable) + 0x10) {
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

typedef bool (*WwisePostEventFn)(void *this_, uint64_t sound_object, const char *event_name,
                                 float seek_position, bool get_play_position, void *callback);
typedef void (*WwiseStopFn)(void *this_, uint64_t sound_object, uint32_t transition_ms);
typedef void (*WwisePauseAllFn)(void *this_);
typedef void (*WwiseResumeAllFn)(void *this_);

/* Each expansion gets its own static flag, so every failure site warns once
 * independently instead of returning false with no trace. */
#define AUDIO_WARN_ONCE(...) \
    do { \
        static bool warned_once_ = false; \
        if (!warned_once_) { \
            log_message(__VA_ARGS__); \
            warned_once_ = true; \
        } \
    } while (0)

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
    return post(sm, sound_object_id, event_name, 0.0f, false, NULL);
}

bool audio_stop(uint64_t sound_object_id) {
    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] Stop refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_STOP);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] Stop refused: VMT entry not found");
        return false;
    }

    WwiseStopFn stop = (WwiseStopFn)func;
    stop(sm, sound_object_id, 0);
    return true;
}

bool audio_pause_all(void) {
    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] PauseAllSounds refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_PAUSE_ALL);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] PauseAllSounds refused: VMT entry not found");
        return false;
    }

    WwisePauseAllFn pause = (WwisePauseAllFn)func;
    pause(sm);
    return true;
}

bool audio_resume_all(void) {
    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] ResumeAllSounds refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_RESUME_ALL);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] ResumeAllSounds refused: VMT entry not found");
        return false;
    }

    WwiseResumeAllFn resume = (WwiseResumeAllFn)func;
    resume(sm);
    return true;
}

// ============================================================================
// State/Switch Control
// ============================================================================

typedef bool (*WwiseSetSwitchFn)(void *this_, const char *switch_group, const char *state,
                                  uint64_t sound_object);
typedef bool (*WwiseSetStateFn)(void *this_, const char *state_group, const char *state);

bool audio_set_switch(uint64_t sound_object_id, const char *switch_group, const char *state) {
    if (!switch_group || !state) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] SetSwitch refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_SET_SWITCH);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] SetSwitch refused: VMT entry not found");
        return false;
    }

    WwiseSetSwitchFn set_switch = (WwiseSetSwitchFn)func;
    return set_switch(sm, switch_group, state, sound_object_id);
}

bool audio_set_state(const char *state_group, const char *state) {
    if (!state_group || !state) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] SetState refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_SET_STATE);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] SetState refused: VMT entry not found");
        return false;
    }

    WwiseSetStateFn set_state = (WwiseSetStateFn)func;
    return set_state(sm, state_group, state);
}

// ============================================================================
// RTPC (Real-Time Parameter Control)
// ============================================================================

typedef bool (*WwiseSetRtpcFn)(void *this_, uint64_t sound_object,
                                const char *name, float value, bool bypass_interpolation);
typedef float (*WwiseGetRtpcFn)(void *this_, uint64_t sound_object, const char *name);
typedef void (*WwiseResetRtpcFn)(void *this_, uint64_t sound_object, const char *name);

bool audio_set_rtpc(uint64_t sound_object_id, const char *name, float value,
                    bool bypass_interpolation) {
    if (!name) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] SetRTPC refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_SET_RTPC);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] SetRTPC refused: VMT entry not found");
        return false;
    }

    WwiseSetRtpcFn set = (WwiseSetRtpcFn)func;
    return set(sm, sound_object_id, name, value, bypass_interpolation);
}

float audio_get_rtpc(uint64_t sound_object_id, const char *name) {
    if (!name) return 0.0f;

    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] GetRTPC returning 0: SoundManager not available");
        return 0.0f;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_GET_RTPC);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] GetRTPC returning 0: VMT entry not found");
        return 0.0f;
    }

    WwiseGetRtpcFn get = (WwiseGetRtpcFn)func;
    return get(sm, sound_object_id, name);
}

bool audio_reset_rtpc(uint64_t sound_object_id, const char *name) {
    if (!name) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] ResetRTPC refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_RESET_RTPC);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] ResetRTPC refused: VMT entry not found");
        return false;
    }

    WwiseResetRtpcFn reset = (WwiseResetRtpcFn)func;
    reset(sm, sound_object_id, name);
    return true;
}

// ============================================================================
// Event/Bank Management
// ============================================================================

typedef bool (*WwiseLoadEventFn)(void *this_, const char *event_name);
typedef bool (*WwiseUnloadEventFn)(void *this_, const char *event_name);

bool audio_load_event(const char *event_name) {
    if (!event_name) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] LoadEvent refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_LOAD_EVENT);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] LoadEvent refused: VMT entry not found");
        return false;
    }

    WwiseLoadEventFn load = (WwiseLoadEventFn)func;
    return load(sm, event_name);
}

bool audio_unload_event(const char *event_name) {
    if (!event_name) return false;

    void *sm = get_sound_manager();
    if (!sm) {
        AUDIO_WARN_ONCE("[Audio] UnloadEvent refused: SoundManager not available");
        return false;
    }

    void *func = read_vmt_entry(sm, WWISE_VMT_UNLOAD_EVENT);
    if (!func) {
        AUDIO_WARN_ONCE("[Audio] UnloadEvent refused: VMT entry not found");
        return false;
    }

    WwiseUnloadEventFn unload = (WwiseUnloadEventFn)func;
    return unload(sm, event_name);
}

// ============================================================================
// Extended Bank/External Sound Management
// ============================================================================

/**
 * PlayExternalSound — play a sound from a file path via a Wwise event.
 *
 * Windows signature:
 *   bool PlayExternalSound(SoundObjectId obj, SoundNameId eventId,
 *                          STDString& path, uint8_t codec,
 *                          float positionSec, bool loop, void* callback)
 *
 * The STDString builder above (ls_stdstring_init) is kept for when this is
 * implemented; see STDSTRING_ABI.md.
 */
bool audio_play_external_sound(uint64_t sound_object_id, const char *event_name,
                                const char *file_path, uint8_t codec,
                                float position_sec) {
    // On 4.1.1.7398727 this is the non-virtual ls::SoundManager::PostEventExternal
    // (object, name, ls::Path const&, codec, uint, float, callback), not a
    // WwiseManager slot; the old slot 28 was StopSound. Refused until its
    // ls::Path argument is worked out.
    (void)sound_object_id; (void)event_name; (void)file_path; (void)codec; (void)position_sec;
    AUDIO_WARN_ONCE("[Audio] PlayExternalSound refused: not implemented for this build");
    return false;
}

static bool bank_api_ready(void) {
    return g_audio.ak_get_id_from_string
        && g_audio.ak_load_bank
        && g_audio.ak_unload_bank
        && g_audio.ak_prepare_bank_by_name
        && g_audio.ak_prepare_bank_by_id;
}

static bool bank_id_valid(uint32_t bank_id) {
    return bank_id != 0 && bank_id != UINT32_MAX;
}

static bool require_bank_api(const char *operation) {
    if (bank_api_ready()) {
        return true;
    }

    /* Warn once per operation (callers pass string literals), so an early
     * LoadBank warning does not silence the first UnloadBank/PrepareBank
     * refusal. */
    static const char *warned_ops[4];
    static int warned_count = 0;
    for (int i = 0; i < warned_count; i++) {
        if (warned_ops[i] == operation) {
            return false;
        }
    }
    if (warned_count < 4) {
        warned_ops[warned_count++] = operation;
    }
    log_message("[Audio] %s deferred: exported Wwise bank entry points are unavailable",
                operation);
    return false;
}

bool audio_load_bank(const char *bank_name) {
    if (!bank_name || !*bank_name || !require_bank_api("LoadBank")) return false;

    uint32_t bank_id = UINT32_MAX;
    int32_t result;

    if (strcmp(bank_name, "Init") == 0) {
        result = g_audio.ak_load_bank(bank_name, &bank_id, 0);
    } else {
        result = g_audio.ak_prepare_bank_by_name(0, bank_name, 1, 0);
        if (result == AK_SUCCESS) {
            bank_id = g_audio.ak_get_id_from_string(bank_name);
        }
    }

    bool success = result == AK_SUCCESS && bank_id_valid(bank_id);
    log_message("[Audio] LoadBank('%s') -> %s (AKRESULT=%d, id=%u)",
                bank_name, success ? "OK" : "FAIL", result, bank_id);
    return success;
}

/**
 * UnloadBank — unload a Wwise sound bank.
 *
 * Windows: UnloadBank(SoundNameId bankId)
 */
bool audio_unload_bank(const char *bank_name) {
    if (!bank_name || !*bank_name || !require_bank_api("UnloadBank")) return false;

    uint32_t bank_id = g_audio.ak_get_id_from_string(bank_name);
    if (!bank_id_valid(bank_id)) {
        log_message("[Audio] UnloadBank: could not resolve bank ID for '%s'", bank_name);
        return false;
    }

    int32_t result = strcmp(bank_name, "Init") == 0
        ? g_audio.ak_unload_bank(bank_id, NULL, 0)
        : g_audio.ak_prepare_bank_by_id(1, bank_id, 1, 0);
    bool success = result == AK_SUCCESS;
    log_message("[Audio] UnloadBank('%s') -> %s (AKRESULT=%d, id=%u)",
                bank_name, success ? "OK" : "FAIL", result, bank_id);
    return success;
}

/**
 * PrepareBank — pre-load bank metadata for streaming.
 * Same signature as LoadBank: callee sets bankId.
 */
bool audio_prepare_bank(const char *bank_name) {
    if (!bank_name || !*bank_name || !require_bank_api("PrepareBank")) return false;

    int32_t result = g_audio.ak_prepare_bank_by_name(0, bank_name, 0, 0);
    uint32_t bank_id = result == AK_SUCCESS
        ? g_audio.ak_get_id_from_string(bank_name)
        : UINT32_MAX;
    bool success = result == AK_SUCCESS && bank_id_valid(bank_id);
    log_message("[Audio] PrepareBank('%s') -> %s (AKRESULT=%d, id=%u)",
                bank_name, success ? "OK" : "FAIL", result, bank_id);
    return success;
}

/**
 * UnprepareBank — release prepared bank metadata.
 * Windows BG3SE's Lua wrapper resolves the name and calls UnloadBank rather
 * than SoundManager::UnprepareBank. Preserve that observable behavior here.
 */
bool audio_unprepare_bank(const char *bank_name) {
    return audio_unload_bank(bank_name);
}
