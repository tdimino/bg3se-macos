/**
 * audio_manager.h - Audio Manager for BG3SE-macOS
 *
 * Provides access to the game's WwiseManager (WWise sound engine)
 * for Ext.Audio API (sound playback, state control, RTPC parameters).
 */

#ifndef AUDIO_MANAGER_H
#define AUDIO_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

// ============================================================================
// Initialization
// ============================================================================

bool audio_manager_init(void *main_binary_base);
bool audio_manager_ready(void);

// ============================================================================
// Sound Object ID Resolution
// ============================================================================

/**
 * Resolve a sound object name to its ID.
 * Special names: "Music", "Listener0"-"Listener3", "Ambient0"-"Ambient3", etc.
 * @return SoundObjectId (0 = invalid)
 */
uint64_t audio_resolve_sound_object(const char *name);

// ============================================================================
// Playback Control
// ============================================================================

bool audio_post_event(uint64_t sound_object_id, const char *event_name);
bool audio_stop(uint64_t sound_object_id);
bool audio_pause_all(void);
bool audio_resume_all(void);

// ============================================================================
// State/Switch Control
// ============================================================================

bool audio_set_switch(uint64_t sound_object_id, const char *switch_group, const char *state);
bool audio_set_state(const char *state_group, const char *state);

// ============================================================================
// RTPC (Real-Time Parameter Control)
// ============================================================================

bool audio_set_rtpc(uint64_t sound_object_id, const char *name, float value);
float audio_get_rtpc(uint64_t sound_object_id, const char *name);
bool audio_reset_rtpc(uint64_t sound_object_id, const char *name);

// ============================================================================
// Event/Bank Management
// ============================================================================

bool audio_load_event(const char *event_name);
bool audio_unload_event(const char *event_name);

/**
 * Play an external sound file via a Wwise event.
 * @param sound_object_id  SoundObjectId (from audio_resolve_sound_object)
 * @param event_name       Wwise event name (used to get event ID)
 * @param file_path        Relative data path (e.g. "Public/MyMod/Assets/sound.wem")
 * @param codec            Audio codec byte (0=PCM, 1=Vorbis, etc.)
 * @param position_sec     Start position in seconds (0.0f = from beginning)
 */
bool audio_play_external_sound(uint64_t sound_object_id, const char *event_name,
                                const char *file_path, uint8_t codec,
                                float position_sec);

/**
 * Load a Wwise sound bank by name.
 */
bool audio_load_bank(const char *bank_name);

/**
 * Unload a Wwise sound bank by name.
 */
bool audio_unload_bank(const char *bank_name);

/**
 * Prepare a Wwise sound bank for streaming (pre-loads metadata).
 */
bool audio_prepare_bank(const char *bank_name);

/**
 * Unprepare a previously prepared Wwise sound bank.
 */
bool audio_unprepare_bank(const char *bank_name);

#endif // AUDIO_MANAGER_H
