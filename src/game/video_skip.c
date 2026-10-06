#include "video_skip.h"
#include "../core/logging.h"
#include "../core/offset_table.h"
#include "../core/safe_memory.h"
#include <dobby.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>

static void *(*orig_BinkLoadVideo)(void *self, const void *path) = NULL;
static bool s_skip_enabled = false;

static const char *s_intro_videos[] = {
    "Splash_Logo_Larian",
    "GUS_CGI01_Part1",
    "GUS_CGI01_Part2",
};
#define NUM_INTRO_VIDEOS 3

static const char *try_read_path_string(const void *path_obj) {
    if (!path_obj) return NULL;

    // ls::Path on macOS ARM64 wraps ls::STDString (libc++ std::string with SSO).
    // Layout: { char *ptr_or_inline; size_t size; size_t capacity_or_flag }
    // SSO: if capacity < 22, string is stored inline starting at byte 0.
    // Long: ptr at offset 0 points to heap buffer.
    //
    // We read the first 24 bytes and check the SSO flag.
    uint8_t buf[24];
    if (!safe_memory_read((mach_vm_address_t)path_obj, buf, sizeof(buf))) {
        return NULL;
    }

    uint64_t first_qword = *(uint64_t *)&buf[0];
    uint64_t size_field   = *(uint64_t *)&buf[8];
    uint64_t cap_field    = *(uint64_t *)&buf[16];

    // Heuristic: if size > 256 or cap > 4096, this isn't a valid string
    if (size_field > 256 || cap_field > 4096) {
        // Might be SSO — try reading inline
        if (size_field < 24) {
            return (const char *)path_obj;
        }
        return NULL;
    }

    // Long string: first_qword is a pointer to the buffer
    if (cap_field >= 23 && first_qword > 0x100000000ULL && first_qword < 0x200000000ULL) {
        return (const char *)(uintptr_t)first_qword;
    }

    // SSO: string is inline starting at path_obj
    return (const char *)path_obj;
}

static bool is_intro_video(const char *str) {
    if (!str) return false;
    for (int i = 0; i < NUM_INTRO_VIDEOS; i++) {
        if (strstr(str, s_intro_videos[i])) return true;
    }
    return false;
}

static void *fake_BinkLoadVideo(void *self, const void *path) {
    if (!s_skip_enabled) {
        return orig_BinkLoadVideo(self, path);
    }

    const char *path_str = try_read_path_string(path);

    if (path_str && is_intro_video(path_str)) {
        LOG_CORE_INFO("[VideoSkip] Suppressing intro video: %.64s", path_str);
        return NULL;
    }

    if (path_str) {
        LOG_CORE_DEBUG("[VideoSkip] Allowing video: %.64s", path_str);
    }

    return orig_BinkLoadVideo(self, path);
}

bool video_skip_init(void *binary_base) {
    const char *env = getenv("BG3SE_SKIP_VIDEOS");
    if (!env || !env[0] || env[0] == '0') {
        LOG_CORE_DEBUG("[VideoSkip] Disabled (BG3SE_SKIP_VIDEOS not set)");
        return true;
    }

    s_skip_enabled = true;

    (void)binary_base;
    // Per-version address from the offset table. A literal here was pinned to
    // 7209685; on 7398727 it lands inside an unrelated UI sort routine.
    void *target = offset_table_game_fn(GAME_FN_BINK_LOAD_VIDEO);
    if (!target) {
        LOG_CORE_WARN("[VideoSkip] BinkManager::LoadVideo not in the offset table "
                      "for this game version — not hooking");
        return false;
    }

    LOG_CORE_INFO("[VideoSkip] Hooking BinkManager::LoadVideo at %p", target);

    int result = DobbyHook(target, (void *)fake_BinkLoadVideo, (void **)&orig_BinkLoadVideo);
    if (result != 0) {
        LOG_CORE_ERROR("[VideoSkip] DobbyHook failed (error: %d)", result);
        return false;
    }

    LOG_CORE_INFO("[VideoSkip] Hook installed — intro videos will be skipped");
    return true;
}
