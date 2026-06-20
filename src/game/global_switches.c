#include "global_switches.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../core/offset_table.h"
#include <dispatch/dispatch.h>
#include <mach-o/dyld.h>
#include <string.h>

// GlobalSwitches singleton: double pointer at this VA
// Found via RE: VMGameData init loads from ADRP 0x108b18000 + LDR [x20, #0xf30]
#define GLOBAL_SWITCHES_PTR_VA 0x108b18f30

// SkipSplashScreen field offset within EoCGlobalSwitches struct (ARM64 macOS)
// Found via RE: LDRB w8, [x8, #0x6ac] after SkipSplashScreen property registration
#define OFFSET_SKIP_SPLASH_SCREEN 0x6ac

static void *s_global_switches = NULL;
static bool s_initialized = false;

static uintptr_t get_base_address(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "Baldur")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    return 0;
}

bool global_switches_init(void) {
    if (s_initialized && s_global_switches) return true;

    uintptr_t base = get_base_address();
    if (!base) {
        LOG_CORE_ERROR("[GlobalSwitches] BG3 base address not found");
        return false;
    }

    uintptr_t slide = base - 0x100000000;
    // The switches pointer slot is a __DATA global -> apply the per-version data
    // shift. This read is safe (safe_memory_read_pointer), so a wrong address
    // just fails gracefully rather than crashing.
    const VersionOffsets *vo = offset_table_get();
    uintptr_t data_shift = vo ? vo->component_data_shift : 0;
    uintptr_t ptr_addr = GLOBAL_SWITCHES_PTR_VA + slide + data_shift;

    void *ptr_val = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)ptr_addr, &ptr_val)) {
        LOG_CORE_ERROR("[GlobalSwitches] Failed to read ptr at 0x%lx", (unsigned long)ptr_addr);
        return false;
    }

    if (!ptr_val) {
        LOG_CORE_DEBUG("[GlobalSwitches] Singleton not yet allocated (ptr=NULL)");
        return false;
    }

    s_global_switches = ptr_val;
    s_initialized = true;
    LOG_CORE_INFO("[GlobalSwitches] Found singleton at 0x%lx (slide=0x%lx)",
                  (unsigned long)s_global_switches, (unsigned long)slide);
    return true;
}

bool global_switches_set_skip_splash_screen(bool value) {
    if (!s_global_switches && !global_switches_init()) return false;

    uint8_t *field = (uint8_t *)s_global_switches + OFFSET_SKIP_SPLASH_SCREEN;
    *field = value ? 1 : 0;
    LOG_CORE_INFO("[GlobalSwitches] SkipSplashScreen = %s (at 0x%lx + 0x%x)",
                  value ? "true" : "false",
                  (unsigned long)s_global_switches, OFFSET_SKIP_SPLASH_SCREEN);
    return true;
}

bool global_switches_get_skip_splash_screen(void) {
    if (!s_global_switches && !global_switches_init()) return false;

    uint8_t *field = (uint8_t *)s_global_switches + OFFSET_SKIP_SPLASH_SCREEN;
    return *field != 0;
}

static int s_deferred_attempts = 0;
#define MAX_DEFERRED_ATTEMPTS 30

static void deferred_set_skip_splash(void *ctx __attribute__((unused))) {
    s_deferred_attempts++;

    if (global_switches_init()) {
        global_switches_set_skip_splash_screen(true);
        LOG_CORE_INFO("[GlobalSwitches] Deferred SkipSplashScreen set after %d attempts", s_deferred_attempts);
        return;
    }

    if (s_deferred_attempts >= MAX_DEFERRED_ATTEMPTS) {
        LOG_CORE_ERROR("[GlobalSwitches] Gave up after %d attempts — singleton never appeared", s_deferred_attempts);
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(500 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(),
                   ^{ deferred_set_skip_splash(NULL); });
}

void global_switches_deferred_set_skip_splash_screen(void) {
    s_deferred_attempts = 0;

    if (global_switches_init() && global_switches_set_skip_splash_screen(true)) {
        return;
    }

    LOG_CORE_INFO("[GlobalSwitches] Starting deferred SkipSplashScreen polling (500ms intervals, max %d)", MAX_DEFERRED_ATTEMPTS);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(500 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(),
                   ^{ deferred_set_skip_splash(NULL); });
}
