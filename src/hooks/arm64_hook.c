/**
 * ARM64 Safe Hooking Implementation
 * Issue #44 - ARM64-Safe Inline Hooking
 *
 * Skip-and-redirect hooking strategy:
 * 1. Analyze prologue to find ADRP+LDR patterns
 * 2. Skip past unsafe PC-relative instructions
 * 3. Install hook at safe point
 * 4. Trampoline executes skipped instructions + branches back
 */

#include "arm64_hook.h"
#include "../core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>   // pthread_jit_write_protect_np (Apple Silicon W^X for MAP_JIT)

// =============================================================================
// Module State
// =============================================================================

static ARM64HookHandle g_hooks[ARM64_HOOK_MAX_TRAMPOLINES];
static int g_hook_count = 0;
static bool g_initialized = false;

// =============================================================================
// Memory Management
// =============================================================================

void* arm64_alloc_near(void* near_addr, size_t size) {
    // Round up to page size
    size_t page_size = (size_t)getpagesize();
    size = (size + page_size - 1) & ~(page_size - 1);

    // Try to allocate within ±128MB of target
    // ARM64 B/BL have 26-bit signed offset (±128MB)
    uint64_t target = (uint64_t)near_addr;

    // Try several addresses around the target
    for (int64_t offset = 0; offset < 128 * 1024 * 1024; offset += page_size) {
        // Try above target
        void* addr = (void*)(target + offset);
        void* result = mmap(addr, size,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
                           -1, 0);
        if (result != MAP_FAILED) {
            // Check if it's actually near enough
            int64_t dist = (int64_t)result - (int64_t)target;
            if (dist >= -128*1024*1024 && dist < 128*1024*1024) {
                return result;
            }
            munmap(result, size);
        }

        // Try below target
        if (target > (uint64_t)offset) {
            addr = (void*)(target - offset);
            result = mmap(addr, size,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
                         -1, 0);
            if (result != MAP_FAILED) {
                int64_t dist = (int64_t)result - (int64_t)target;
                if (dist >= -128*1024*1024 && dist < 128*1024*1024) {
                    return result;
                }
                munmap(result, size);
            }
        }
    }

    // Fallback: allocate anywhere and use absolute branch
    void* result = mmap(NULL, size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
                       -1, 0);
    if (result != MAP_FAILED) {
        log_message("[ARM64Hook] Warning: Trampoline %p is far from target %p",
                   result, near_addr);
    }
    return result != MAP_FAILED ? result : NULL;
}

void arm64_free_near(void* addr, size_t size) {
    if (addr) {
        size_t page_size = (size_t)getpagesize();
        size = (size + page_size - 1) & ~(page_size - 1);
        munmap(addr, size);
    }
}

// =============================================================================
// Instruction Encoding
// =============================================================================

uint32_t arm64_encode_branch(void* from, void* to, bool is_call) {
    int64_t offset = (int64_t)to - (int64_t)from;

    // Check range: ±128MB for B/BL
    if (offset < -128*1024*1024 || offset >= 128*1024*1024) {
        log_message("[ARM64Hook] Branch out of range: %p -> %p (offset %lld)",
                   from, to, offset);
        return 0;
    }

    // Offset must be 4-byte aligned
    if (offset & 0x3) {
        log_message("[ARM64Hook] Branch target not aligned: %p", to);
        return 0;
    }

    // Encode as signed 26-bit immediate (divided by 4)
    int32_t imm26 = (int32_t)(offset >> 2) & 0x3FFFFFF;

    if (is_call) {
        // BL: 100101 + imm26
        return 0x94000000 | imm26;
    } else {
        // B: 000101 + imm26
        return 0x14000000 | imm26;
    }
}

/**
 * Encode an absolute jump using LDR + BR sequence.
 * Writes 4 instructions (16 bytes):
 *   LDR X16, #8    ; Load target address from PC+8
 *   BR  X16        ; Branch to target
 *   .quad target   ; 64-bit target address
 */
static void arm64_encode_absolute_branch(uint32_t* out, void* target) {
    // LDR X16, #8 (load from 8 bytes ahead)
    out[0] = 0x58000050;  // LDR X16, [PC+8]
    // BR X16
    out[1] = 0xD61F0200;
    // Target address (as two 32-bit words)
    uint64_t addr = (uint64_t)target;
    out[2] = (uint32_t)(addr & 0xFFFFFFFF);
    out[3] = (uint32_t)(addr >> 32);
}

// =============================================================================
// Memory Writing
// =============================================================================

bool arm64_write_instruction(void* addr, uint32_t insn) {
    // Make memory writable
    vm_address_t page = (vm_address_t)addr & ~(vm_address_t)(getpagesize() - 1);
    vm_size_t size = getpagesize();

    kern_return_t kr = vm_protect(mach_task_self(), page, size, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        log_message("[ARM64Hook] vm_protect failed: %d", kr);
        return false;
    }

    // Write instruction
    *(uint32_t*)addr = insn;

    // Restore execute permission and flush caches
    vm_protect(mach_task_self(), page, size, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);

    // Flush instruction cache
    sys_icache_invalidate(addr, 4);

    return true;
}

bool arm64_write_instructions(void* addr, const uint32_t* insns, int count) {
    if (count <= 0) return true;

    // Make memory writable
    vm_address_t start = (vm_address_t)addr;
    vm_address_t end = start + count * 4;
    vm_address_t page_start = start & ~(vm_address_t)(getpagesize() - 1);
    vm_address_t page_end = (end + getpagesize() - 1) & ~(vm_address_t)(getpagesize() - 1);
    vm_size_t size = page_end - page_start;

    kern_return_t kr = vm_protect(mach_task_self(), page_start, size, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        log_message("[ARM64Hook] vm_protect failed: %d", kr);
        return false;
    }

    // Write instructions
    memcpy(addr, insns, count * 4);

    // Restore execute permission
    vm_protect(mach_task_self(), page_start, size, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);

    // Flush instruction cache
    sys_icache_invalidate(addr, count * 4);

    return true;
}

// =============================================================================
// Hook Implementation
// =============================================================================

void arm64_hook_init(void) {
    if (g_initialized) return;
    memset(g_hooks, 0, sizeof(g_hooks));
    g_hook_count = 0;
    g_initialized = true;
    log_message("[ARM64Hook] Initialized");
}

void arm64_hook_cleanup(void) {
    arm64_unhook_all();
    g_initialized = false;
}

static ARM64HookHandle* alloc_hook_handle(void) {
    if (!g_initialized) arm64_hook_init();

    for (int i = 0; i < ARM64_HOOK_MAX_TRAMPOLINES; i++) {
        if (!g_hooks[i].active) {
            memset(&g_hooks[i], 0, sizeof(g_hooks[i]));
            return &g_hooks[i];
        }
    }
    log_message("[ARM64Hook] No free hook slots");
    return NULL;
}

ARM64HookHandle* arm64_safe_hook(void* target, void* replacement, void** out_original) {
    if (!target || !replacement) {
        log_message("[ARM64Hook] Invalid arguments");
        return NULL;
    }

    // Analyze prologue
    ARM64PrologueAnalysis analysis;
    if (!arm64_analyze_prologue(target, 16, &analysis)) {
        log_message("[ARM64Hook] Prologue analysis failed for %p", target);
        return NULL;
    }

    // Get safe hook offset
    int skip_bytes = analysis.safe_hook_offset;
    if (skip_bytes < 0) {
        log_message("[ARM64Hook] No safe hook point found for %p", target);
        return NULL;
    }

    return arm64_hook_at_offset(target, skip_bytes, replacement, out_original);
}

ARM64HookHandle* arm64_hook_at_offset(void* target, int skip_bytes, void* replacement, void** out_original) {
    if (!target || !replacement || skip_bytes < 0) {
        log_message("[ARM64Hook] Invalid arguments");
        return NULL;
    }

    // Align skip_bytes to instruction boundary
    skip_bytes = (skip_bytes + 3) & ~3;

    ARM64HookHandle* handle = alloc_hook_handle();
    if (!handle) return NULL;

    handle->target_func = target;
    handle->replacement_func = replacement;
    handle->skip_bytes = skip_bytes;
    handle->hook_offset = skip_bytes;

    // Analyze prologue for logging
    arm64_analyze_prologue(target, 16, &handle->prologue);

    log_message("[ARM64Hook] Installing hook at %p + %d -> %p",
               target, skip_bytes, replacement);

    // Calculate hook point
    void* hook_point = (char*)target + skip_bytes;

    // We need at least 4 bytes for a branch (ideally 16 for absolute)
    // Determine how many instructions we're overwriting
    int patch_size = 4;  // Start with relative branch

    // Try to encode relative branch to replacement
    uint32_t branch_insn = arm64_encode_branch(hook_point, replacement, false);
    if (branch_insn == 0) {
        // Need absolute branch (16 bytes)
        patch_size = 16;
        log_message("[ARM64Hook] Using absolute branch (16 bytes)");
    }

    int insn_count = patch_size / 4;

    // Save original instructions
    handle->saved_insns = malloc(insn_count * sizeof(uint32_t));
    if (!handle->saved_insns) {
        log_message("[ARM64Hook] Failed to allocate saved instructions");
        return NULL;
    }
    memcpy(handle->saved_insns, hook_point, insn_count * 4);
    handle->saved_insn_count = insn_count;

    // Allocate trampoline for calling original
    // Trampoline layout:
    //   [skipped prologue instructions]  - skip_bytes
    //   [overwritten instructions]       - patch_size
    //   [branch back to original]        - 4 or 16 bytes
    int trampoline_size = skip_bytes + patch_size + 16;  // Extra for absolute branch
    handle->trampoline = arm64_alloc_near(target, trampoline_size);
    if (!handle->trampoline) {
        log_message("[ARM64Hook] Failed to allocate trampoline");
        free(handle->saved_insns);
        return NULL;
    }

    // Build trampoline
    uint32_t* tramp = (uint32_t*)handle->trampoline;
    int tramp_idx = 0;

    // The trampoline is a MAP_JIT page. On Apple Silicon, MAP_JIT pages are
    // execute-protected per-thread by default; we must disable JIT write
    // protection before writing and re-enable it (then flush icache) after.
    // Without this, the memcpy below faults with KERN_PROTECTION_FAILURE on
    // recent macOS (e.g. 26.x). No-op on Intel.
    pthread_jit_write_protect_np(0);  // make MAP_JIT writable on this thread

    // Copy skipped prologue (runs first when calling original)
    if (skip_bytes > 0) {
        memcpy(tramp, target, skip_bytes);
        tramp_idx = skip_bytes / 4;
    }

    // Copy overwritten instructions
    memcpy(&tramp[tramp_idx], handle->saved_insns, insn_count * 4);
    tramp_idx += insn_count;

    // Add branch back to original (after hook point + patch)
    void* continue_addr = (char*)hook_point + patch_size;
    uint32_t back_branch = arm64_encode_branch(&tramp[tramp_idx], continue_addr, false);
    if (back_branch != 0) {
        tramp[tramp_idx++] = back_branch;
    } else {
        // Need absolute branch back
        arm64_encode_absolute_branch(&tramp[tramp_idx], continue_addr);
        tramp_idx += 4;
    }

    pthread_jit_write_protect_np(1);  // re-protect (execute) before running

    // Flush trampoline cache
    sys_icache_invalidate(handle->trampoline, tramp_idx * 4);

    // Install hook
    if (patch_size == 4) {
        // Single branch instruction
        if (!arm64_write_instruction(hook_point, branch_insn)) {
            log_message("[ARM64Hook] Failed to write hook");
            arm64_free_near(handle->trampoline, trampoline_size);
            free(handle->saved_insns);
            return NULL;
        }
    } else {
        // Absolute branch (4 instructions)
        uint32_t abs_branch[4];
        arm64_encode_absolute_branch(abs_branch, replacement);
        if (!arm64_write_instructions(hook_point, abs_branch, 4)) {
            log_message("[ARM64Hook] Failed to write absolute hook");
            arm64_free_near(handle->trampoline, trampoline_size);
            free(handle->saved_insns);
            return NULL;
        }
    }

    handle->active = true;
    g_hook_count++;

    // Return trampoline as "original" function pointer
    // Note: Caller should use this starting from offset 0
    // which includes the skipped prologue
    if (out_original) {
        *out_original = handle->trampoline;
    }

    log_message("[ARM64Hook] Hook installed successfully");
    log_message("[ARM64Hook]   Target: %p", target);
    log_message("[ARM64Hook]   Hook point: %p (+%d)", hook_point, skip_bytes);
    log_message("[ARM64Hook]   Trampoline: %p", handle->trampoline);
    log_message("[ARM64Hook]   Replacement: %p", replacement);

    return handle;
}

bool arm64_unhook(ARM64HookHandle* handle) {
    if (!handle || !handle->active) {
        return false;
    }

    void* hook_point = (char*)handle->target_func + handle->hook_offset;

    // Restore original instructions
    if (!arm64_write_instructions(hook_point, handle->saved_insns, handle->saved_insn_count)) {
        log_message("[ARM64Hook] Failed to restore original instructions");
        return false;
    }

    // Free trampoline
    int trampoline_size = handle->skip_bytes + handle->saved_insn_count * 4 + 16;
    arm64_free_near(handle->trampoline, trampoline_size);

    // Free saved instructions
    free(handle->saved_insns);

    handle->active = false;
    g_hook_count--;

    log_message("[ARM64Hook] Hook removed from %p", handle->target_func);
    return true;
}

void arm64_unhook_all(void) {
    for (int i = 0; i < ARM64_HOOK_MAX_TRAMPOLINES; i++) {
        if (g_hooks[i].active) {
            arm64_unhook(&g_hooks[i]);
        }
    }
}

// =============================================================================
// Query Functions
// =============================================================================

bool arm64_has_prologue_adrp(void* func_addr) {
    if (!func_addr) return false;

    uint32_t* insns = (uint32_t*)func_addr;
    for (int i = 0; i < 4; i++) {  // Check first 4 instructions
        if (arm64_is_adrp(insns[i])) {
            return true;
        }
    }
    return false;
}

int arm64_get_recommended_hook_offset(void* func_addr) {
    ARM64PrologueAnalysis analysis;
    if (!arm64_analyze_prologue(func_addr, 16, &analysis)) {
        return -1;
    }
    return analysis.safe_hook_offset;
}

void arm64_analyze_and_log(void* func_addr, const char* func_name) {
    if (!func_addr) return;

    log_message("[ARM64] ========================================");
    log_message("[ARM64] Analyzing: %s @ %p", func_name ? func_name : "unknown", func_addr);

    ARM64PrologueAnalysis analysis;
    if (arm64_analyze_prologue(func_addr, 16, &analysis)) {
        arm64_print_prologue_analysis(&analysis);

        if (analysis.safe_hook_offset >= 0) {
            log_message("[ARM64] RECOMMENDATION: Hook at offset +%d (0x%x)",
                       analysis.safe_hook_offset, analysis.safe_hook_offset);
        } else {
            log_message("[ARM64] WARNING: No safe hook point found!");
        }
    } else {
        log_message("[ARM64] Analysis failed");
    }

    log_message("[ARM64] ========================================");
}
