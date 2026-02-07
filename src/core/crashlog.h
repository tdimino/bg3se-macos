/**
 * BG3SE-macOS - Crash-Resilient Logging
 *
 * Provides crash-safe diagnostics via:
 * 1. mmap'd ring buffer (survives SIGSEGV — kernel flushes dirty pages)
 * 2. SIGSEGV signal handler with backtrace (SA_ONSTACK + sigaltstack)
 * 3. Breadcrumb trail (lock-free ring for last N function entries)
 *
 * All signal handler code is async-signal-safe: write() only, no stdio/malloc.
 */

#ifndef BG3SE_CRASHLOG_H
#define BG3SE_CRASHLOG_H

#include <stdint.h>
#include <stddef.h>
#include <mach/mach_time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the crash logging system.
 * Creates mmap'd ring buffer, installs signal handler, sets up sigaltstack.
 * Must be called early in bg3se_init(), after log_init().
 */
void crashlog_init(void);

/**
 * Shutdown crash logging. Unmaps ring buffer, restores signal handlers.
 */
void crashlog_shutdown(void);

// ============================================================================
// Ring Buffer (crash-safe log)
// ============================================================================

/**
 * Write a message to the mmap'd ring buffer.
 * Async-signal-safe: uses only atomic ops and memcpy.
 * @param msg Message to write (will be truncated if > 255 bytes)
 * @param len Length of message
 */
void crashlog_write(const char *msg, size_t len);

/**
 * Write a formatted message to the ring buffer.
 * NOT async-signal-safe (uses vsnprintf). Use for pre-crash context only.
 */
void crashlog_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * Hex dump data to the crash file fd.
 * Async-signal-safe: uses pre-allocated buffer, write() only.
 * Use in signal handler to dump register state, ring buffer tail, etc.
 */
void crashlog_hexdump(int fd, const char *label, const void *data, size_t len);

// ============================================================================
// Breadcrumbs (lock-free function trail)
// ============================================================================

#define BREADCRUMB_RING_SIZE 32

typedef struct {
    const char *func;       // __func__ string literal (always valid, read-only data)
    uint32_t extra;         // funcId or other context value
    uint32_t timestamp_low; // low 32 bits of mach_absolute_time()
} BreadcrumbEntry;

/**
 * Record a breadcrumb. Lock-free, ~10-15ns per call.
 */
static inline void breadcrumb_mark(const char *func, uint32_t extra) {
    extern BreadcrumbEntry g_breadcrumbs[BREADCRUMB_RING_SIZE];
    extern uint32_t g_bc_idx;
    uint32_t idx = __atomic_fetch_add(&g_bc_idx, 1, __ATOMIC_RELAXED) & (BREADCRUMB_RING_SIZE - 1);
    g_breadcrumbs[idx].extra = extra;
    g_breadcrumbs[idx].timestamp_low = (uint32_t)mach_absolute_time();
    __atomic_store_n(&g_breadcrumbs[idx].func, func, __ATOMIC_RELEASE);
}

#define BREADCRUMB()        breadcrumb_mark(__func__, 0)
#define BREADCRUMB_ID(id)   breadcrumb_mark(__func__, (id))

// ============================================================================
// Accessors (for Mach exception handler)
// ============================================================================

/**
 * Get the pre-opened crash file descriptor.
 * Returns -1 if not initialized. Used by mach_exception.c to write
 * crash diagnostics from the exception listener thread.
 */
int crashlog_get_crash_fd(void);

// ============================================================================
// Signal Handler
// ============================================================================

/**
 * Install SIGSEGV/SIGBUS/SIGABRT handler with SA_ONSTACK.
 * Called by crashlog_init().
 */
void crash_handler_install(void);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_CRASHLOG_H
