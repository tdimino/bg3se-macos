/**
 * BG3SE-macOS - Crash-Resilient Logging Implementation
 *
 * Issue #66: When Osi.AddGold crashes, buffered log never flushes.
 * This module provides crash-safe diagnostics:
 *
 * 1. mmap'd ring buffer: MAP_SHARED file-backed mmap. Kernel flushes dirty
 *    pages on process death — data survives SIGSEGV.
 *
 * 2. SIGSEGV handler: SA_SIGINFO | SA_ONSTACK with sigaltstack.
 *    Writes signal info, fault address, breadcrumbs, and backtrace to a
 *    pre-opened crash file using only write() (async-signal-safe).
 *
 * 3. Breadcrumb trail: Lock-free ring of 32 entries tracking recent function
 *    entries in the dispatch path. Read by signal handler after crash.
 *
 * On macOS, EXC_BAD_ACCESS from pointer authentication (PAC) failures are
 * delivered as Mach exceptions before POSIX signal handlers fire. We handle
 * this via mach_exception.c, which registers a Mach exception port using
 * task_swap_exception_ports(). The Mach handler fires first (writes
 * breadcrumbs + register state), then returns KERN_FAILURE so CrashReporter
 * still generates .ips files. The POSIX signal handler here is a second-chance
 * catch for signals that bypass Mach exceptions.
 *
 * References:
 * - PLCrashReporter (Microsoft): SA_ONSTACK + sigaltstack pattern
 * - POSIX signal-safety(7): async-signal-safe function list
 * - backtrace(3): backtrace_symbols_fd is safe (no malloc)
 */

#include "crashlog.h"
#include "mach_exception.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <execinfo.h>
#include <stdarg.h>
#include <errno.h>

// ============================================================================
// Ring Buffer Configuration
// ============================================================================

// 16KB = one ARM64 page on Apple Silicon
#define RING_BUFFER_SIZE (16 * 1024)
#define RING_ENTRY_MAX   256

// ============================================================================
// Globals
// ============================================================================

// Breadcrumb ring (exported for inline breadcrumb_mark)
BreadcrumbEntry g_breadcrumbs[BREADCRUMB_RING_SIZE];
uint32_t g_bc_idx = 0;

// Ring buffer state
static char *g_ring_buf = NULL;           // mmap'd region
static uint32_t g_ring_cursor = 0;        // atomic write cursor
static int g_ring_fd = -1;                // backing file fd
static char g_ring_path[512] = {0};       // path for diagnostics

// Crash file state (pre-opened for signal handler)
static int g_crash_fd = -1;
static char g_crash_path[512] = {0};

// Signal handler chain
static struct sigaction g_old_sigsegv;
static struct sigaction g_old_sigbus;
static struct sigaction g_old_sigabrt;

// Sigaltstack
static stack_t g_alt_stack;
static void *g_alt_stack_mem = NULL;
#define ALT_STACK_SIZE (64 * 1024)  // 64KB

// Pre-allocated hex buffer for signal handler hexdump (no malloc)
static char g_hex_buf[4096] __attribute__((used));

// ============================================================================
// Internal: Signal-safe integer-to-string
// ============================================================================

// Write a uint64 as hex into buf. Returns number of chars written.
static int uint64_to_hex(char *buf, int bufsize, uint64_t val) {
    static const char hex[] = "0123456789abcdef";
    if (bufsize < 3) return 0;
    buf[0] = '0';
    buf[1] = 'x';
    int pos = 2;

    // Find first non-zero nibble
    int started = 0;
    for (int i = 60; i >= 0 && pos < bufsize - 1; i -= 4) {
        int nibble = (val >> i) & 0xF;
        if (nibble || started || i == 0) {
            buf[pos++] = hex[nibble];
            started = 1;
        }
    }
    buf[pos] = '\0';
    return pos;
}

// Write a decimal int into buf. Returns chars written.
static int int_to_dec(char *buf, int bufsize, int val) {
    if (bufsize < 2) return 0;
    if (val == 0) { buf[0] = '0'; buf[1] = '\0'; return 1; }

    int neg = 0;
    unsigned int uval;
    if (val < 0) { neg = 1; uval = (unsigned int)(-val); } else { uval = (unsigned int)val; }

    char tmp[12];
    int len = 0;
    while (uval > 0 && len < 11) {
        tmp[len++] = '0' + (uval % 10);
        uval /= 10;
    }

    int pos = 0;
    if (neg && pos < bufsize - 1) buf[pos++] = '-';
    for (int i = len - 1; i >= 0 && pos < bufsize - 1; i--) {
        buf[pos++] = tmp[i];
    }
    buf[pos] = '\0';
    return pos;
}

// Signal-safe string write helper
static void crash_write_str(int fd, const char *str) {
    if (fd < 0 || !str) return;
    size_t len = 0;
    while (str[len]) len++;
    (void)write(fd, str, len);
}

// ============================================================================
// Ring Buffer
// ============================================================================

static void ring_buffer_init(void) {
    const char *data_dir = bg3se_get_data_dir();
    if (!data_dir) return;

    snprintf(g_ring_path, sizeof(g_ring_path),
             "%s/crash_ring_%d.bin", data_dir, getpid());

    g_ring_fd = open(g_ring_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (g_ring_fd < 0) {
        LOG_CORE_WARN("crashlog: failed to create ring buffer at %s: %s",
                      g_ring_path, strerror(errno));
        return;
    }

    // Extend file to RING_BUFFER_SIZE
    if (ftruncate(g_ring_fd, RING_BUFFER_SIZE) < 0) {
        LOG_CORE_WARN("crashlog: ftruncate failed: %s", strerror(errno));
        close(g_ring_fd);
        g_ring_fd = -1;
        return;
    }

    g_ring_buf = (char *)mmap(NULL, RING_BUFFER_SIZE,
                               PROT_READ | PROT_WRITE, MAP_SHARED,
                               g_ring_fd, 0);
    if (g_ring_buf == MAP_FAILED) {
        LOG_CORE_WARN("crashlog: mmap failed: %s", strerror(errno));
        g_ring_buf = NULL;
        close(g_ring_fd);
        g_ring_fd = -1;
        return;
    }

    memset(g_ring_buf, 0, RING_BUFFER_SIZE);
    LOG_CORE_INFO("crashlog: ring buffer at %s (%d bytes)", g_ring_path, RING_BUFFER_SIZE);
}

void crashlog_write(const char *msg, size_t len) {
    if (!g_ring_buf || !msg || len == 0) return;

    // Truncate to max entry size (leave room for newline)
    if (len > RING_ENTRY_MAX - 1) len = RING_ENTRY_MAX - 1;

    // NOTE: Cursor advance is atomic but memcpy is not. Two concurrent writers
    // can interleave data if their regions overlap during wrap-around. This is
    // acceptable for crash diagnostics (best-effort logging). Entries may show
    // partial/torn writes under high concurrency, but the ring buffer is read
    // only after a crash when all threads are stopped.

    // Atomic cursor advance
    size_t total = len + 1; // +1 for newline
    uint32_t pos = __atomic_fetch_add(&g_ring_cursor, (uint32_t)total, __ATOMIC_RELAXED);
    pos %= RING_BUFFER_SIZE;

    // Handle wrap-around with two memcpy's if needed
    if (pos + total <= RING_BUFFER_SIZE) {
        memcpy(g_ring_buf + pos, msg, len);
        g_ring_buf[pos + len] = '\n';
    } else {
        // Wraps around: copy what fits, then the rest
        size_t first = RING_BUFFER_SIZE - pos;
        if (first > len) first = len;
        memcpy(g_ring_buf + pos, msg, first);
        size_t remaining = len - first;
        if (remaining > 0) {
            memcpy(g_ring_buf, msg + first, remaining);
        }
        g_ring_buf[(pos + len) % RING_BUFFER_SIZE] = '\n';
    }
}

void crashlog_printf(const char *fmt, ...) {
    char buf[RING_ENTRY_MAX];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        crashlog_write(buf, (size_t)n);
    }
}

// ============================================================================
// Hex Dump (async-signal-safe — uses pre-allocated g_hex_buf)
// ============================================================================

void crashlog_hexdump(int fd, const char *label, const void *data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    if (fd < 0 || !data || len == 0) return;

    if (label) {
        crash_write_str(fd, label);
        crash_write_str(fd, ":\n");
    }

    const uint8_t *p = (const uint8_t *)data;
    // Cap at buffer size minus margin for formatting
    if (len > 256) len = 256;

    for (size_t off = 0; off < len; off += 16) {
        int pos = 0;

        // Offset prefix "  +0xNN: "
        g_hex_buf[pos++] = ' ';
        g_hex_buf[pos++] = ' ';
        g_hex_buf[pos++] = '+';
        g_hex_buf[pos++] = '0';
        g_hex_buf[pos++] = 'x';
        g_hex_buf[pos++] = hex[(off >> 4) & 0xF];
        g_hex_buf[pos++] = hex[off & 0xF];
        g_hex_buf[pos++] = ':';
        g_hex_buf[pos++] = ' ';

        // Hex bytes
        for (int j = 0; j < 16 && off + j < len; j++) {
            g_hex_buf[pos++] = hex[(p[off + j] >> 4) & 0xF];
            g_hex_buf[pos++] = hex[p[off + j] & 0xF];
            g_hex_buf[pos++] = ' ';
        }

        g_hex_buf[pos++] = '\n';
        (void)write(fd, g_hex_buf, pos);
    }
}

// ============================================================================
// Crash File (pre-opened for signal handler)
// ============================================================================

static void crash_file_init(void) {
    const char *data_dir = bg3se_get_data_dir();
    if (!data_dir) return;

    snprintf(g_crash_path, sizeof(g_crash_path), "%s/crash.log", data_dir);

    g_crash_fd = open(g_crash_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (g_crash_fd < 0) {
        LOG_CORE_WARN("crashlog: failed to pre-open crash file at %s", g_crash_path);
    }

    // Force-resolve write() symbol to avoid dyld_stub_binder deadlock in handler
    (void)write(g_crash_fd, "", 0);
}

// ============================================================================
// Signal Handler (async-signal-safe)
// ============================================================================

static void crash_handler(int signo, siginfo_t *info, void *ucontext) {
    int saved_errno = errno;

    if (g_crash_fd < 0) goto chain;

    // Header
    crash_write_str(g_crash_fd, "\n=== BG3SE CRASH REPORT ===\n");
    crash_write_str(g_crash_fd, "Signal: ");
    char sigbuf[16];
    int_to_dec(sigbuf, sizeof(sigbuf), signo);
    crash_write_str(g_crash_fd, sigbuf);

    if (signo == SIGSEGV)     crash_write_str(g_crash_fd, " (SIGSEGV)\n");
    else if (signo == SIGBUS) crash_write_str(g_crash_fd, " (SIGBUS)\n");
    else if (signo == SIGABRT) crash_write_str(g_crash_fd, " (SIGABRT)\n");
    else if (signo == SIGFPE) crash_write_str(g_crash_fd, " (SIGFPE)\n");
    else if (signo == SIGILL) crash_write_str(g_crash_fd, " (SIGILL)\n");
    else crash_write_str(g_crash_fd, "\n");

    // Fault address
    if (info) {
        crash_write_str(g_crash_fd, "Fault addr: ");
        char addrbuf[24];
        uint64_to_hex(addrbuf, sizeof(addrbuf), (uint64_t)(uintptr_t)info->si_addr);
        crash_write_str(g_crash_fd, addrbuf);
        crash_write_str(g_crash_fd, "\n");
    }

    // Breadcrumbs (most recent first)
    crash_write_str(g_crash_fd, "\n--- Breadcrumbs (most recent first) ---\n");
    uint32_t cur_idx = __atomic_load_n(&g_bc_idx, __ATOMIC_ACQUIRE);
    for (int i = 0; i < BREADCRUMB_RING_SIZE; i++) {
        uint32_t idx = (cur_idx - 1 - i) & (BREADCRUMB_RING_SIZE - 1);
        const char *func = __atomic_load_n(&g_breadcrumbs[idx].func, __ATOMIC_ACQUIRE);
        if (!func) continue;

        crash_write_str(g_crash_fd, "  [");
        char ibuf[8];
        int_to_dec(ibuf, sizeof(ibuf), i);
        crash_write_str(g_crash_fd, ibuf);
        crash_write_str(g_crash_fd, "] ");
        crash_write_str(g_crash_fd, func);

        uint32_t extra = g_breadcrumbs[idx].extra;
        if (extra != 0) {
            crash_write_str(g_crash_fd, " id=");
            char extrabuf[24];
            uint64_to_hex(extrabuf, sizeof(extrabuf), extra);
            crash_write_str(g_crash_fd, extrabuf);
        }

        crash_write_str(g_crash_fd, "\n");
    }

    // Backtrace
    // NOTE: backtrace()/backtrace_symbols_fd() are not strictly async-signal-safe
    // on macOS. Apple's libunwind may call malloc() or dladdr() internally.
    // Pre-loading at init (crash_handler_install) mitigates the dyld_stub_binder
    // deadlock but doesn't eliminate all risk. If the crash occurs while holding
    // a malloc lock, this may deadlock. Accepted risk — the breadcrumbs above
    // provide the critical context even if backtrace fails.
    crash_write_str(g_crash_fd, "\n--- Backtrace (best-effort, may deadlock) ---\n");
    void *frames[64];
    int nframes = backtrace(frames, 64);
    if (nframes > 0) {
        backtrace_symbols_fd(frames, nframes, g_crash_fd);
    }

    // Dump last 256 bytes of ring buffer for immediate post-mortem context
    if (g_ring_buf) {
        crashlog_hexdump(g_crash_fd, "\n--- Ring buffer tail (last 256 bytes)",
                         g_ring_buf + (RING_BUFFER_SIZE - 256), 256);
    }

    crash_write_str(g_crash_fd, "\n--- Full ring buffer at: ");
    crash_write_str(g_crash_fd, g_ring_path);
    crash_write_str(g_crash_fd, " ---\n");

    crash_write_str(g_crash_fd, "=== END CRASH REPORT ===\n");

    // NOTE: fsync() removed — kernel flushes on process exit (MAP_SHARED for
    // ring buffer, and close-on-exit for crash fd). Adding fsync() here would
    // add unnecessary latency during crash handling with no benefit.

chain:
    errno = saved_errno;

    // Chain to previous handler or re-raise for default behavior
    struct sigaction *old = NULL;
    if (signo == SIGSEGV) old = &g_old_sigsegv;
    else if (signo == SIGBUS) old = &g_old_sigbus;
    else if (signo == SIGABRT) old = &g_old_sigabrt;

    if (old && (old->sa_flags & SA_SIGINFO) && old->sa_sigaction) {
        old->sa_sigaction(signo, info, ucontext);
    } else if (old && old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN) {
        old->sa_handler(signo);
    } else {
        // Re-raise with default handler for core dump / CrashReporter
        signal(signo, SIG_DFL);
        raise(signo);
    }
}

// ============================================================================
// Signal Handler Installation
// ============================================================================

void crash_handler_install(void) {
    // Set up alternate signal stack (handles stack overflow crashes)
    g_alt_stack_mem = malloc(ALT_STACK_SIZE);
    if (g_alt_stack_mem) {
        g_alt_stack.ss_sp = g_alt_stack_mem;
        g_alt_stack.ss_size = ALT_STACK_SIZE;
        g_alt_stack.ss_flags = 0;
        if (sigaltstack(&g_alt_stack, NULL) != 0) {
            LOG_CORE_WARN("crashlog: sigaltstack failed: %s", strerror(errno));
        }
    }

    // Pre-load backtrace machinery to avoid dyld_stub_binder deadlock
    void *dummy[1];
    (void)backtrace(dummy, 1);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    // Block other crash signals during handler
    sigaddset(&sa.sa_mask, SIGSEGV);
    sigaddset(&sa.sa_mask, SIGBUS);
    sigaddset(&sa.sa_mask, SIGABRT);
    sigaddset(&sa.sa_mask, SIGFPE);
    sigaddset(&sa.sa_mask, SIGILL);

    // Install handlers, saving old ones for chaining
    if (sigaction(SIGSEGV, &sa, &g_old_sigsegv) != 0) {
        LOG_CORE_WARN("crashlog: failed to install SIGSEGV handler");
    }
    if (sigaction(SIGBUS, &sa, &g_old_sigbus) != 0) {
        LOG_CORE_WARN("crashlog: failed to install SIGBUS handler");
    }
    if (sigaction(SIGABRT, &sa, &g_old_sigabrt) != 0) {
        LOG_CORE_WARN("crashlog: failed to install SIGABRT handler");
    }

    LOG_CORE_INFO("crashlog: signal handlers installed (SIGSEGV/SIGBUS/SIGABRT)");
}

// ============================================================================
// Log Callback (bridges logging system → ring buffer)
// ============================================================================

static void crashlog_log_callback(LogLevel level, LogModule module,
                                   const char *message, void *userdata) {
    (void)userdata;
    (void)level;
    (void)module;
    if (message) {
        size_t len = strlen(message);
        crashlog_write(message, len);
    }
}

// ============================================================================
// Public API
// ============================================================================

int crashlog_get_crash_fd(void) {
    return g_crash_fd;
}

void crashlog_init(void) {
    ring_buffer_init();
    crash_file_init();
    crash_handler_install();

    // Register as log callback for WARN+ on crash-relevant modules
    uint32_t module_mask = (1u << LOG_MODULE_OSIRIS) |
                           (1u << LOG_MODULE_HOOKS) |
                           (1u << LOG_MODULE_CORE);
    log_register_callback(crashlog_log_callback, NULL, LOG_LEVEL_WARN, module_mask);

    // Mach exception handler (catches EXC_BAD_ACCESS before POSIX signals)
    mach_exception_init();

    LOG_CORE_INFO("crashlog: initialized (ring=%s, crash=%s)",
                  g_ring_path, g_crash_path);
}

void crashlog_shutdown(void) {
    mach_exception_shutdown();

    if (g_ring_buf) {
        munmap(g_ring_buf, RING_BUFFER_SIZE);
        g_ring_buf = NULL;
    }
    if (g_ring_fd >= 0) {
        close(g_ring_fd);
        g_ring_fd = -1;
    }
    if (g_crash_fd >= 0) {
        close(g_crash_fd);
        g_crash_fd = -1;
    }
    if (g_alt_stack_mem) {
        g_alt_stack.ss_flags = SS_DISABLE;
        sigaltstack(&g_alt_stack, NULL);
        free(g_alt_stack_mem);
        g_alt_stack_mem = NULL;
    }
}
