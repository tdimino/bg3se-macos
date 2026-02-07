/**
 * BG3SE-macOS - Mach Exception Handler
 *
 * Catches EXC_BAD_ACCESS (including PAC failures) and EXC_BAD_INSTRUCTION
 * via Mach exception ports. This fires BEFORE POSIX signal handlers and
 * CrashReporter, ensuring our crash diagnostics (breadcrumbs, ring buffer,
 * register state) are captured even when sigaction handlers are preempted.
 *
 * Pattern: MIG-generated server + dedicated listener thread.
 * Based on PLCrashReporter and Mike Ash's Friday Q&A 2013-01-11.
 */

#ifndef BG3SE_MACH_EXCEPTION_H
#define BG3SE_MACH_EXCEPTION_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the Mach exception handler.
 *
 * Allocates an exception port, registers it for EXC_BAD_ACCESS and
 * EXC_BAD_INSTRUCTION via task_swap_exception_ports (preserving old
 * handlers for forwarding), and spawns a listener thread.
 *
 * Call after crashlog_init() so the crash file fd is available.
 */
void mach_exception_init(void);

/**
 * Shut down the Mach exception handler.
 *
 * Restores previous exception ports, deallocates our port (which
 * unblocks the listener thread), and joins the thread.
 */
void mach_exception_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* BG3SE_MACH_EXCEPTION_H */
