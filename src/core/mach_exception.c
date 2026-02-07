/**
 * BG3SE-macOS - Mach Exception Handler
 *
 * Catches EXC_BAD_ACCESS (PAC failures, SIGSEGV, SIGBUS) and
 * EXC_BAD_INSTRUCTION (SIGILL) via Mach exception ports before
 * CrashReporter or POSIX signal handlers fire.
 *
 * Architecture:
 *   1. Allocate exception port, register via task_swap_exception_ports
 *   2. Spawn listener thread running mach_msg() loop
 *   3. MIG-generated mach_exc_server() dispatches to catch_mach_exception_raise()
 *   4. Handler writes breadcrumbs + register state to crash.log
 *   5. Returns KERN_FAILURE → kernel forwards to CrashReporter (.ips still generated)
 *
 * References:
 *   - Mike Ash: Friday Q&A 2013-01-11 (Mach Exception Handlers)
 *   - fdiv.net: Exceptional Behavior (2024, ARM64 example)
 *   - PLCrashReporter: PLCrashMachExceptionServer.m
 */

#include "mach_exception.h"
#include "crashlog.h"
#include "logging.h"

#include <mach/mach.h>
#include <mach/task.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#ifdef __aarch64__
#include <mach/arm/thread_state.h>
#endif

/* MIG-generated stubs */
#include "mach_exc.h"
#include "mach_excServer.h"

/* ========================================================================== */
/* State                                                                      */
/* ========================================================================== */

/* Exception port we own */
static mach_port_t g_exc_port = MACH_PORT_NULL;

/* Listener thread */
static pthread_t g_exc_thread;
static volatile int g_exc_shutdown = 0;

/* Previous exception ports (saved for forwarding) */
#define MAX_OLD_PORTS 16
static mach_msg_type_number_t g_old_count = 0;
static exception_mask_t       g_old_masks[MAX_OLD_PORTS];
static mach_port_t            g_old_ports[MAX_OLD_PORTS];
static exception_behavior_t   g_old_behaviors[MAX_OLD_PORTS];
static thread_state_flavor_t  g_old_flavors[MAX_OLD_PORTS];

/* ========================================================================== */
/* Signal-safe write helpers (same as crashlog.c — minimal, no dependencies)  */
/* ========================================================================== */

static void exc_write_str(int fd, const char *str) {
    if (fd < 0 || !str) return;
    size_t len = 0;
    while (str[len]) len++;
    (void)write(fd, str, len);
}

static int exc_uint64_to_hex(char *buf, int bufsize, uint64_t val) {
    static const char hex[] = "0123456789abcdef";
    if (bufsize < 3) return 0;
    buf[0] = '0'; buf[1] = 'x';
    int pos = 2, started = 0;
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

static void exc_write_hex(int fd, const char *label, uint64_t val) {
    char buf[24];
    exc_write_str(fd, label);
    exc_uint64_to_hex(buf, sizeof(buf), val);
    exc_write_str(fd, buf);
    exc_write_str(fd, "\n");
}

static const char *exc_type_name(exception_type_t type) {
    switch (type) {
        case EXC_BAD_ACCESS:      return "EXC_BAD_ACCESS";
        case EXC_BAD_INSTRUCTION: return "EXC_BAD_INSTRUCTION";
        case EXC_ARITHMETIC:      return "EXC_ARITHMETIC";
        case EXC_BREAKPOINT:      return "EXC_BREAKPOINT";
        case EXC_SOFTWARE:        return "EXC_SOFTWARE";
        default:                  return "EXC_UNKNOWN";
    }
}

/* ========================================================================== */
/* MIG Callbacks (called by mach_exc_server)                                  */
/* ========================================================================== */

/**
 * Main exception handler — EXCEPTION_DEFAULT behavior.
 * Called on the listener thread while the faulting thread is suspended.
 */
kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt)
{
    (void)exception_port;
    (void)task;

    int fd = crashlog_get_crash_fd();
    if (fd < 0) return KERN_FAILURE;

    /* Header */
    exc_write_str(fd, "\n=== BG3SE MACH EXCEPTION REPORT ===\n");
    exc_write_str(fd, "Exception: ");
    exc_write_str(fd, exc_type_name(exception));
    exc_write_str(fd, "\n");

    /* Exception codes */
    if (codeCnt >= 1) exc_write_hex(fd, "Code[0] (kern_return): ", (uint64_t)code[0]);
    if (codeCnt >= 2) exc_write_hex(fd, "Code[1] (fault addr):  ", (uint64_t)code[1]);

#ifdef __aarch64__
    /* ARM64 register state — thread port used for thread_get_state */
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64,
                                         (thread_state_t)&state, &count);
    if (kr == KERN_SUCCESS) {
        exc_write_str(fd, "\n--- ARM64 Thread State ---\n");
        exc_write_hex(fd, "  PC:  ", (uint64_t)__darwin_arm_thread_state64_get_pc(state));
        exc_write_hex(fd, "  LR:  ", (uint64_t)__darwin_arm_thread_state64_get_lr(state));
        exc_write_hex(fd, "  SP:  ", (uint64_t)__darwin_arm_thread_state64_get_sp(state));
        exc_write_hex(fd, "  FP:  ", (uint64_t)__darwin_arm_thread_state64_get_fp(state));
        exc_write_hex(fd, "  X0:  ", state.__x[0]);
        exc_write_hex(fd, "  X1:  ", state.__x[1]);
        exc_write_hex(fd, "  X2:  ", state.__x[2]);
        exc_write_hex(fd, "  X3:  ", state.__x[3]);
        exc_write_hex(fd, "  X8:  ", state.__x[8]);  /* indirect return */
        exc_write_hex(fd, "  X16: ", state.__x[16]); /* scratch / PAC */
        exc_write_hex(fd, "  X17: ", state.__x[17]); /* scratch / PAC */
    } else {
        exc_write_str(fd, "  (failed to get thread state)\n");
    }
#else
    (void)thread;
#endif

    /* Breadcrumbs — faulting thread is suspended, safe to read */
    exc_write_str(fd, "\n--- Breadcrumbs (most recent first) ---\n");
    extern BreadcrumbEntry g_breadcrumbs[BREADCRUMB_RING_SIZE];
    extern uint32_t g_bc_idx;
    uint32_t cur_idx = __atomic_load_n(&g_bc_idx, __ATOMIC_ACQUIRE);
    for (int i = 0; i < BREADCRUMB_RING_SIZE; i++) {
        uint32_t idx = (cur_idx - 1 - i) & (BREADCRUMB_RING_SIZE - 1);
        const char *func = __atomic_load_n(&g_breadcrumbs[idx].func, __ATOMIC_ACQUIRE);
        if (!func) continue;

        char ibuf[8];
        ibuf[0] = ' '; ibuf[1] = ' '; ibuf[2] = '[';
        ibuf[3] = '0' + (i / 10); ibuf[4] = '0' + (i % 10);
        ibuf[5] = ']'; ibuf[6] = ' '; ibuf[7] = '\0';
        exc_write_str(fd, ibuf);
        exc_write_str(fd, func);

        uint32_t extra = g_breadcrumbs[idx].extra;
        if (extra != 0) {
            exc_write_hex(fd, " id=", extra);
        } else {
            exc_write_str(fd, "\n");
        }
    }

    exc_write_str(fd, "\n=== END MACH EXCEPTION REPORT ===\n");

    /* Return KERN_FAILURE: we did NOT handle the exception.
     * The kernel will try the next handler (CrashReporter) and also
     * convert to a POSIX signal, so our sigaction handler gets a
     * second chance too. */
    return KERN_FAILURE;
}

/* Required stubs — we registered with EXCEPTION_DEFAULT so these won't be called,
 * but the linker requires them because mach_exc_server() references all three. */
kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
    (void)exception_port; (void)exception; (void)code; (void)codeCnt;
    (void)flavor; (void)old_state; (void)old_stateCnt;
    (void)new_state; (void)new_stateCnt;
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
    (void)exception_port; (void)thread; (void)task;
    (void)exception; (void)code; (void)codeCnt;
    (void)flavor; (void)old_state; (void)old_stateCnt;
    (void)new_state; (void)new_stateCnt;
    return KERN_FAILURE;
}

/* ========================================================================== */
/* Listener Thread                                                            */
/* ========================================================================== */

static void *exception_listener(void *arg) {
    (void)arg;
    pthread_setname_np("BG3SE-ExcHandler");

    /* Stack-allocate message buffers — no malloc needed */
    union __RequestUnion__catch_mach_exc_subsystem request;
    union __ReplyUnion__catch_mach_exc_subsystem reply;

    while (!g_exc_shutdown) {
        /* Block until an exception message arrives */
        mach_msg_return_t mr = mach_msg(
            &request.Request_mach_exception_raise.Head,
            MACH_RCV_MSG,
            0,
            sizeof(request),
            g_exc_port,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);

        if (mr != MACH_MSG_SUCCESS) {
            /* Port deallocated (shutdown) or other error — exit */
            break;
        }

        /* Dispatch to catch_mach_exception_raise via MIG-generated server */
        mach_exc_server(
            &request.Request_mach_exception_raise.Head,
            &reply.Reply_mach_exception_raise.Head);

        /* Send reply back to the kernel */
        mr = mach_msg(
            &reply.Reply_mach_exception_raise.Head,
            MACH_SEND_MSG,
            reply.Reply_mach_exception_raise.Head.msgh_size,
            0,
            MACH_PORT_NULL,
            0,
            MACH_PORT_NULL);

        if (mr != MACH_MSG_SUCCESS) {
            /* Send failed — not much we can do */
            break;
        }
    }

    return NULL;
}

/* ========================================================================== */
/* Public API                                                                 */
/* ========================================================================== */

void mach_exception_init(void) {
    kern_return_t kr;

    /* Allocate receive port */
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port);
    if (kr != KERN_SUCCESS) {
        LOG_CORE_WARN("mach_exception: port_allocate failed: %d", kr);
        return;
    }

    /* Insert send right so we can reply */
    kr = mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port,
                                 MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        LOG_CORE_WARN("mach_exception: insert_right failed: %d", kr);
        mach_port_deallocate(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        return;
    }

    /* Register for exceptions, atomically saving old ports.
     * EXCEPTION_DEFAULT: we get thread + task ports, fetch state ourselves.
     * MACH_EXCEPTION_CODES: 64-bit exception codes (required on ARM64). */
    exception_mask_t mask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION;
    g_old_count = MAX_OLD_PORTS;

    kr = task_swap_exception_ports(
        mach_task_self(),
        mask,
        g_exc_port,
        EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
        THREAD_STATE_NONE,
        g_old_masks,
        &g_old_count,
        g_old_ports,
        g_old_behaviors,
        g_old_flavors);

    if (kr != KERN_SUCCESS) {
        LOG_CORE_WARN("mach_exception: task_swap_exception_ports failed: %d", kr);
        mach_port_deallocate(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        return;
    }

    /* Spawn listener thread */
    g_exc_shutdown = 0;
    int err = pthread_create(&g_exc_thread, NULL, exception_listener, NULL);
    if (err != 0) {
        LOG_CORE_WARN("mach_exception: pthread_create failed: %d", err);
        /* Restore old ports */
        for (mach_msg_type_number_t i = 0; i < g_old_count; i++) {
            task_set_exception_ports(mach_task_self(), g_old_masks[i],
                                      g_old_ports[i], g_old_behaviors[i],
                                      g_old_flavors[i]);
        }
        mach_port_deallocate(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        return;
    }

    LOG_CORE_INFO("mach_exception: handler installed (EXC_BAD_ACCESS | EXC_BAD_INSTRUCTION), "
                  "saved %u old port(s)", g_old_count);
}

void mach_exception_shutdown(void) {
    if (g_exc_port == MACH_PORT_NULL) return;

    /* Signal shutdown and deallocate port to unblock mach_msg.
     * mach_port_destruct replaces deprecated mach_port_destroy.
     * srdelta=0 means no send-right delta (we just want to destroy the port). */
    g_exc_shutdown = 1;
    mach_port_destruct(mach_task_self(), g_exc_port, 0, 0);
    g_exc_port = MACH_PORT_NULL;

    /* Wait for listener thread */
    pthread_join(g_exc_thread, NULL);

    /* Restore old exception ports */
    for (mach_msg_type_number_t i = 0; i < g_old_count; i++) {
        task_set_exception_ports(mach_task_self(), g_old_masks[i],
                                  g_old_ports[i], g_old_behaviors[i],
                                  g_old_flavors[i]);
    }
    g_old_count = 0;

    LOG_CORE_INFO("mach_exception: handler removed, old ports restored");
}
