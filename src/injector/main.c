/**
 * BG3SE-macOS - Baldur's Gate 3 Script Extender for macOS
 *
 * Minimal version - just proves injection works
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

// Version info
#define BG3SE_VERSION "0.2.1"
#define BG3SE_NAME "BG3SE-macOS"

// Log file for debugging
#define LOG_FILE "/tmp/bg3se_macos.log"

/**
 * Write to both syslog and our log file
 */
static void log_message(const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Write to syslog
    syslog(LOG_ERR, "[%s] %s", BG3SE_NAME, buffer);

    // Write to log file
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, buffer);
        fclose(f);
    }
}

/**
 * Main constructor - runs when dylib is loaded
 */
__attribute__((constructor))
static void bg3se_init(void) {
    // Clear log file
    FILE *f = fopen(LOG_FILE, "w");
    if (f) {
        fprintf(f, "=== %s v%s ===\n", BG3SE_NAME, BG3SE_VERSION);
        fprintf(f, "Injection timestamp: %ld\n", (long)time(NULL));
        fprintf(f, "Process ID: %d\n", getpid());
        fclose(f);
    }

    log_message("=== %s v%s initialized ===", BG3SE_NAME, BG3SE_VERSION);
    log_message("Running in process: %s (PID: %d)", getprogname(), getpid());
    log_message("Minimal mode - no hooks installed");
    log_message("=== Initialization complete ===");
}

/**
 * Destructor - runs when dylib is unloaded
 */
__attribute__((destructor))
static void bg3se_cleanup(void) {
    log_message("=== %s shutting down ===", BG3SE_NAME);
}
