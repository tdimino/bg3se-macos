/**
 * BG3SE-macOS - Logging Implementation
 */

#include "logging.h"
#include "version.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>

void log_init(void) {
    FILE *f = fopen(BG3SE_LOG_FILE, "w");
    if (f) {
        fprintf(f, "=== %s v%s ===\n", BG3SE_NAME, BG3SE_VERSION);
        fprintf(f, "Injection timestamp: %ld\n", (long)time(NULL));
        fclose(f);
    }
}

void log_message(const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Write to syslog
    syslog(LOG_ERR, "[%s] %s", BG3SE_NAME, buffer);

    // Write to log file
    FILE *f = fopen(BG3SE_LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, buffer);
        fclose(f);
    }
}
