/**
 * BG3SE-macOS - Logging Module
 *
 * Provides logging to syslog and file.
 */

#ifndef BG3SE_LOGGING_H
#define BG3SE_LOGGING_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Log a message to syslog and the log file.
 * Uses printf-style formatting.
 */
void log_message(const char *format, ...) __attribute__((format(printf, 1, 2)));

/**
 * Clear the log file (call at startup).
 */
void log_init(void);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_LOGGING_H
