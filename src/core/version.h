/**
 * BG3SE-macOS - Version and Constants
 */

#ifndef BG3SE_VERSION_H
#define BG3SE_VERSION_H

// Version info
#define BG3SE_VERSION "0.36.21"
#define BG3SE_NAME "BG3SE-macOS"

// Data directory (under ~/Library/Application Support/)
#define BG3SE_DATA_DIR_NAME "BG3SE"

// File names (will be placed in data directory)
#define BG3SE_LOG_FILENAME "bg3se.log"
#define BG3SE_CACHE_FILENAME "gst_offsets.cache"

/**
 * Get the BG3SE data directory path.
 * Creates the directory if it doesn't exist.
 * Returns a pointer to a static buffer containing the path.
 * Thread-safe after first call.
 */
const char *bg3se_get_data_dir(void);

/**
 * Get full path to a file in the data directory.
 * Returns a pointer to a static buffer.
 * @param filename The filename (e.g., "bg3se.log")
 */
const char *bg3se_get_data_path(const char *filename);

#endif // BG3SE_VERSION_H
