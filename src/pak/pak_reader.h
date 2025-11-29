/**
 * BG3SE-macOS - PAK File Reader
 *
 * LSPK v18 format parser for reading Baldur's Gate 3 PAK archives.
 * Supports uncompressed, zlib, and LZ4 compressed entries.
 */

#ifndef BG3SE_PAK_READER_H
#define BG3SE_PAK_READER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

#define LSPK_SIGNATURE 0x4B50534C  // "LSPK"
#define LSPK_ENTRY_SIZE 272

// Compression types
#define PAK_COMPRESSION_NONE 0
#define PAK_COMPRESSION_ZLIB 1
#define PAK_COMPRESSION_LZ4  2

// ============================================================================
// Data Structures
// ============================================================================

/**
 * PAK file entry - represents a single file within the archive
 */
typedef struct {
    char name[256];             // File path within archive
    uint64_t offset;            // Offset in PAK file where data starts
    uint8_t archive_part;       // Archive part index (for split archives)
    uint8_t compression;        // Compression type (0=none, 1=zlib, 2=LZ4)
    uint32_t disk_size;         // Compressed size on disk
    uint32_t uncompressed_size; // Uncompressed data size
} PakEntry;

/**
 * PAK file handle - manages an open PAK archive
 */
typedef struct {
    void *file;                 // FILE* handle (void* for header portability)
    uint32_t version;           // LSPK version
    uint64_t file_list_offset;  // Offset to file list in archive
    uint32_t file_list_size;    // Size of file list
    uint32_t num_files;         // Number of files in archive
    PakEntry *entries;          // Array of file entries
} PakFile;

// ============================================================================
// Core API
// ============================================================================

/**
 * Open a PAK file and read its header and file list.
 * @param path Path to the .pak file
 * @return PakFile handle, or NULL on failure
 */
PakFile *pak_open(const char *path);

/**
 * Close a PAK file and free all associated resources.
 * @param pak PakFile handle to close
 */
void pak_close(PakFile *pak);

/**
 * Find an entry in a PAK file by its path.
 * @param pak PakFile handle
 * @param path File path to search for (case-sensitive)
 * @return Entry index (0-based), or -1 if not found
 */
int pak_find_entry(PakFile *pak, const char *path);

/**
 * Read a file from a PAK archive.
 * Handles decompression automatically based on entry compression type.
 * @param pak PakFile handle
 * @param entry_idx Index of entry to read (from pak_find_entry)
 * @param out_size Pointer to receive uncompressed size (optional, can be NULL)
 * @return Allocated buffer with file contents (null-terminated), or NULL on failure
 *         Caller must free() the returned buffer
 */
char *pak_read_file(PakFile *pak, int entry_idx, size_t *out_size);

/**
 * Check if a PAK file contains a specific file path.
 * @param pak PakFile handle
 * @param path File path to check for
 * @return 1 if file exists, 0 if not found
 */
int pak_contains_file(PakFile *pak, const char *path);

/**
 * Get the number of files in a PAK archive.
 * @param pak PakFile handle
 * @return Number of files
 */
uint32_t pak_get_file_count(PakFile *pak);

/**
 * Get entry info by index.
 * @param pak PakFile handle
 * @param index Entry index
 * @return Pointer to PakEntry, or NULL if index out of range
 */
const PakEntry *pak_get_entry(PakFile *pak, uint32_t index);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_PAK_READER_H
