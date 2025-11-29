/**
 * BG3SE-macOS - PAK File Reader Implementation
 *
 * LSPK v18 format parser for Baldur's Gate 3 PAK archives.
 */

#include "pak_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "lz4/lz4.h"

// ============================================================================
// Core API Implementation
// ============================================================================

PakFile *pak_open(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    // Read header (40 bytes)
    uint8_t header[40];
    if (fread(header, 1, 40, f) != 40) {
        fclose(f);
        return NULL;
    }

    // Check signature
    uint32_t signature;
    memcpy(&signature, header, 4);
    if (signature != LSPK_SIGNATURE) {
        fclose(f);
        return NULL;
    }

    // Parse header
    uint32_t version;
    uint64_t file_list_offset;
    uint32_t file_list_size;

    memcpy(&version, header + 4, 4);
    memcpy(&file_list_offset, header + 8, 8);
    memcpy(&file_list_size, header + 16, 4);

    // Seek to file list
    fseek(f, file_list_offset, SEEK_SET);

    // Read file count and compressed size
    uint32_t num_files, compressed_size;
    if (fread(&num_files, 4, 1, f) != 1 || fread(&compressed_size, 4, 1, f) != 1) {
        fclose(f);
        return NULL;
    }

    // Read compressed file list
    uint8_t *compressed_data = (uint8_t *)malloc(compressed_size);
    if (!compressed_data) {
        fclose(f);
        return NULL;
    }

    if (fread(compressed_data, 1, compressed_size, f) != compressed_size) {
        free(compressed_data);
        fclose(f);
        return NULL;
    }

    // Decompress file list (LZ4)
    uint32_t uncompressed_size = num_files * LSPK_ENTRY_SIZE;
    uint8_t *decompressed = (uint8_t *)malloc(uncompressed_size);
    if (!decompressed) {
        free(compressed_data);
        fclose(f);
        return NULL;
    }

    int result = LZ4_decompress_safe((const char *)compressed_data, (char *)decompressed,
                                      compressed_size, uncompressed_size);
    free(compressed_data);

    if (result < 0) {
        free(decompressed);
        fclose(f);
        return NULL;
    }

    // Parse entries
    PakEntry *entries = (PakEntry *)calloc(num_files, sizeof(PakEntry));
    if (!entries) {
        free(decompressed);
        fclose(f);
        return NULL;
    }

    for (uint32_t i = 0; i < num_files; i++) {
        uint8_t *entry_data = decompressed + (i * LSPK_ENTRY_SIZE);

        // Name: 256 bytes, null-terminated
        memcpy(entries[i].name, entry_data, 255);
        entries[i].name[255] = '\0';

        // Offset: 48-bit value (bytes 256-261)
        uint32_t offset_lo;
        uint16_t offset_hi;
        memcpy(&offset_lo, entry_data + 256, 4);
        memcpy(&offset_hi, entry_data + 260, 2);
        entries[i].offset = offset_lo | ((uint64_t)offset_hi << 32);

        entries[i].archive_part = entry_data[262];
        entries[i].compression = entry_data[263] & 0x0F;

        memcpy(&entries[i].disk_size, entry_data + 264, 4);
        memcpy(&entries[i].uncompressed_size, entry_data + 268, 4);
    }

    free(decompressed);

    // Create PakFile struct
    PakFile *pak = (PakFile *)malloc(sizeof(PakFile));
    if (!pak) {
        free(entries);
        fclose(f);
        return NULL;
    }

    pak->file = f;
    pak->version = version;
    pak->file_list_offset = file_list_offset;
    pak->file_list_size = file_list_size;
    pak->num_files = num_files;
    pak->entries = entries;

    return pak;
}

void pak_close(PakFile *pak) {
    if (pak) {
        if (pak->file) fclose((FILE *)pak->file);
        if (pak->entries) free(pak->entries);
        free(pak);
    }
}

int pak_find_entry(PakFile *pak, const char *path) {
    if (!pak || !path) return -1;

    for (uint32_t i = 0; i < pak->num_files; i++) {
        if (strcmp(pak->entries[i].name, path) == 0) {
            return i;
        }
    }
    return -1;
}

char *pak_read_file(PakFile *pak, int entry_idx, size_t *out_size) {
    if (!pak || entry_idx < 0 || entry_idx >= (int)pak->num_files) return NULL;

    PakEntry *entry = &pak->entries[entry_idx];
    FILE *f = (FILE *)pak->file;

    // Seek to file data
    fseek(f, entry->offset, SEEK_SET);

    // Read compressed/raw data
    uint8_t *disk_data = (uint8_t *)malloc(entry->disk_size);
    if (!disk_data) return NULL;

    if (fread(disk_data, 1, entry->disk_size, f) != entry->disk_size) {
        free(disk_data);
        return NULL;
    }

    char *content = NULL;

    if (entry->compression == PAK_COMPRESSION_NONE) {
        // Uncompressed
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            memcpy(content, disk_data, entry->uncompressed_size);
            content[entry->uncompressed_size] = '\0';
            if (out_size) *out_size = entry->uncompressed_size;
        }
    } else if (entry->compression == PAK_COMPRESSION_ZLIB) {
        // zlib
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            uLongf dest_len = entry->uncompressed_size;
            if (uncompress((Bytef *)content, &dest_len, disk_data, entry->disk_size) == Z_OK) {
                content[dest_len] = '\0';
                if (out_size) *out_size = dest_len;
            } else {
                free(content);
                content = NULL;
            }
        }
    } else if (entry->compression == PAK_COMPRESSION_LZ4) {
        // LZ4
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            int result = LZ4_decompress_safe((const char *)disk_data, content,
                                              entry->disk_size, entry->uncompressed_size);
            if (result > 0) {
                content[result] = '\0';
                if (out_size) *out_size = result;
            } else {
                free(content);
                content = NULL;
            }
        }
    }

    free(disk_data);
    return content;
}

int pak_contains_file(PakFile *pak, const char *path) {
    return pak_find_entry(pak, path) >= 0;
}

uint32_t pak_get_file_count(PakFile *pak) {
    return pak ? pak->num_files : 0;
}

const PakEntry *pak_get_entry(PakFile *pak, uint32_t index) {
    if (!pak || index >= pak->num_files) return NULL;
    return &pak->entries[index];
}
