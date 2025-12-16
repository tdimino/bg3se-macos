/**
 * BG3SE-macOS - Safe Memory Reading Module
 *
 * Provides safe memory access using mach_vm APIs to prevent SIGBUS crashes
 * when probing potentially invalid memory addresses.
 *
 * Background: macOS ARM64 has GPU carveout regions (0x1000000000-0x7000000000)
 * that pass basic address validation but cause SIGBUS when accessed.
 * Simple range checks are insufficient; we need mach_vm_region validation.
 */

#ifndef BG3SE_SAFE_MEMORY_H
#define BG3SE_SAFE_MEMORY_H

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Information about an address's memory region.
 */
typedef struct {
    bool is_valid;           /* Address is in a mapped region */
    bool is_readable;        /* Region has read permission */
    bool is_writable;        /* Region has write permission */
    mach_vm_address_t region_start;
    mach_vm_size_t region_size;
} SafeMemoryInfo;

/**
 * Check if an address is in a valid, readable memory region.
 *
 * @param address The address to check
 * @return SafeMemoryInfo with validity and region details
 */
SafeMemoryInfo safe_memory_check_address(mach_vm_address_t address);

/**
 * Safely read memory from source to dest.
 * Uses mach_vm_read_overwrite which won't crash on invalid addresses.
 *
 * @param source Source address to read from
 * @param dest Destination buffer to write to
 * @param size Number of bytes to read
 * @return true on success, false on failure
 */
bool safe_memory_read(mach_vm_address_t source, void *dest, size_t size);

/**
 * Safely read a pointer value from an address.
 *
 * @param address Address to read the pointer from
 * @param out_ptr Output: the pointer value read
 * @return true on success, false on failure
 */
bool safe_memory_read_pointer(mach_vm_address_t address, void **out_ptr);

/**
 * Safely read a uint64_t value from an address.
 *
 * @param address Address to read from
 * @param out_value Output: the value read
 * @return true on success, false on failure
 */
bool safe_memory_read_u64(mach_vm_address_t address, uint64_t *out_value);

/**
 * Safely read a uint32_t value from an address.
 *
 * @param address Address to read from
 * @param out_value Output: the value read
 * @return true on success, false on failure
 */
bool safe_memory_read_u32(mach_vm_address_t address, uint32_t *out_value);

/**
 * Safely read an int32_t value from an address.
 *
 * @param address Address to read from
 * @param out_value Output: the value read
 * @return true on success, false on failure
 */
bool safe_memory_read_i32(mach_vm_address_t address, int32_t *out_value);

/**
 * Safely read a uint8_t value from an address.
 *
 * @param address Address to read from
 * @param out_value Output: the value read
 * @return true on success, false on failure
 */
bool safe_memory_read_u8(mach_vm_address_t address, uint8_t *out_value);

/**
 * Safely read a null-terminated string from an address.
 * Reads one byte at a time until null terminator or max_len reached.
 *
 * @param address Address to read the string from
 * @param buffer Output buffer for the string
 * @param max_len Maximum bytes to read (including null terminator)
 * @return true on success, false on failure
 */
bool safe_memory_read_string(mach_vm_address_t address, char *buffer, size_t max_len);

/**
 * Check if an address is likely in GPU/device reserved memory.
 * These regions pass basic validation but cause SIGBUS on access.
 *
 * @param address Address to check
 * @return true if address is in suspected GPU region
 */
bool safe_memory_is_gpu_region(mach_vm_address_t address);

#ifdef __cplusplus
}
#endif

#endif /* BG3SE_SAFE_MEMORY_H */
