/**
 * BG3SE-macOS - Safe Memory Reading Implementation
 *
 * Uses mach_vm APIs for safe memory access that won't crash on invalid addresses.
 */

#include "safe_memory.h"
#include "logging.h"
#include <mach/mach_vm.h>
#include <string.h>

/* GPU carveout region boundaries (observed on macOS ARM64) */
#define GPU_REGION_START 0x1000000000ULL
#define GPU_REGION_END   0x7000000000ULL

SafeMemoryInfo safe_memory_check_address(mach_vm_address_t address) {
    SafeMemoryInfo info = {0};

    /* Quick check for obviously invalid addresses */
    if (address == 0 || address < 0x1000) {
        return info;
    }

    mach_port_t task = mach_task_self();
    mach_vm_address_t region_addr = address;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t region_info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = mach_vm_region(
        task,
        &region_addr,
        &region_size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&region_info,
        &info_count,
        &object_name
    );

    if (kr != KERN_SUCCESS) {
        /* Address not in any mapped region */
        LOG_MEMORY_DEBUG("mach_vm_region FAILED for 0x%llx: kr=%d",
                   (unsigned long long)address, kr);
        return info;
    }

    /* Check if the original address falls within the returned region
     * mach_vm_region returns the region at or AFTER the address,
     * so we need to verify the address is actually inside it */
    if (address < region_addr || address >= region_addr + region_size) {
        /* Address is in a gap between regions - log for diagnostics */
        LOG_MEMORY_DEBUG("VALIDATION FAILED: addr=0x%llx not in region 0x%llx-0x%llx (%s)",
                   (unsigned long long)address,
                   (unsigned long long)region_addr,
                   (unsigned long long)(region_addr + region_size),
                   address < region_addr ? "BELOW" : "ABOVE");
        return info;
    }

    info.is_valid = true;
    info.is_readable = (region_info.protection & VM_PROT_READ) != 0;
    info.is_writable = (region_info.protection & VM_PROT_WRITE) != 0;
    info.region_start = region_addr;
    info.region_size = region_size;

    return info;
}

bool safe_memory_read(mach_vm_address_t source, void *dest, size_t size) {
    if (dest == NULL || size == 0) {
        return false;
    }

    /* Pre-check: avoid GPU carveout region even if it appears mapped */
    if (safe_memory_is_gpu_region(source)) {
        return false;
    }

    mach_vm_size_t bytes_read = size;

    kern_return_t kr = mach_vm_read_overwrite(
        mach_task_self(),
        source,
        size,
        (mach_vm_address_t)dest,
        &bytes_read
    );

    return kr == KERN_SUCCESS && bytes_read == size;
}

bool safe_memory_read_pointer(mach_vm_address_t address, void **out_ptr) {
    if (out_ptr == NULL) {
        return false;
    }
    *out_ptr = NULL;
    return safe_memory_read(address, out_ptr, sizeof(void *));
}

bool safe_memory_read_u64(mach_vm_address_t address, uint64_t *out_value) {
    if (out_value == NULL) {
        return false;
    }
    *out_value = 0;
    return safe_memory_read(address, out_value, sizeof(uint64_t));
}

bool safe_memory_read_u32(mach_vm_address_t address, uint32_t *out_value) {
    if (out_value == NULL) {
        return false;
    }
    *out_value = 0;
    return safe_memory_read(address, out_value, sizeof(uint32_t));
}

bool safe_memory_read_i32(mach_vm_address_t address, int32_t *out_value) {
    if (out_value == NULL) {
        return false;
    }
    *out_value = 0;
    return safe_memory_read(address, out_value, sizeof(int32_t));
}

bool safe_memory_read_string(mach_vm_address_t address, char *buffer, size_t max_len) {
    if (buffer == NULL || max_len == 0) {
        return false;
    }

    /* Clear buffer first */
    memset(buffer, 0, max_len);

    /* Skip pre-validation - mach_vm_read_overwrite will fail safely.
     * This avoids issues with mach_vm_region not returning expected regions. */

    /* Read one byte at a time until null terminator or max_len reached
     * This is slower but safer than reading a block and risking
     * crossing into an invalid region */
    for (size_t i = 0; i < max_len - 1; i++) {
        char c;
        if (!safe_memory_read(address + i, &c, 1)) {
            /* Read failed - return what we have so far if any */
            return i > 0;
        }
        buffer[i] = c;
        if (c == '\0') {
            return true;
        }
    }

    /* Reached max_len without null terminator */
    buffer[max_len - 1] = '\0';
    return true;
}

bool safe_memory_is_gpu_region(mach_vm_address_t address) {
    /* Known GPU carveout region on macOS ARM64
     * This region passes mach_vm_region checks but causes SIGBUS
     * Examples seen in crashes: 0x49000004a6, 0x4900000000 */
    return address >= GPU_REGION_START && address < GPU_REGION_END;
}
