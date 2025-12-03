/**
 * arm64_call.h - ARM64 ABI utilities for calling BG3 functions
 *
 * This module provides wrappers for calling game functions that require
 * special ARM64 ABI handling, particularly functions returning large structs
 * via the x8 register.
 */

#ifndef ARM64_CALL_H
#define ARM64_CALL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================================
// LsResult - Result type for TryGetSingleton and similar functions
// ============================================================================

// TryGetSingleton returns ls::Result<ComponentPtr, ls::Error>
// This is a 64-byte struct on ARM64 that requires indirect return via x8 register.
// Layout (from Ghidra analysis of stores to x19 = saved x8):
//   offset 0x00: void* value (component pointer, or garbage on error)
//   offset 0x08: reserved/zeroed on success
//   offset 0x10-0x2F: additional data
//   offset 0x30: uint8_t error flag (0=success, 1=error)
typedef struct __attribute__((aligned(16))) {
    void* value;               // 0x00: Component pointer
    uint64_t reserved1;        // 0x08: Reserved
    uint64_t reserved2[4];     // 0x10-0x2F: Additional data (32 bytes)
    uint8_t has_error;         // 0x30: Error flag (0=success, 1=error)
    uint8_t _pad[15];          // 0x31-0x3F: Padding to 64 bytes
} LsResult;

// ============================================================================
// ARM64 Function Call Wrappers
// ============================================================================

/**
 * Call a TryGetSingleton function with proper ARM64 ABI.
 *
 * ARM64 calling convention: Functions returning structs >16 bytes
 * pass the return buffer address in the x8 register.
 *
 * @param fn The function pointer to call (expects void (*)(void* entityWorld))
 * @param entityWorld Pointer to EntityWorld
 * @return The component pointer if successful, NULL on error
 */
void* call_try_get_singleton_with_x8(void *fn, void *entityWorld);

/**
 * Check if ARM64 call wrappers are available (vs x86_64 stubs).
 * @return true on ARM64, false on other architectures
 */
bool arm64_call_available(void);

// ============================================================================
// GetRawComponent Call Wrapper
// ============================================================================

/**
 * Call GetRawComponent with proper ARM64 ABI.
 *
 * GetRawComponent signature:
 *   void* GetRawComponent(EntityWorld* world, EntityHandle handle,
 *                         ComponentTypeIndex type, size_t componentSize,
 *                         bool isProxy)
 *
 * @param fn GetRawComponent function pointer
 * @param entityWorld Pointer to EntityWorld
 * @param entityHandle Entity handle (64-bit packed value)
 * @param typeIndex Component type index (uint16_t)
 * @param componentSize Expected component size
 * @param isProxy Whether this is a proxy component access
 * @return Pointer to component data, or NULL
 */
void* call_get_raw_component(void *fn, void *entityWorld, uint64_t entityHandle,
                              uint16_t typeIndex, size_t componentSize, bool isProxy);

// ============================================================================
// GetComponent Template Call Wrapper
// ============================================================================

/**
 * Call a GetComponent<T> template instantiation directly.
 *
 * GetComponent<T> signature:
 *   T* EntityWorld::GetComponent<T>(EntityHandle handle)
 *
 * On macOS, there's no GetRawComponent dispatcher - each GetComponent<T>
 * is template-inlined. This wrapper calls those instantiations directly.
 *
 * @param fn_addr GetComponent<T> function address (with ASLR slide applied)
 * @param entityWorld Pointer to EntityWorld (this pointer)
 * @param entityHandle Entity handle (64-bit packed value)
 * @return Pointer to component data, or NULL
 */
void* call_get_component_template(void *fn_addr, void *entityWorld, uint64_t entityHandle);

/**
 * Call EntityStorageContainer::TryGet to get EntityStorageData.
 *
 * TryGet signature:
 *   EntityStorageData* EntityStorageContainer::TryGet(EntityHandle handle)
 *
 * @param fn_addr TryGet function address (with ASLR slide applied)
 * @param storageContainer EntityStorageContainer pointer (from EntityWorld + 0x2d0)
 * @param entityHandle Entity handle (64-bit packed value)
 * @return Pointer to EntityStorageData, or NULL
 */
void* call_try_get(void *fn_addr, void *storageContainer, uint64_t entityHandle);

#endif // ARM64_CALL_H
