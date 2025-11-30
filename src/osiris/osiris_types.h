/**
 * BG3SE-macOS - Osiris Type Definitions
 *
 * Data structures for Osiris scripting engine integration.
 * Based on Windows BG3SE, validated via runtime logging.
 */

#ifndef BG3SE_OSIRIS_TYPES_H
#define BG3SE_OSIRIS_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Value Types
// ============================================================================

typedef enum {
    OSI_TYPE_NONE = 0,
    OSI_TYPE_INTEGER = 1,
    OSI_TYPE_INTEGER64 = 2,
    OSI_TYPE_REAL = 3,
    OSI_TYPE_STRING = 4,
    OSI_TYPE_GUIDSTRING = 5
} OsiValueType;

// ============================================================================
// Function Types
// ============================================================================

typedef enum {
    OSI_FUNC_UNKNOWN = 0,
    OSI_FUNC_EVENT = 1,
    OSI_FUNC_QUERY = 2,
    OSI_FUNC_CALL = 3,
    OSI_FUNC_DATABASE = 4,
    OSI_FUNC_PROC = 5,
    OSI_FUNC_SYSQUERY = 6,   // System-provided queries
    OSI_FUNC_SYSCALL = 7,    // System-provided calls
    OSI_FUNC_USERQUERY = 8   // User-defined queries
} OsiFunctionType;

// Helper to convert function type to string
static inline const char *osi_func_type_str(uint8_t type) {
    switch (type) {
        case OSI_FUNC_EVENT:     return "Event";
        case OSI_FUNC_QUERY:     return "Query";
        case OSI_FUNC_CALL:      return "Call";
        case OSI_FUNC_DATABASE:  return "Database";
        case OSI_FUNC_PROC:      return "Proc";
        case OSI_FUNC_SYSQUERY:  return "SysQuery";
        case OSI_FUNC_SYSCALL:   return "SysCall";
        case OSI_FUNC_USERQUERY: return "UserQuery";
        default:                 return "Unknown";
    }
}

// ============================================================================
// Argument Structures
// ============================================================================

// Argument value - tagged union
typedef struct OsiArgumentValue {
    union {
        int32_t int32Val;
        int64_t int64Val;
        float floatVal;
        char *stringVal;
    };
    uint16_t typeId;
    uint16_t flags;
} OsiArgumentValue;

// Argument linked list node
typedef struct OsiArgumentDesc {
    struct OsiArgumentDesc *nextParam;  // offset 0 (8 bytes on ARM64)
    OsiArgumentValue value;              // offset 8
} OsiArgumentDesc;

// ============================================================================
// Function Definition
// ============================================================================

// Structure returned by pFunctionData()
// Note: Layout determined empirically
typedef struct {
    void *vtable;           // offset 0: C++ vtable pointer
    void *name_ptr;         // offset 8: pointer to std::string or char*
    uint32_t funcId;        // offset 16: function ID
    uint8_t  funcType;      // offset 20: function type
    uint8_t  numInParams;   // offset 21: number of input parameters
    uint8_t  numOutParams;  // offset 22: number of output parameters
    uint8_t  reserved1;     // offset 23: padding
    // More fields follow but we don't need them
} OsiFunctionDef;

// ============================================================================
// Function Cache Entry
// ============================================================================

typedef struct {
    char name[128];
    uint8_t arity;
    uint8_t type;  // OsiFunctionType
    uint32_t id;
} CachedFunction;

// ============================================================================
// Known Event Entry
// ============================================================================

// Known function entry (events, queries, calls)
typedef struct {
    const char *name;
    uint32_t funcId;        // 0 = not yet discovered
    uint8_t expectedArity;
    uint8_t funcType;       // OsiFunctionType
} KnownFunction;

// Legacy alias for compatibility
typedef KnownFunction KnownEvent;

// ============================================================================
// Function Pointer Types
// ============================================================================

typedef void (*OsiEventFn)(void *thisPtr, uint32_t funcId, OsiArgumentDesc *args);
typedef int (*InternalQueryFn)(uint32_t funcId, OsiArgumentDesc *args);
typedef int (*InternalCallFn)(uint32_t funcId, void *params);
typedef void* (*pFunctionDataFn)(void *funcMan, uint32_t funcId);

// ============================================================================
// Constants
// ============================================================================

#define INVALID_FUNCTION_ID 0xFFFFFFFF
#define OSI_FUNCTION_TYPE_MASK 0x80000000  // High bit indicates function type

#ifdef __cplusplus
}
#endif

#endif // BG3SE_OSIRIS_TYPES_H
