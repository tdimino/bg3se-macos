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

// Guess function type from name prefix (safer default than UNKNOWN)
static inline uint8_t osi_func_guess_type(const char *name) {
    if (!name) return OSI_FUNC_CALL;
    if (name[0] == 'Q' && name[1] == 'R' && name[2] == 'Y' && name[3] == '_')
        return OSI_FUNC_QUERY;
    if (name[0] == 'P' && name[1] == 'R' && name[2] == 'O' && name[3] == 'C' && name[4] == '_')
        return OSI_FUNC_PROC;
    if (name[0] == 'D' && name[1] == 'B' && name[2] == '_')
        return OSI_FUNC_DATABASE;
    // Default to CALL — the UNKNOWN path (try query then call) can SIGSEGV
    return OSI_FUNC_CALL;
}

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
    uint32_t handle;  // Encoded OsirisFunctionHandle (0 = not yet computed)
} CachedFunction;

// ============================================================================
// OsirisFunctionHandle Encoding
// ============================================================================
// Windows BG3SE packs Key[0..3] into a 32-bit handle for DivFunctions dispatch.
// Layout: bits 0-2 = type, bits 3-27 = funcId (type<4) or 3-19 + 20-27 (type>=4),
// bit 31 = Part4.

// Encode Key[0..3] into a 32-bit handle
static inline uint32_t osi_encode_handle(uint32_t type, uint32_t part2,
                                          uint32_t funcId, uint32_t part4) {
    uint32_t h = (type & 7) | ((part4 & 1) << 31);
    if (type < 4)
        h |= (funcId & 0x1FFFFFF) << 3;       // 25-bit funcId
    else
        h |= ((funcId & 0x1FFFF) << 3) | ((part2 & 0xFF) << 20);
    return h;
}

// Decode funcId from packed handle
static inline uint32_t osi_decode_func_id(uint32_t handle) {
    uint8_t type = handle & 7;
    return (type < 4) ? (handle >> 3) & 0x1FFFFFF : (handle >> 3) & 0x1FFFF;
}

// Decode function type from packed handle
static inline uint8_t osi_decode_func_type(uint32_t handle) {
    return handle & 7;
}

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
// DivFunctions - Engine callback table for Osiris Call/Query dispatch
// ============================================================================

// Call/Query function pointer (both use the same signature)
typedef int (*DivCallProc)(uint32_t funcId, OsiArgumentDesc *params);
typedef void (*DivErrorMessageProc)(const char *message);
typedef void (*DivAssertProc)(int successful, const char *message, int unknown2);

// DivFunctions struct - registered by engine via COsiris::RegisterDIVFunctions
// Windows BG3SE captures Call/Query from this struct for Osiris dispatch.
// Layout from Windows BG3SE: BG3Extender/GameDefinitions/Osiris.h:265-276
typedef struct {
    void *unknown0;              // +0x00
    DivCallProc call;            // +0x08: Call dispatch (takes OsiArgumentDesc*)
    DivCallProc query;           // +0x10: Query dispatch (takes OsiArgumentDesc*)
    DivErrorMessageProc error;   // +0x18: Error message callback
    DivAssertProc assert_fn;     // +0x20: Assert callback
} DivFunctions;

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
