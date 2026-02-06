/**
 * BG3SE-macOS - Network Protocol Definitions
 *
 * Matches the game's net::Protocol VMT layout on macOS ARM64.
 * Uses the Itanium C++ ABI vtable format (TWO destructor entries).
 *
 * Windows reference: BG3Extender/GameDefinitions/Net.h lines 105-124
 *
 * Issue #6: NetChannel API (Phase 4D)
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Protocol Constants
// ============================================================================

/** Custom message ID for Script Extender messages (matches Windows BG3SE). */
#define NETMSG_SCRIPT_EXTENDER 400

/** Maximum payload length for extender messages. */
#define MAX_EXTENDER_PAYLOAD 0xFFFFF  // ~1MB, matches Windows

/** Server ExtenderProtocol ID (matches Windows). */
#define EXTENDER_PROTOCOL_ID_SERVER 101

/** Client ExtenderProtocol ID (matches Windows). */
#define EXTENDER_PROTOCOL_ID_CLIENT 100

// ============================================================================
// Ghidra-Verified Offsets (Phase 4D)
//
// EocServer → GameServer → NetMessageFactory / ProtocolList
// Verified via statistical binary analysis of 2706 EocServer singleton
// loads in the macOS ARM64 BG3 binary. See ghidra/offsets/NETWORKING.md.
// ============================================================================

/** EocServer → GameServer pointer. Matches Windows (+0xA8). */
#define OFFSET_EOCSERVER_GAMESERVER  0xA8

/** GameServer → NetMessageFactory pointer. Windows ~0x1E8, macOS +16. */
#define OFFSET_GAMESERVER_MSGFACTORY 0x1F8

/**
 * GameServer → ProtocolList (Array<Protocol*>).
 * Windows ~0x2B0, macOS shifted +48 due to pthread_mutex_t growth.
 *
 * Array layout (confirmed via statistical binary analysis, NETWORKING.md):
 *   +0x2E0: data pointer (Protocol**)   — 61 accesses confirmed
 *   +0x2F0: capacity (uint64_t)         — LDR X12 confirmed
 *   +0x300: size/count (uint64_t)       — LDR X10 confirmed
 *
 * 16-byte stride between fields (data→capacity→size) is standard for
 * Larian's Array template which includes padding/alignment.
 */
#define OFFSET_GAMESERVER_PROTOLIST       0x2E0
#define OFFSET_GAMESERVER_PROTOLIST_CAP   0x2F0
#define OFFSET_GAMESERVER_PROTOLIST_SIZE  0x300
#define OFFSET_GAMESERVER_PROTOMAP        0x310

// ============================================================================
// Ghidra Addresses (Phase 4F)
//
// These are virtual addresses from the Ghidra analysis.
// At runtime, apply ASLR: runtime = ghidra - 0x100000000 + binary_base
// ============================================================================

/** NetMessageFactory::GetMessage (GetFreeMessage) — 524 callers confirmed. */
#define ADDR_GETMESSAGE 0x1063d5998ULL

// ============================================================================
// Protocol Version (matches Windows BG3SE ProtoVersion enum)
// ============================================================================

typedef enum {
    PROTO_VERSION_INITIAL       = 1,
    PROTO_VERSION_BIN_SERIALIZER = 2,  // Added binary Lua serializer
    PROTO_VERSION_CURRENT       = 2
} ProtoVersion;

// ============================================================================
// Protocol Result (matches Windows net::ProtocolResult)
// ============================================================================

typedef enum {
    PROTOCOL_RESULT_UNHANDLED          = 0,
    PROTOCOL_RESULT_HANDLED            = 1,
    PROTOCOL_RESULT_ABORT              = 2,
    PROTOCOL_RESULT_ABORT_AND_DISCONNECT = 3
} ProtocolResult;

// ============================================================================
// Forward Declarations
// ============================================================================

typedef struct Protocol Protocol;
typedef struct MessageContext MessageContext;

// ============================================================================
// MessageContext (matches Windows net::MessageContext)
// ============================================================================

struct MessageContext {
    int32_t user_id;
    void *msg;           // net::Message*
    uint32_t unknown1;
    uint8_t  unknown2;
};

// ============================================================================
// Protocol VMT — Itanium C++ ABI Layout (macOS ARM64)
//
// The Itanium ABI places TWO destructor entries in the vtable:
//   [0] complete_destructor  — destroys object, no deallocation
//   [1] deleting_destructor  — destroys object + calls operator delete
//   [2] ProcessMsg
//   [3] PreUpdate
//   [4] PostUpdate
//   [5] OnAddedToHost
//   [6] OnRemovedFromHost
//   [7] Reset
//
// The vptr in the object points to entry [0].
// Entries at negative offsets from vptr: RTTI (-8) and offset-to-top (-16).
//
// To create a compatible vtable in C, we allocate a block with the preamble
// (offset_to_top + RTTI) followed by the function pointers, and set vptr to
// point past the preamble.
// ============================================================================

typedef void          (*Protocol_Destructor)(Protocol *self);
typedef ProtocolResult (*Protocol_ProcessMsg)(Protocol *self, void *unused,
                                              MessageContext *ctx, void *msg);
typedef ProtocolResult (*Protocol_PreUpdate)(Protocol *self, void *game_time);
typedef ProtocolResult (*Protocol_PostUpdate)(Protocol *self, void *game_time);
typedef void          (*Protocol_OnAddedToHost)(Protocol *self);
typedef void          (*Protocol_OnRemovedFromHost)(Protocol *self);
typedef void          (*Protocol_Reset)(Protocol *self);

/**
 * Itanium C++ ABI vtable preamble.
 * Must precede the function pointer table in memory.
 */
typedef struct {
    intptr_t offset_to_top;  // 0 for primary vtable
    void    *typeinfo;       // RTTI pointer (NULL = no RTTI)
} ItaniumVtablePreamble;

/**
 * Protocol virtual function table (Itanium ABI).
 * The game indexes into this table when calling virtual methods.
 */
typedef struct {
    Protocol_Destructor         complete_destructor;   // vtable[0]
    Protocol_Destructor         deleting_destructor;   // vtable[1]
    Protocol_ProcessMsg         process_msg;           // vtable[2]
    Protocol_PreUpdate          pre_update;            // vtable[3]
    Protocol_PostUpdate         post_update;           // vtable[4]
    Protocol_OnAddedToHost      on_added_to_host;      // vtable[5]
    Protocol_OnRemovedFromHost  on_removed_from_host;  // vtable[6]
    Protocol_Reset              reset;                 // vtable[7]
} Protocol_VMT;

/**
 * Complete vtable block: preamble + function table.
 * Allocate one of these and set Protocol.vmt = &block.vmt.
 */
typedef struct {
    ItaniumVtablePreamble preamble;
    Protocol_VMT          vmt;
} ProtocolVtableBlock;

// ============================================================================
// Protocol Base Struct
//
// In the game, Protocol has one data member: AbstractPeer* Peer
// We embed the VMT pointer first for C "inheritance" via casting.
// ============================================================================

struct Protocol {
    const Protocol_VMT *vmt;
    void *peer;              // AbstractPeer* (set when added to protocol list)
};

#endif /* PROTOCOL_H */
