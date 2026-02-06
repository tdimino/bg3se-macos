# Networking System Offsets (macOS ARM64)

## Overview

The networking system in BG3 uses a layered architecture:
- `esv::EocServer` — Top-level server singleton
- `net::GameServer` — Network server (inherits Host → AbstractPeer → AbstractPeerBase)
- `net::AbstractPeer` — Core peer class with ProtocolList, NetMessageFactory, message queues
- `net::Protocol` — Base class for message protocol handlers
- `net::MessageFactory` — Manages message pool creation and registration

## Inheritance Chain

```
net::AbstractPeerBase (VMT at +0x00)
  └─ net::AbstractPeer (VMT2 at +0x08, VMT3 at +0x10, VMT4 at +0x18, ...)
       └─ net::Host (adds GameServerVMT2)
            └─ net::GameServer (adds replication, peer arrays, etc.)
```

## Key Singletons

| Symbol | Address | Description |
|--------|---------|-------------|
| `esv::EocServer::m_ptr` | `0x10898e8b8` | Server singleton pointer |
| `ecl::EocClient::m_ptr` | `0x10898c968` | Client singleton pointer |

## EocServer Structure

**Windows reference** (`BG3Extender/GameDefinitions/GameState.h`):

| Field | Windows Offset | macOS Offset | Notes |
|-------|---------------|--------------|-------|
| `field_0` | 0x00 | 0x00 | char |
| `field_8` | 0x08 | 0x08 | int64 — accessed in ActivatePeer |
| `GameStateMachine` | 0xA0 | TBD | Pointer |
| `GameServer` | **0xA8** | **TBD** | `net::GameServer*` — KEY OFFSET |
| `EntityWorld` | ~0x288 | TBD | `ecs::EntityWorld*` |
| field at +0x270 | — | 0x270 | Accessed from EocServer in ActivatePeer (array ptr) |
| field at +0x27c | — | 0x27C | Accessed from EocServer in ActivatePeer (count/int) |

### Finding EocServer.GameServer offset

**Status: CONFIRMED (Phase 4D)**

The Windows offset is 0xA8. **macOS offset is also 0xA8** — confirmed via statistical binary
analysis of all 2706 EocServer singleton loads. 233 field accesses at +0xA8 reference
GameServer operations (NetMessageFactory reads, ProtocolList traversal, peer hash lookups).

## GameServer (net::GameServer) Structure

GameServer inherits all AbstractPeer fields. Key GameServer-specific fields discovered via disassembly:

| Field | macOS Offset | Type | Evidence |
|-------|-------------|------|----------|
| Peer array ptr | +0x650 | pointer/array | `ADD X19, X24, #0x650` in ActivatePeer; `LDR X8, [X20, #0x650]` in DeactivatePeer |
| Peer array size/count | +0x65c | uint32 | `LDR W10, [X20, #0x65c]` in DeactivatePeer |
| Peer hash shift | +0x690 | uint32 | `LDR W8, [X0, #0x690]` in DeactivatePeer |
| Peer hash multiplier | +0x694 | uint32 | `LDR W8, [X24, #0x694]` in both Activate/Deactivate |
| Peer hash table | +0x698 | pointer | `LDR X8, [X24, #0x698]` in both Activate/Deactivate |
| field_6B4 | +0x6B4 | uint32 | `LDR W8, [X0, #0x6B4]` in ActivatePeer |

### AbstractPeer Fields (at base of GameServer)

**Windows reference** (`BG3Extender/GameDefinitions/Net.h`):

| Field | Windows Offset | Est. macOS Offset | Notes |
|-------|---------------|-------------------|-------|
| VMT (AbstractPeerBase) | 0x00 | 0x00 | |
| VMT2 | 0x08 | 0x08 | |
| VMT3 | 0x10 | 0x10 | |
| VMT4 | 0x18 | 0x18 | |
| RakNetPeer | 0x20 | 0x20 | |
| NetMessageFactory | **~0x1E8** | **0x1F8** | `MessageFactory*` — CONFIRMED (74 accesses, +16 shift from Windows) |
| AddressManager | ~0x1F0 | ~0x200 | |
| NetEventManager | ~0x1F8 | ~0x208 | |
| ProtocolList (data) | **~0x2B0** | **0x2E0** | `Protocol**` data pointer — CONFIRMED (61 accesses) |
| ProtocolList (capacity) | ~0x2B8 | **0x2F0** | `uint64_t` capacity — CONFIRMED via LDR X12 |
| ProtocolList (size) | ~0x2C0 | **0x300** | `uint64_t` count — CONFIRMED via LDR X10 |
| ProtocolMap | ~0x2C8 | **0x310** | `HashMap<uint32_t, Protocol*>` — CONFIRMED via LDR X8 |

**Important:** macOS ARM64 shifts these offsets due to:
- `pthread_mutex_t` (64 bytes) vs Windows `CRITICAL_SECTION` (40 bytes)
- Multiple `QueueCS<Message*>` fields each contain a mutex
- Estimated total shift: ~120+ bytes for 5 QueueCS instances

## String References (Verified)

| String | Address (in slice) | Virtual Address | Usage |
|--------|-------------------|-----------------|-------|
| `"GameServer Peer Activate: %d"` | 0x7cedee2 | 0x107cedee2 | Logging in ActivatePeer |
| `"GameServer Peer Deactivate: %d"` | 0x7cedf0e | 0x107cedf0e | Logging in DeactivatePeer |
| `"eocnet::PeerActivateMessage"` | 0x7b987f0 | 0x107b987f0 | Message type name |
| `"eocnet::NETMSG_PEER_ACTIVATE"` | 0x7b9880c | 0x107b9880c | Message ID name |
| `"net::AbstractPeer::Protocols"` | 0x7b64331 | 0x107b64331 | TypeContext for ProtocolList |
| `"net::NETMSG_HANDSHAKE"` | 0x7b982ab | 0x107b982ab | First network message |
| `"AbstractPeer.cpp"` | 0x7d53f0f | 0x107d53f0f | Source file reference |

## Code References (Verified)

### GameServer::ActivatePeer

| Address | Description |
|---------|-------------|
| `0x104abbb2c` | Function prologue (STP X29, X30, [SP, #400]!) |
| `0x104abbb34` | `MOV X24, X0` — this = GameServer* |
| `0x104abbb98` | Loads EocServer singleton |
| `0x104abc368` | `ADD X19, X24, #0x650` — peer data structure |
| `0x104abc3ec` | ADRP+ADD "GameServer Peer Activate" string |
| `0x104abc408` | `LDR W8, [X24, #0x694]` — peer hash field |

### GameServer::DeactivatePeer

| Address | Description |
|---------|-------------|
| `0x105347910` | Function prologue |
| `0x105347920` | `MOV X20, X0` — this = GameServer* |
| `0x105347924` | `LDR W9, [X0, #0x694]` — same hash field as Activate |
| `0x105347a28` | `LDR X8, [X20, #0x650]` — same peer array |
| `0x105347b10` | ADRP+ADD "GameServer Peer Deactivate" string |

### AbstractPeer::Protocols TypeContext Registration

| Address | Description |
|---------|-------------|
| `0x1010a857c` | Function prologue |
| `0x1010a85b4` | Loads TypeId guard at 0x10898ca98 |
| `0x1010a8648` | ADRP+ADD "net::AbstractPeer::Protocols" string |

### TypeId Guard Variables (Protocols)

| Address | Description |
|---------|-------------|
| `0x10898ca98` | TypeId guard for AbstractPeer::Protocols |
| `0x10898cab0` | Related TypeId guard |
| `0x10898cac0` | Related TypeId guard |
| `0x10898ca80` | Another Protocols-related TypeId |
| `0x10898ca90` | Another Protocols-related TypeId |

## Fat Binary Information

- **BG3 binary:** Universal (fat) Mach-O
- **ARM64 slice offset:** `0xf534000`
- **ARM64 base address:** `0x100000000`
- **TEXT segment size:** `0x8398000`
- **File offset formula:** `file_offset = FAT_OFFSET + (virtual_address - BASE)`

## Protocol Registration Pattern (from Windows reference)

```c
// In Windows BG3SE ServerNetworking.cpp:
void NetworkManager::ExtendNetworking() {
    auto server = GetServer();  // gets GameServer*

    // Insert ExtenderProtocol at index 0 (highest priority)
    protocol_ = new ExtenderProtocol();
    server->ProtocolList.insert_at(0, protocol_);
    server->ProtocolMap.set(ExtenderProtocol::ProtocolId, protocol_);

    // Register custom message type
    auto extenderMsg = new net::ExtenderMessage();
    server->NetMessageFactory->Register(
        (uint32_t)net::ExtenderMessage::MessageId, extenderMsg);
}
```

## MessageFactory Structure (Windows)

```c
struct MessageFactory {
    LegacyArray<MessagePool*> MessagePools;  // +0x00
    CRITICAL_SECTION CriticalSection;        // +0x18

    Message* GetFreeMessage(uint32_t messageId);
    void Grow(uint32_t lastMessageId);
    void Register(uint32_t messageId, Message* tmpl);
};
```

## Protocol Base Class (Windows)

```c
struct Protocol {
    virtual ~Protocol() {}                                              // VMT+0x00
    virtual ProtocolResult ProcessMsg(void*, MessageContext*, Message*); // VMT+0x08
    virtual ProtocolResult PreUpdate(GameTime const& time);             // VMT+0x10
    virtual ProtocolResult PostUpdate(GameTime const& time);            // VMT+0x18
    virtual void OnAddedToHost();                                       // VMT+0x20
    virtual void OnRemovedFromHost();                                   // VMT+0x28
    virtual void Reset();                                               // VMT+0x30

    AbstractPeer* Peer{ nullptr };  // +0x08 (after VMT)
};
```

## Phase 4D Results (Completed)

All critical offsets verified via statistical binary analysis:

| Item | macOS ARM64 Offset | Windows Offset | Shift | Verification |
|------|-------------------|----------------|-------|--------------|
| EocServer→GameServer | **0xA8** | 0xA8 | +0 | 233 accesses, 2706 singleton loads |
| GameServer→NetMessageFactory | **0x1F8** | ~0x1E8 | +16 | 74 accesses, BL to GetMessage confirmed |
| GameServer→ProtocolList.data | **0x2E0** | ~0x2B0 | +48 | 61 accesses, LDR X10 patterns |
| GameServer→ProtocolList.capacity | **0x2F0** | ~0x2B8 | +56 | LDR X12 confirmed |
| GameServer→ProtocolList.size | **0x300** | ~0x2C0 | +64 | LDR X10 confirmed |
| GameServer→ProtocolMap | **0x310** | ~0x2C8 | +72 | LDR X8 confirmed |

### Itanium C++ ABI Vtable Layout (macOS ARM64)

macOS uses the Itanium ABI which has TWO destructor entries (unlike MSVC's one):

```
Memory layout:
  [-16] offset_to_top (0 for primary)
  [-8]  typeinfo ptr (RTTI, or NULL)
  [0]   complete_destructor    ← vptr points here
  [+8]  deleting_destructor
  [+16] ProcessMsg
  [+24] PreUpdate
  [+32] PostUpdate
  [+40] OnAddedToHost
  [+48] OnRemovedFromHost
  [+56] Reset
```

### Message Dispatch

The game's AbstractPeer iterates ProtocolList and calls `Protocol::ProcessMsg` (vtable[2])
on each protocol. No hooking needed — we insert our ExtenderProtocol at index 0 and the
game dispatches to us automatically.

**NetMessageFactory::GetMessage** at `0x1063d5998` (524 callers found in binary).

### Implementation

Phase 4D implementation in `src/network/`:
- `protocol.h` — Itanium ABI vtable structs, offset constants
- `extender_protocol.c` — Static vtable block with preamble, ProcessMsg checks msg_id
- `net_hooks.c` — Captures GameServer, probes ProtocolList layout at runtime
- Wired into `main.c` after EntityWorld discovery

### Next Steps (Phase 4E)

1. **Runtime verification** — Launch game and check logs for net_hooks_capture_peer output
2. **Actual ProtocolList insertion** — Insert ExtenderProtocol at index 0 after verifying array layout
3. **MessageFactory registration** — Register NETMSG_SCRIPT_EXTENDER (ID 400) with factory
4. **ProtocolMap registration** — Set ExtenderProtocol in ProtocolMap for ID-based lookup
5. **Thread safety** — Ensure insertion happens during safe point (between ticks)
