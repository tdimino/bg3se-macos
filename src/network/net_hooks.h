/**
 * BG3SE-macOS - Network Hooks
 *
 * Dobby hooks for game network functions, enabling real multiplayer
 * message transmission via the game's RakNet transport.
 *
 * Phase 4D will fill in the actual Ghidra-verified offsets.
 * Until then, all hook functions are stubs that log and return.
 *
 * Hook targets (from Windows BG3SE + Ghidra RE):
 * 1. NetMessageFactory::Register - Register NETMSG_SCRIPT_EXTENDER (ID 400)
 * 2. AbstractPeer ProtocolList - Insert ExtenderProtocol at index 0
 * 3. Message dispatch - Route incoming ID 400 to message_bus
 * 4. ClientConnectMessage::Serialize - Handshake version negotiation
 *
 * Issue #6: NetChannel API (Phase 4D)
 */

#ifndef NET_HOOKS_H
#define NET_HOOKS_H

#include <stdbool.h>
#include <stdint.h>

// ============================================================================
// Hook Status
// ============================================================================

typedef struct {
    bool message_factory_hooked;   // NetMessageFactory::Register intercepted
    bool protocol_list_hooked;     // ExtenderProtocol inserted in ProtocolList
    bool message_dispatch_hooked;  // Incoming message interception active
    bool handshake_hooked;         // ClientConnect version negotiation active
} NetHookStatus;

// ============================================================================
// Captured Pointers (populated at runtime via hooks)
// ============================================================================

typedef struct {
    void *abstract_peer;           // AbstractPeer* (from EocServer/EocClient)
    void *message_factory;         // NetMessageFactory* (from AbstractPeer)
    void *protocol_list;           // ProtocolList* (from AbstractPeer)
} NetCapturedPtrs;

// ============================================================================
// Public API
// ============================================================================

/**
 * Install all network hooks.
 * Must be called after the game's network subsystem is initialized.
 *
 * Phase 4D: Will use Dobby to hook game functions at Ghidra-verified offsets.
 * Currently a stub that logs and returns false.
 *
 * @return true if all hooks installed successfully
 */
bool net_hooks_install(void);

/**
 * Remove all network hooks and restore original functions.
 * Safe to call even if hooks were never installed.
 */
void net_hooks_remove(void);

/**
 * Get the current hook status.
 *
 * @return Status struct with per-hook booleans
 */
NetHookStatus net_hooks_get_status(void);

/**
 * Get captured network pointers.
 * Pointers are populated at runtime when hooks fire.
 *
 * @return Captured pointer struct (pointers may be NULL if not yet captured)
 */
NetCapturedPtrs net_hooks_get_ptrs(void);

/**
 * Attempt to capture AbstractPeer from the EocServer singleton.
 * Called during game initialization when EocServer becomes available.
 *
 * Phase 4D: Will read AbstractPeer from EocServer at the Ghidra-verified offset.
 *
 * @param eoc_server Pointer to esv::EocServer (captured via existing hook)
 * @return true if AbstractPeer was found
 */
bool net_hooks_capture_peer(void *eoc_server);

/**
 * Register our ExtenderMessage (ID 400) with the game's NetMessageFactory.
 * Must be called after AbstractPeer is captured.
 *
 * Phase 4D: Will call MessageFactory::Register with our message template.
 *
 * @return true if registration succeeded
 */
bool net_hooks_register_message(void);

/**
 * Insert ExtenderProtocol at index 0 of the game's ProtocolList.
 * Must be called after AbstractPeer is captured.
 *
 * Phase 4D: Will manipulate the ProtocolList array in AbstractPeer.
 *
 * @return true if insertion succeeded
 */
bool net_hooks_insert_protocol(void);

#endif /* NET_HOOKS_H */
