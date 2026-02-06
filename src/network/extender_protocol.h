/**
 * BG3SE-macOS - Extender Protocol
 *
 * Custom protocol inserted at index 0 of the game's ProtocolList.
 * Intercepts NETMSG_SCRIPT_EXTENDER (ID 400) messages and routes
 * them to the message bus for Lua event dispatch.
 *
 * Matches Windows BG3SE ExtenderProtocolBase.
 *
 * Issue #6: NetChannel API (Phase 4A)
 */

#ifndef EXTENDER_PROTOCOL_H
#define EXTENDER_PROTOCOL_H

#include "protocol.h"
#include <stdbool.h>

// ============================================================================
// ExtenderProtocol
//
// Embeds Protocol as first member for C "inheritance" via casting.
// The VMT is set up in extender_protocol_create().
// ============================================================================

typedef struct {
    Protocol base;          // Must be first (allows Protocol* <-> ExtenderProtocol*)
    bool     active;        // Whether protocol is installed in ProtocolList
} ExtenderProtocol;

// ============================================================================
// Public API
// ============================================================================

/**
 * Create a new ExtenderProtocol instance.
 * Sets up the VMT with our custom handlers.
 *
 * @return Newly allocated ExtenderProtocol, or NULL on failure
 */
ExtenderProtocol *extender_protocol_create(void);

/**
 * Destroy an ExtenderProtocol instance.
 *
 * @param proto Protocol to destroy (may be NULL)
 */
void extender_protocol_destroy(ExtenderProtocol *proto);

/**
 * Get the singleton ExtenderProtocol instance.
 * Creates it on first call.
 *
 * @return The global ExtenderProtocol
 */
ExtenderProtocol *extender_protocol_get(void);

/**
 * Check if the extender protocol is active (installed in ProtocolList).
 *
 * @return true if active
 */
bool extender_protocol_is_active(void);

#endif /* EXTENDER_PROTOCOL_H */
