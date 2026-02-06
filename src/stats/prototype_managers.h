/**
 * prototype_managers.h - Prototype Manager Accessors for BG3SE-macOS
 *
 * Provides access to the game's prototype managers (Spell, Status, Passive, Interrupt)
 * that are required for Ext.Stats.Sync() to make created stats usable by the game.
 *
 * Architecture:
 *   Each prototype type (Spell, Status, Passive, Interrupt, Boost) has a singleton
 *   manager that stores parsed prototypes in a HashMap<FixedString, *Prototype>.
 *   When a stat is created/modified via Ext.Stats, the corresponding prototype
 *   must be synced for the game to recognize and use it.
 *
 * Discovery (Dec 2025):
 *   - PassivePrototypeManager*: 0x108aeccd8 (via ADRP+LDR in GetPassivePrototype)
 *   - BoostPrototypeManager::m_ptr: 0x108991528 (symbol table)
 *   - InterruptPrototypeManager::GetPrototype: 0x101b9686c (function address)
 *   - SpellPrototypeManager: TBD (analyze GetSpellPrototype functions)
 *   - StatusPrototypeManager: TBD (analyze GetStatusPrototype functions)
 */

#ifndef PROTOTYPE_MANAGERS_H
#define PROTOTYPE_MANAGERS_H

#include <stdbool.h>
#include <stdint.h>

// Forward declaration for stats object
typedef void* StatsObjectPtr;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize prototype manager accessors.
 * Must be called after the game binary is loaded and stats system is ready.
 *
 * @param main_binary_base Base address of the main game binary
 * @return true if initialization successful
 */
bool prototype_managers_init(void *main_binary_base);

/**
 * Check if prototype managers are ready.
 *
 * @return true if managers are initialized and accessible
 */
bool prototype_managers_ready(void);

// ============================================================================
// Singleton Accessors
// ============================================================================

/**
 * Get the PassivePrototypeManager singleton.
 *
 * @return Pointer to PassivePrototypeManager, or NULL if not found
 */
void* get_passive_prototype_manager(void);

/**
 * Get the BoostPrototypeManager singleton.
 *
 * @return Pointer to BoostPrototypeManager, or NULL if not found
 */
void* get_boost_prototype_manager(void);

/**
 * Get the InterruptPrototypeManager singleton.
 *
 * @return Pointer to InterruptPrototypeManager, or NULL if not found
 */
void* get_interrupt_prototype_manager(void);

/**
 * Get the SpellPrototypeManager singleton.
 *
 * @return Pointer to SpellPrototypeManager, or NULL if not found
 */
void* get_spell_prototype_manager(void);

/**
 * Get the StatusPrototypeManager singleton.
 *
 * @return Pointer to StatusPrototypeManager, or NULL if not found
 */
void* get_status_prototype_manager(void);

// ============================================================================
// Cached Prototype Lookup (Ext.Stats.GetCachedSpell/Status/Passive/Interrupt)
// ============================================================================

/**
 * Look up a cached spell prototype by name.
 * @return Pointer to SpellPrototype, or NULL if not found
 */
void* prototype_get_cached_spell(const char *name);

/**
 * Look up a cached status prototype by name.
 * @return Pointer to StatusPrototype, or NULL if not found
 */
void* prototype_get_cached_status(const char *name);

/**
 * Look up a cached passive prototype by name.
 * @return Pointer to PassivePrototype, or NULL if not found
 */
void* prototype_get_cached_passive(const char *name);

/**
 * Look up a cached interrupt prototype by name.
 * @return Pointer to InterruptPrototype, or NULL if not found
 */
void* prototype_get_cached_interrupt(const char *name);

// ============================================================================
// Prototype Sync Functions
// ============================================================================

/**
 * Sync a SpellData stat with SpellPrototypeManager.
 * Creates or updates the SpellPrototype for the stat.
 *
 * @param obj Pointer to the stats::Object
 * @param name Stat entry name
 * @return true if sync successful
 */
bool sync_spell_prototype(StatsObjectPtr obj, const char *name);

/**
 * Sync a StatusData stat with StatusPrototypeManager.
 *
 * @param obj Pointer to the stats::Object
 * @param name Stat entry name
 * @return true if sync successful
 */
bool sync_status_prototype(StatsObjectPtr obj, const char *name);

/**
 * Sync a PassiveData stat with PassivePrototypeManager.
 *
 * @param obj Pointer to the stats::Object
 * @param name Stat entry name
 * @return true if sync successful
 */
bool sync_passive_prototype(StatsObjectPtr obj, const char *name);

/**
 * Sync an InterruptData stat with InterruptPrototypeManager.
 *
 * @param obj Pointer to the stats::Object
 * @param name Stat entry name
 * @return true if sync successful
 */
bool sync_interrupt_prototype(StatsObjectPtr obj, const char *name);

// ============================================================================
// Unified Sync Interface
// ============================================================================

/**
 * Sync a stat with its appropriate prototype manager.
 * Automatically determines the correct manager based on stat type.
 *
 * @param obj Pointer to the stats::Object
 * @param name Stat entry name
 * @param type Stat type name ("SpellData", "StatusData", "PassiveData", etc.)
 * @return true if sync successful, false if type doesn't need prototype sync
 */
bool sync_stat_prototype(StatsObjectPtr obj, const char *name, const char *type);

// ============================================================================
// Debug Functions
// ============================================================================

/**
 * Dump prototype manager status to log.
 */
void prototype_managers_dump_status(void);

/**
 * Probe a prototype manager for structure discovery.
 *
 * @param manager_name Name of manager to probe ("Spell", "Status", etc.)
 */
void prototype_managers_probe(const char *manager_name);

#endif // PROTOTYPE_MANAGERS_H
