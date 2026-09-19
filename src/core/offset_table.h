/**
 * offset_table.h - Per-version memory offset table for BG3SE-macOS
 *
 * All address-dependent features (stats, entity, staticdata, templates, audio,
 * level) derive their runtime pointers from this table. Adding a new BG3 version
 * means adding one row here; no other files need editing for the address changes.
 *
 * Addressing convention:
 *   All fields are stored as offsets from the binary load base (i.e. the Ghidra
 *   address minus 0x100000000). Runtime address = binary_base + field_value.
 *   A field value of 0 means "unknown for this version — skip gracefully".
 */

#ifndef OFFSET_TABLE_H
#define OFFSET_TABLE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable identifiers for callable functions in the BG3 main executable. */
typedef enum GameFunctionId {
    GAME_FN_FIXED_STRING_CREATE = 0,
    GAME_FN_RESOURCE_GET,
    GAME_FN_EXECUTE_STATS_FUNCTOR,
    GAME_FN_EXECUTE_FUNCTORS_ATTACK_TARGET,
    GAME_FN_EXECUTE_FUNCTORS_ATTACK_POSITION,
    GAME_FN_EXECUTE_FUNCTORS_MOVE,
    GAME_FN_EXECUTE_FUNCTORS_TARGET,
    GAME_FN_EXECUTE_FUNCTORS_NEARBY_ATTACKED,
    GAME_FN_EXECUTE_FUNCTORS_NEARBY_ATTACKING,
    GAME_FN_EXECUTE_FUNCTORS_EQUIP,
    GAME_FN_EXECUTE_FUNCTORS_SOURCE,
    GAME_FN_EXECUTE_FUNCTORS_INTERRUPT,
    GAME_FN_PROCESS_DEAL_DAMAGE_FUNCTORS,
    GAME_FN_TRANSLATED_STRING_TRY_GET,
    GAME_FN_TRANSLATED_STRING_GET,
    GAME_FN_TRANSLATED_STRING_ADD,
    GAME_FN_MESSAGE_FACTORY_GET_FREE_MESSAGE,
    GAME_FN_STD_STRING_CTOR,
    GAME_FN_BINK_LOAD_VIDEO,
    GAME_FN_VALUELIST_INSERT,
    GAME_FN_COUNT
} GameFunctionId;

typedef struct {
    const char *version;                 // e.g. "4.1.1.6995620"

    /* ------------------------------------------------------------------ */
    /* Data-segment singleton pointer globals                              */
    /* Offset from binary base; dereference once to get the object ptr.   */
    /* ------------------------------------------------------------------ */

    uintptr_t eocserver_ptr;            // esv::EocServer::m_ptr
    uintptr_t eocclient_ptr;            // ecl::EocClient::m_ptr
    uintptr_t spell_proto_mgr_ptr;      // SpellPrototypeManager::m_ptr
    uintptr_t rpgstats_ptr;             // RPGStats::m_ptr
    uintptr_t resource_mgr_ptr;         // ResourceManager::m_ptr
    uintptr_t level_mgr_ptr;            // LevelManager::m_ptr
    uintptr_t global_template_mgr_ptr;  // ls::GlobalTemplateManager::m_ptr
    uintptr_t cache_template_mgr_ptr;   // CacheTemplateManager::m_ptr
    uintptr_t level_cache_mgr_ptr;      // Level::s_CacheTemplateManager
    uintptr_t staticdata_mstate_ptr;    // ImmutableDataHeadmaster::m_State
    uintptr_t gst_ptr;                  // ls::gGlobalStringTable (FixedString pool)
    uintptr_t translated_string_repo_ptr; // ls::TranslatedStringRepository::m_ptr
    uintptr_t global_switches_ptr;      // EoCGlobalSwitches* slot (double pointer).
                                        // NOT covered by component_data_shift: this
                                        // __common slot moved -0x24000 between 6995620
                                        // and 7209685, breaking the uniform-shift rule.
    uintptr_t osiris_interface_ptr;     // osi::OsirisInterface global instance slot.
                                        // No nm symbol — verified per-version by
                                        // disassembling OsirisQuery's ADRP+LDR pair
                                        // (see ghidra/offsets/OSIRIS_DATABASES.md).
                                        // Used by osi_read_param_defs (main.c).
    uintptr_t status_proto_mgr_ptr;     // eoc::StatusPrototypeManager::m_ptr
    uintptr_t passives_ptr;             // eoc::Passives::m_ptr (nm BSS symbol)
    uintptr_t interrupt_proto_mgr_ptr;  // eoc::InterruptPrototypeManager::m_ptr
    uintptr_t boost_proto_mgr_ptr;      // eoc::BoostPrototypeManager::m_ptr
    uintptr_t wwise_manager_vtable;     // vtable for ww::WwiseManager (symbol address;
                                        // objects point 0x10 past it). audio_manager.c
                                        // calls the object at ResourceManager+0x90 only
                                        // when its vtable matches; 0 = audio refused.
    uintptr_t baseapp_instance_ptr;     // BaseApp::s_AppInstance (focus_hack.c
                                        // reads the instance pointer here, then
                                        // writes the +0x142 focus flag — MUST be
                                        // per-version or the write lands wild)

    /* ------------------------------------------------------------------ */
    /* Function offsets                                                    */
    /* Offset from binary base; cast directly to function pointer type.   */
    /* ------------------------------------------------------------------ */

    uintptr_t fn_feat_getfeats;         // FeatManager::GetFeats
    uintptr_t fn_getallfeats;           // GetAllFeats (context capture)
    uintptr_t fn_get_background;        // Get<eoc::BackgroundManager>
    uintptr_t fn_get_origin;            // Get<eoc::OriginManager>
    uintptr_t fn_get_class;             // Get<eoc::ClassDescriptions>
    uintptr_t fn_get_progression;       // Get<eoc::ProgressionManager>
    uintptr_t fn_get_actionresource;    // Get<eoc::ActionResourceTypes>
    uintptr_t fn_get_template_raw;      // GlobalTemplateManager::GetTemplateRaw
    uintptr_t fn_cache_template;        // CacheTemplateManagerBase::CacheTemplate
    uintptr_t fn_aigrid_to_tile_pos;    // eoc::AiGrid::ToTilePos
    uintptr_t fn_aigrid_get_metadata;   // eoc::AiGrid::GetMetaData
    uintptr_t fn_aigrid_remove_path;    // eoc::AiGrid::RemovePath
    uintptr_t fn_aigrid_find_path;      // eoc::AiGrid::FindPath
    uintptr_t fn_aigrid_find_path_immediate; // eoc::AiGrid::FindPathImmediate

    /* ------------------------------------------------------------------ */
    /* Entity system                                                       */
    /* ------------------------------------------------------------------ */

    uintptr_t fn_try_get_uuid_mapping;  // ecs::legacy::Helper::TryGetSingleton<uuid::ToHandleMappingComponent>
    uintptr_t fn_storage_tryget;        // ecs::EntityStorageContainer::TryGet(EntityHandle)
    uintptr_t fn_spell_proto_init;      // eoc::SpellPrototype::Init(FixedString const&)
    uintptr_t fn_status_proto_init;     // eoc::StatusPrototype::Init(FixedString const&, bool)
    uintptr_t fn_interrupt_proto_get;   // eoc::InterruptPrototypeManager::GetPrototype(FixedString const&) const
                                        // ABI: x1 = FixedString const* (loads through it)
    uintptr_t fn_passives_get;          // eoc::Passives::Get(FixedString const&) const
                                        // ABI: LTO arg-promoted — x1 = FixedString INDEX BY VALUE
                                        // despite the const& in the symbol (instruction-verified,
                                        // ghidra/offsets/COMPONENT_OPS_AND_PROTO_INIT.md)
    intptr_t component_data_shift;      // signed delta added to compiled-in __DATA Ghidra
                                        // addresses (legacy TypeIds and prototype-manager
                                        // singletons) to reach THIS
                                        // version. NOT applied to global_switches_ptr —
                                        // that slot has its own per-version field above.
                                        // Convention: all compiled-in __DATA constants are
                                        // 4.1.1.7209685-vintage (nm-audited), so the
                                        // 7209685 row is 0 and 6995620 is -0x8000.
    bool component_data_shift_valid;    // false when shared TypeIds have multiple deltas;
                                        // consumers must not treat component_data_shift as
                                        // a family-wide migration in that version.

    /* Per-version offsets for GameFunctionId, relative to the image base. */
    uintptr_t game_functions[GAME_FN_COUNT];
} VersionOffsets;

/**
 * Initialize the offset table using the already-detected game version.
 * Must be called after version_detect_init().
 */
void offset_table_init(void);

/**
 * Return offsets for the running game version, or NULL if the version is not
 * in the table (caller should fall back to degraded mode).
 */
const VersionOffsets *offset_table_get(void);

/**
 * Resolve a singleton offset to a runtime address.
 * Returns NULL if binary_base is unknown or the offset is 0.
 *
 * Usage:
 *   void **ptr = (void **)offset_table_resolve(off->rpgstats_ptr);
 *   if (ptr) stats = *ptr;
 */
void *offset_table_resolve(uintptr_t offset);

/**
 * Resolve a function offset to a callable pointer.
 * Returns NULL if binary_base is unknown or the offset is 0.
 *
 * Usage:
 *   typedef void (*FnType)(void);
 *   FnType fn = (FnType)offset_table_fn(off->fn_feat_getfeats);
 */
void *offset_table_fn(uintptr_t offset);

/**
 * Resolve a stable game-function ID to a callable runtime pointer.
 * Returns NULL for an unknown version, invalid ID, missing binary base, or a
 * zero/unverified address in the active version row.
 */
void *offset_table_game_fn(GameFunctionId id);

#ifdef __cplusplus
}
#endif

#endif /* OFFSET_TABLE_H */
