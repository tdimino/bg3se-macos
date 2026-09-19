/**
 * offset_table.c - Per-version memory offset table for BG3SE-macOS
 *
 * To add support for a new BG3 version, DON'T do it by hand — run the resolver:
 *     python3 tools/port_offsets.py resolve --emit
 * and paste its generated VersionOffsets row here.
 * The recipe of every address is tools/offset_manifest.json; see docs/PORTING.md.
 * Validate any change with:  python3 tools/port_offsets.py verify
 *
 * Manual fallback (if a symbol can't be resolved):
 *   - Singleton offsets: `nm` the binary, or runtime probe (Ext.Debug.ReadPtr).
 *   - Function offsets: `nm`/Ghidra. Fields left 0 = "unknown" -> callers skip
 *     that feature gracefully rather than crash.
 *
 * All offsets are (Ghidra address - 0x100000000), i.e. offset from binary load base.
 */

#include "offset_table.h"
#include "version_detect.h"
#include "logging.h"

#include <string.h>

// ============================================================================
// Version Table
// ============================================================================

static const VersionOffsets g_offset_table[] = {

    /* ------------------------------------------------------------------
     * 4.1.1.6995620 — original verified version
     * All offsets discovered via Ghidra analysis (Dec 2025).
     * ------------------------------------------------------------------ */
    {
        .version                 = "4.1.1.6995620",

        /* Singleton pointer globals */
        .eocserver_ptr           = 0x0898e8b8,  // esv::EocServer::m_ptr
        .eocclient_ptr           = 0x0898c968,  // ecl::EocClient::m_ptr
        .spell_proto_mgr_ptr     = 0x089bac80,  // SpellPrototypeManager::m_ptr
        .rpgstats_ptr            = 0x089c5730,  // RPGStats::m_ptr
        .resource_mgr_ptr        = 0x08a8f070,  // ResourceManager::m_ptr
        .level_mgr_ptr           = 0x08a3be40,  // LevelManager::m_ptr
        .global_template_mgr_ptr = 0x08a88508,  // ls::GlobalTemplateManager::m_ptr
        .cache_template_mgr_ptr  = 0x08a309a8,  // CacheTemplateManager::m_ptr
        .level_cache_mgr_ptr     = 0x08a735d8,  // Level::s_CacheTemplateManager
        .staticdata_mstate_ptr   = 0x083c4a68,  // ImmutableDataHeadmaster::m_State
        .gst_ptr                 = 0x08aeccd8,  // ls::gGlobalStringTable
        .translated_string_repo_ptr = 0x08aed088, // TranslatedStringRepository::m_ptr
        .global_switches_ptr     = 0x08b18f30,  // EoCGlobalSwitches* (May 2026 RE: VMGameData init)
        .osiris_interface_ptr    = 0,           // osi::OsirisInterface instance — never verified
                                                // on this vintage (0 = param-defs reader disabled;
                                                // osi_dynamic_call falls back to legacy guessing)
        /* Prototype-manager singletons: 7209685 values minus the validated
         * +0x8000 __DATA shift — exactly what the retired ghidra_to_runtime
         * (component_data_shift = -0x8000) computed on this vintage. */
        .status_proto_mgr_ptr    = 0x089bdb30,
        .passives_ptr            = 0x089b4228,
        .interrupt_proto_mgr_ptr = 0x089b28f0,
        .boost_proto_mgr_ptr     = 0x08991528,
        .baseapp_instance_ptr    = 0,           // focus_hack postdates this vintage;
                                                // never verified — fail closed

        /* Function offsets */
        .fn_feat_getfeats        = 0x01b752b4,  // FeatManager::GetFeats
        .fn_getallfeats          = 0x0120b3e8,  // GetAllFeats
        .fn_get_background       = 0x02994834,  // Get<eoc::BackgroundManager>
        .fn_get_origin           = 0x0341c42c,  // Get<eoc::OriginManager>
        .fn_get_class            = 0x0262f184,  // Get<eoc::ClassDescriptions>
        .fn_get_progression      = 0x03697f0c,  // Get<eoc::ProgressionManager>
        .fn_get_actionresource   = 0x011a4494,  // Get<eoc::ActionResourceTypes>
        .fn_get_template_raw     = 0x05f96304,  // GlobalTemplateManager::GetTemplateRaw
        .fn_cache_template       = 0x05d31ce4,  // CacheTemplateManagerBase::CacheTemplate
        .fn_aigrid_to_tile_pos   = 0,           // not derived for this binary vintage
        .fn_aigrid_get_metadata  = 0,           // not derived for this binary vintage
        .fn_aigrid_remove_path   = 0,           // not derived for this binary vintage
        .fn_aigrid_find_path     = 0,           // not derived for this binary vintage
        .fn_aigrid_find_path_immediate = 0,     // not derived for this binary vintage

        /* Entity system */
        .fn_try_get_uuid_mapping = 0x010dc924,  // TryGetSingleton<uuid::ToHandleMappingComponent>
        .fn_storage_tryget       = 0x0636b27c,  // ecs::EntityStorageContainer::TryGet
        .fn_spell_proto_init     = 0x01f72754,  // eoc::SpellPrototype::Init
        .fn_status_proto_init    = 0,           // not derived for this binary vintage
        .fn_interrupt_proto_get  = 0,           // not derived for this binary vintage
        .fn_passives_get         = 0,           // not derived for this binary vintage
        .component_data_shift    = -0x8000,     // compiled-in __DATA constants are 7209685;
                                                // this version's __DATA sits 0x8000 lower
        .component_data_shift_valid = true,

        .game_functions = {
            [GAME_FN_FIXED_STRING_CREATE] = 0x064b9ebc,
            [GAME_FN_RESOURCE_GET] = 0x060cc608,
            [GAME_FN_EXECUTE_STATS_FUNCTOR] = 0x05783a38,
            [GAME_FN_EXECUTE_FUNCTORS_ATTACK_TARGET] = 0x05787918,
            [GAME_FN_EXECUTE_FUNCTORS_ATTACK_POSITION] = 0x05787c6c,
            [GAME_FN_EXECUTE_FUNCTORS_MOVE] = 0x0578975c,
            [GAME_FN_EXECUTE_FUNCTORS_TARGET] = 0x0578a918,
            [GAME_FN_EXECUTE_FUNCTORS_NEARBY_ATTACKED] = 0x0578e4d8,
            [GAME_FN_EXECUTE_FUNCTORS_NEARBY_ATTACKING] = 0x0578fba8,
            [GAME_FN_EXECUTE_FUNCTORS_EQUIP] = 0x05790a28,
            [GAME_FN_EXECUTE_FUNCTORS_SOURCE] = 0x05792a90,
            [GAME_FN_EXECUTE_FUNCTORS_INTERRUPT] = 0x057965e4,
            [GAME_FN_PROCESS_DEAL_DAMAGE_FUNCTORS] = 0x0538f374,
            [GAME_FN_TRANSLATED_STRING_TRY_GET] = 0x06534d54,
            [GAME_FN_TRANSLATED_STRING_GET] = 0x06535148,
            [GAME_FN_TRANSLATED_STRING_ADD] = 0x06532590,
            [GAME_FN_MESSAGE_FACTORY_GET_FREE_MESSAGE] = 0x063d5998,
            [GAME_FN_STD_STRING_CTOR] = 0x0651fb60,
            [GAME_FN_BINK_LOAD_VIDEO] = 0x0390b6cc,
            [GAME_FN_VALUELIST_INSERT] = 0,
        },
    },

    /* ------------------------------------------------------------------
     * 4.1.1.7209685 — in use as of June 2026
     *
     * The entire __DATA segment shifted by a uniform +0x8000 relative to
     * 6995620. This was established by:
     *   - Export-trie diff: ls::TypeId<eoc::FeatManager,...>::m_TypeIndex
     *     moved 0x1088efd00 -> 0x1088f7d00 (exactly +0x8000).
     *   - otool ADRP/LDR reference-frequency scan: every old singleton
     *     offset + 0x8000 lands on a hot (heavily-referenced) __DATA slot.
     *   - Runtime structural validation against a loaded session:
     *       rpgstats(+0xd4)=16994 objects, fixedstrings pool at +0x348;
     *       ResourceManager banks valid at +0x28/+0x30;
     *       StaticData TypeContext traversal yields 121 named managers
     *       (FeatManager, RaceManager, BackgroundManager, ... ClassDescriptions).
     * So every singleton below is simply (6995620 value + 0x8000).
     *
     * Function offsets live in __TEXT, which did NOT shift uniformly (the
     * three template accessors moved -0x105E8, the feat funcs -0x1BAA0, the
     * Get<T> accessors ~-0x1A7A8), so they were resolved individually by
     * symbol-table lookup (nm) rather than a constant shift. The macOS
     * binary is essentially fully symbolized (765k local+global symbols),
     * so each function below is the address of its named symbol.
     * ------------------------------------------------------------------ */
    {
        .version                 = "4.1.1.7209685",

        /* Singleton pointer globals — uniform +0x8000 vs 6995620 (validated) */
        .eocserver_ptr           = 0x089968b8,  // 0x0898e8b8 + 0x8000
        .eocclient_ptr           = 0x08994968,  // 0x0898c968 + 0x8000
        .spell_proto_mgr_ptr     = 0x089c2c80,  // 0x089bac80 + 0x8000
        .rpgstats_ptr            = 0x089cd730,  // 0x089c5730 + 0x8000 (count=16994)
        .resource_mgr_ptr        = 0x08a97070,  // 0x08a8f070 + 0x8000 (banks valid)
        .level_mgr_ptr           = 0x08a43e40,  // 0x08a3be40 + 0x8000
        .global_template_mgr_ptr = 0x08a90508,  // 0x08a88508 + 0x8000
        .cache_template_mgr_ptr  = 0x08a389a8,  // 0x08a309a8 + 0x8000
        .level_cache_mgr_ptr     = 0x08a7b5d8,  // 0x08a735d8 + 0x8000
        .staticdata_mstate_ptr   = 0x083cca68,  // 0x083c4a68 + 0x8000 (121 managers)
                                                // NOTE: this is the __DATA_CONST,__got SLOT whose
                                                // contents = 0x108947ba0 (TypeContext<ImmutableData-
                                                // Headmaster>::m_State object) — correct for the
                                                // one-dereference traversal in staticdata_manager.c.
                                                // nm cannot see it; audit via otool -Iv / __got.
        .gst_ptr                 = 0x08af4cd8,  // 0x08aeccd8 + 0x8000 (val=GST ptr, validated)
        .translated_string_repo_ptr = 0x08af5088, // TranslatedStringRepository::m_ptr (nm)
        .global_switches_ptr     = 0x08af4f30,  // EoCGlobalSwitches* — NOT old+0x8000 (slot moved
                                                // -0x24000). Verified 2026-07-29: 916 disasm refs
                                                // across 593 fns incl. App::CreateGlobalSwitches()
                                                // and BaseApp::CreateGlobalSwitches().
        .osiris_interface_ptr    = 0x08a86128,  // osi::OsirisInterface instance slot. No nm symbol;
                                                // verified 2026-07-29 by otool disasm of
                                                // osi::OsirisInterface::OsirisQuery @ 0x105c093b0:
                                                //   adrp x8, 0x108a86000 ; ldr x25, [x8, #0x128]
                                                // (matches PR #93's live-verified chain; see
                                                // ghidra/offsets/OSIRIS_DATABASES.md)
        /* Prototype-manager singletons + BaseApp — nm local symbols,
         * re-derived 2026-07-28 (formerly hardcoded in prototype_managers.c
         * and focus_hack.c; moved here 2026-08-04, Wave 2 lead). */
        .status_proto_mgr_ptr    = 0x089c5b30,  // eoc::StatusPrototypeManager::m_ptr
        .passives_ptr            = 0x089bc228,  // eoc::Passives::m_ptr (74 ADRP+LDR sites)
        .interrupt_proto_mgr_ptr = 0x089ba8f0,  // eoc::InterruptPrototypeManager::m_ptr
        .boost_proto_mgr_ptr     = 0x08999528,  // eoc::BoostPrototypeManager::m_ptr
        .baseapp_instance_ptr    = 0x08ac0278,  // BaseApp::s_AppInstance

        /* Function offsets (__TEXT) — resolved by nm symbol lookup on the
         * 7209685 binary; non-uniform shift, see note above. */
        .fn_feat_getfeats        = 0x01b59814,  // eoc::FeatManager::GetFeats() const
        .fn_getallfeats          = 0x011ef948,  // eoc::character_creation::GetAllFeats(Environment const&)
        .fn_get_background       = 0x0297a068,  // ImmutableDataHeadmaster::Get<eoc::BackgroundManager>() const
        .fn_get_origin           = 0x03401c84,  // ImmutableDataHeadmaster::Get<eoc::OriginManager>() const
        .fn_get_class            = 0x02614874,  // ImmutableDataHeadmaster::Get<eoc::ClassDescriptions>() const
        .fn_get_progression      = 0x0367d764,  // ImmutableDataHeadmaster::Get<eoc::ProgressionManager>() const
        .fn_get_actionresource   = 0x011889f4,  // ImmutableDataHeadmaster::Get<eoc::ActionResourceTypes>() const
        .fn_get_template_raw     = 0x05f85d1c,  // ls::GlobalTemplateManager::GetTemplateRaw(FixedString const&) const
        .fn_cache_template       = 0x05d216fc,  // ls::CacheTemplateManagerBase::CacheTemplate(...)
        .fn_aigrid_to_tile_pos   = 0x011619c0,  // eoc::AiGrid::ToTilePos(Vector3f const&, AiTilePos&, bool) const
        .fn_aigrid_get_metadata  = 0x0114b2e4,  // eoc::AiGrid::GetMetaData(AiTilePos const&)
        .fn_aigrid_remove_path   = 0x01161ea4,  // eoc::AiGrid::RemovePath(int)
        .fn_aigrid_find_path     = 0x01162a4c,  // eoc::AiGrid::FindPath(int)
        .fn_aigrid_find_path_immediate = 0x01165cec, // eoc::AiGrid::FindPathImmediate(int, bool)

        /* Entity system (verified end-to-end).
         * fn_try_get_uuid_mapping: ecs::legacy::Helper::TryGetSingleton<
         *   uuid::ToHandleMappingComponent const> (symbol-verified, old-0x1baa0).
         * The earlier crash was NOT this offset — it was read_eocserver_from_global
         * reading a stale EocServer address, yielding a garbage EntityWorld.
         * With the EocServer source fixed (offset table eocserver_ptr) the
         * EntityWorld at EocServer+0x288 is valid (probe-confirmed: 0xc8bb74000
         * with sane sub-structure), and EocServer::StartUp's `ldr x20,[x19,#0x288]`
         * confirms +0x288 is unchanged for this version.
         * component_data_shift: uniform +0x8000 __DATA shift. */
        .fn_try_get_uuid_mapping = 0x010c0e84,
        .fn_storage_tryget       = 0x0635ac94,  // ecs::EntityStorageContainer::TryGet (old 0x0636b27c - 0x105E8)
        .fn_spell_proto_init     = 0x01f56cb4,  // eoc::SpellPrototype::Init (old 0x01f72754 - 0x1baa0)
        .fn_status_proto_init    = 0x01ff7150,  // eoc::StatusPrototype::Init(FixedString const&, bool)
        .fn_interrupt_proto_get  = 0x01b7adcc,  // eoc::InterruptPrototypeManager::GetPrototype(FixedString const&) const
                                                // (nm; instruction-verified: x1=FS const*, x0 return,
                                                // NULL on miss, hit = &array[index], stride 0x1f0)
        .fn_passives_get         = 0x01c0f27c,  // eoc::Passives::Get(FixedString const&) const
                                                // (nm; instruction-verified 2026-08-01: LTO ARG-PROMOTED,
                                                // x1 = FS index BY VALUE, x0 return, NULL on miss)
        .component_data_shift    = 0,           // compiled-in __DATA constants ARE this
                                                // vintage (nm-audited 7209685) — no shift
        .component_data_shift_valid = true,

        .game_functions = {
            [GAME_FN_FIXED_STRING_CREATE] = 0x064a8a74,
            [GAME_FN_RESOURCE_GET] = 0x060bc020,
            [GAME_FN_EXECUTE_STATS_FUNCTOR] = 0x0577399c,
            [GAME_FN_EXECUTE_FUNCTORS_ATTACK_TARGET] = 0x0577787c,
            [GAME_FN_EXECUTE_FUNCTORS_ATTACK_POSITION] = 0x05777bd0,
            [GAME_FN_EXECUTE_FUNCTORS_MOVE] = 0x057796c0,
            [GAME_FN_EXECUTE_FUNCTORS_TARGET] = 0x0577a87c,
            [GAME_FN_EXECUTE_FUNCTORS_NEARBY_ATTACKED] = 0x0577e43c,
            [GAME_FN_EXECUTE_FUNCTORS_NEARBY_ATTACKING] = 0x0577fb0c,
            [GAME_FN_EXECUTE_FUNCTORS_EQUIP] = 0x0578098c,
            [GAME_FN_EXECUTE_FUNCTORS_SOURCE] = 0x057829f4,
            [GAME_FN_EXECUTE_FUNCTORS_INTERRUPT] = 0x05786548,
            [GAME_FN_PROCESS_DEAL_DAMAGE_FUNCTORS] = 0x0537e8b4,
            [GAME_FN_TRANSLATED_STRING_TRY_GET] = 0x0652390c,
            [GAME_FN_TRANSLATED_STRING_GET] = 0x06523d00,
            [GAME_FN_TRANSLATED_STRING_ADD] = 0x06521148,
            [GAME_FN_MESSAGE_FACTORY_GET_FREE_MESSAGE] = 0x063c4550,
            [GAME_FN_STD_STRING_CTOR] = 0x0650e718,
            [GAME_FN_BINK_LOAD_VIDEO] = 0x0390b6cc,
            [GAME_FN_VALUELIST_INSERT] = 0x01c44920,
        },
    },

    /* ------------------------------------------------------------------
     * 4.1.1.7398727 — exact arm64 nm/c++filt migration (2026-08-04).
     * Symbol-backed fields were resolved independently. The GOT field was
     * resolved with otool -Iv. The two anonymous slots were derived by the
     * Wave 2A ADRP+LDR metathesis (self-tested against 7209685; see
     * ghidra/offsets/ADDRESS_MIGRATION_7398727.md).
     * Shared ComponentTypeId entries have multiple observed deltas,
     * so the legacy scalar shift is explicitly invalid for this version.
     * ------------------------------------------------------------------ */
    {
        .version                 = "4.1.1.7398727",

        .eocserver_ptr           = 0x089c6f58,
        .eocclient_ptr           = 0x089c4fc0,
        .spell_proto_mgr_ptr     = 0x089f3320,
        .rpgstats_ptr            = 0x089fddd0,
        .resource_mgr_ptr        = 0x08ac8080,
        .wwise_manager_vtable    = 0x087bab10,  // vtable for ww::WwiseManager
        .level_mgr_ptr           = 0x08a74610,
        .global_template_mgr_ptr = 0x08ac0d98,
        .cache_template_mgr_ptr  = 0x08a69178,
        .level_cache_mgr_ptr     = 0x08aabda8,
        .staticdata_mstate_ptr   = 0x083fcc38,
        .gst_ptr                 = 0x08b25ce8,
        .translated_string_repo_ptr = 0x08b26098,
        .global_switches_ptr     = 0x08b25f40,  // EoCGlobalSwitches* — Wave 2A metathesis
                                                // (unique ADRP+LDR candidate; writer/reader
                                                // corroborated; self-test reproduced the
                                                // 7209685 value. ghidra/offsets/
                                                // ADDRESS_MIGRATION_7398727.md)
        .osiris_interface_ptr    = 0x08ab68f8,  // osi::OsirisInterface slot — Wave 2A
                                                // (loaded by OsirisCall/OsirisQuery/
                                                // ErrorMessage, written by InitStory/
                                                // ShutdownStory in both builds; same doc)
        /* Prototype-manager singletons + BaseApp — exact arm64 nm on the
         * frozen 7398727 binary (offset_manifest.json source records). */
        .status_proto_mgr_ptr    = 0x089f61d0,  // eoc::StatusPrototypeManager::m_ptr
        .passives_ptr            = 0x089ec8c8,  // eoc::Passives::m_ptr
        .interrupt_proto_mgr_ptr = 0x089eaf90,  // eoc::InterruptPrototypeManager::m_ptr
        .boost_proto_mgr_ptr     = 0x089c9bc8,  // eoc::BoostPrototypeManager::m_ptr
        .baseapp_instance_ptr    = 0x08af1288,  // BaseApp::s_AppInstance

        .fn_feat_getfeats        = 0x01b56f08,
        .fn_getallfeats          = 0x011ed03c,
        .fn_get_background       = 0x02980bd8,
        .fn_get_origin           = 0x0340c638,
        .fn_get_class            = 0x026162a8,
        .fn_get_progression      = 0x036881d0,
        .fn_get_actionresource   = 0x011860e8,
        .fn_get_template_raw     = 0x05f9cda4,
        .fn_cache_template       = 0x05d2c6e8,
        .fn_aigrid_to_tile_pos   = 0x0115f0b4,
        .fn_aigrid_get_metadata  = 0x011489d8,
        .fn_aigrid_remove_path   = 0x0115f598,
        .fn_aigrid_find_path     = 0x01160140,
        .fn_aigrid_find_path_immediate = 0x011633e0,
        .fn_try_get_uuid_mapping = 0x010be578,
        .fn_storage_tryget       = 0x06382944,
        .fn_spell_proto_init     = 0x01f543a8,
        .fn_status_proto_init    = 0x01ff4844,
        .fn_interrupt_proto_get  = 0x01b784c0,
        .fn_passives_get         = 0x01c0c970,
        .component_data_shift    = 0,
        .component_data_shift_valid = false,

        .game_functions = {
            [GAME_FN_FIXED_STRING_CREATE] = 0x064d0cb4,
            [GAME_FN_RESOURCE_GET] = 0x060e3cd0,
            [GAME_FN_EXECUTE_STATS_FUNCTOR] = 0x0577e650,
            [GAME_FN_EXECUTE_FUNCTORS_ATTACK_TARGET] = 0x05782530,
            [GAME_FN_EXECUTE_FUNCTORS_ATTACK_POSITION] = 0x05782884,
            [GAME_FN_EXECUTE_FUNCTORS_MOVE] = 0x05784374,
            [GAME_FN_EXECUTE_FUNCTORS_TARGET] = 0x05785530,
            [GAME_FN_EXECUTE_FUNCTORS_NEARBY_ATTACKED] = 0x057890f0,
            [GAME_FN_EXECUTE_FUNCTORS_NEARBY_ATTACKING] = 0x0578a7c0,
            [GAME_FN_EXECUTE_FUNCTORS_EQUIP] = 0x0578b640,
            [GAME_FN_EXECUTE_FUNCTORS_SOURCE] = 0x0578d6a8,
            [GAME_FN_EXECUTE_FUNCTORS_INTERRUPT] = 0x057911fc,
            [GAME_FN_PROCESS_DEAL_DAMAGE_FUNCTORS] = 0x05389568,
            [GAME_FN_TRANSLATED_STRING_TRY_GET] = 0x0654bb4c,
            [GAME_FN_TRANSLATED_STRING_GET] = 0x0654bf40,
            [GAME_FN_TRANSLATED_STRING_ADD] = 0x06549388,
            [GAME_FN_MESSAGE_FACTORY_GET_FREE_MESSAGE] = 0x063ec790,
            [GAME_FN_STD_STRING_CTOR] = 0x06536958,
            [GAME_FN_BINK_LOAD_VIDEO] = 0x03916380,
            [GAME_FN_VALUELIST_INSERT] = 0x01c42014,
        },
    },

};

#define NUM_VERSIONS (sizeof(g_offset_table) / sizeof(g_offset_table[0]))

// ============================================================================
// State
// ============================================================================

static const VersionOffsets *g_active = NULL;

// ============================================================================
// Public API
// ============================================================================

void offset_table_init(void) {
    const char *version = version_detect_get_version();
    if (!version) {
        log_message("[OffsetTable] Version not detected — all address-dependent features disabled");
        return;
    }

    for (int i = 0; i < (int)NUM_VERSIONS; i++) {
        if (strcmp(g_offset_table[i].version, version) == 0) {
            g_active = &g_offset_table[i];
            log_message("[OffsetTable] Loaded offsets for %s", version);
            return;
        }
    }

    log_message("[OffsetTable] Version %s not in table — running in degraded mode. "
                "Add a new entry to src/core/offset_table.c to enable full features.",
                version);
}

const VersionOffsets *offset_table_get(void) {
    return g_active;
}

void *offset_table_resolve(uintptr_t offset) {
    if (!offset) return NULL;
    void *base = version_detect_get_binary_base();
    if (!base) return NULL;
    return (void *)((uintptr_t)base + offset);
}

void *offset_table_fn(uintptr_t offset) {
    return offset_table_resolve(offset);
}

void *offset_table_game_fn(GameFunctionId id) {
    if (!g_active || id < 0 || id >= GAME_FN_COUNT) return NULL;
    return offset_table_resolve(g_active->game_functions[id]);
}
