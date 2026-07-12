/**
 * component_typeid.c - TypeId<T>::m_TypeIndex global discovery
 *
 * Reads TypeId globals from the game binary to discover component type indices.
 * These globals are initialized at game startup with the actual indices.
 */

#include "component_typeid.h"
#include "component_registry.h"
#include "component_property.h"  // For property system linkage
#include "entity_storage.h"  // For GHIDRA_BASE_ADDRESS
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../core/offset_table.h"  // For per-version component_data_shift

#include <string.h>

// ============================================================================
// Known TypeId Addresses
// ============================================================================

/**
 * Table of known TypeId<T>::m_TypeIndex global addresses.
 * These were discovered via Ghidra analysis of the macOS ARM64 binary.
 *
 * Mangled name pattern:
 *   __ZN2ls6TypeIdIN3{namespace}{length}{Component}EN3ecs22ComponentTypeIdContextEE11m_TypeIndexE
 */
typedef struct {
    const char *componentName;  // Full component name (e.g., "ecl::Character")
    uint64_t ghidraAddr;        // Ghidra address of m_TypeIndex global
    uint16_t expectedSize;      // Expected component size (0 = unknown)
    bool isProxy;               // Is this a proxy component?
    bool isPointer;             // If true, ghidraAddr points to TypeInfo*, read value at *ptr
} TypeIdEntry;

static const TypeIdEntry g_KnownTypeIds[] = {
    // =====================================================================
    // ecl:: namespace (client components)
    // Discovered via: nm -gU "Baldur's Gate 3" | c++filt | grep TypeId
    // Game version: 4.1.1.6995620 (macOS ARM64)
    // =====================================================================
    { "ecl::Character", 0x1088ab8e0, 0, false },
    { "ecl::Item",      0x1088ab8f0, 0, false },

    // =====================================================================
    // eoc:: namespace (engine of combat)
    // =====================================================================
    { "eoc::HealthComponent",  0x10890a360, 0, false },
    { "eoc::StatsComponent",   0x10890b058, 0, false },
    { "eoc::ArmorComponent",   0x108912e40, 0, false },
    { "eoc::BaseHpComponent",  0x108907888, 0, false },
    { "eoc::DataComponent",    0x10890b088, 0, false },

    // =====================================================================
    // ls:: namespace (base Larian components)
    // =====================================================================
    { "ls::TransformComponent", 0x108940550, 0, false },
    { "ls::LevelComponent",     0x10893e780, 0, false },
    { "ls::VisualComponent",    0x108940110, 0, false },
    { "ls::PhysicsComponent",   0x10893c8e8, 0, false },

    // =====================================================================
    // Phase 2 Components (Issue #33)
    // =====================================================================
    { "eoc::LevelComponent",             0x10890b068, 0, false },  // Character level (different from ls::LevelComponent)
    { "eoc::exp::ExperienceComponent",   0x1088ef818, 0, false },
    { "eoc::exp::AvailableLevelComponent", 0x108907918, 0, false },
    { "eoc::PassiveComponent",           0x1089113f8, 0, false },
    { "eoc::PassiveContainerComponent",  0x108907158, 0, false },
    { "eoc::ResistancesComponent",       0x108910010, 0, false },
    { "eoc::TagComponent",               0x10890b048, 0, false },
    { "eoc::RaceComponent",              0x1089075f0, 0, false },
    { "eoc::OriginComponent",            0x108900530, 0, false },
    { "eoc::ClassesComponent",           0x10890b098, 0, false },
    { "eoc::MovementComponent",          0x108909240, 0, false },

    // =====================================================================
    // Phase 2 Batch 2 Components (Issue #33)
    // =====================================================================
    { "eoc::BackgroundComponent",        0x1089004e0, 0, false },
    { "eoc::god::GodComponent",          0x1088faf68, 0, false },
    { "eoc::ValueComponent",             0x1089078e8, 0, false },
    { "eoc::TurnBasedComponent",         0x10890e9a8, 0, false },

    // =====================================================================
    // Phase 2 Batch 3 Components (Issue #33) - High-priority gameplay
    // =====================================================================
    { "eoc::WeaponComponent",            0x108912e00, 0, false },
    { "eoc::spell::BookComponent",       0x10890ae78, 0, false },
    { "eoc::status::ContainerComponent", 0x1089130e0, 0, false },
    { "eoc::inventory::ContainerComponent", 0x108908f08, 0, false },
    { "eoc::ActionResourcesComponent",   0x10890eb08, 0, false },

    // =====================================================================
    // Phase 2 Batch 4 Components (Issue #33) - Inventory relationships
    // =====================================================================
    { "eoc::inventory::OwnerComponent",    0x108908ef8, 0, false },
    { "eoc::inventory::MemberComponent",   0x1089153b0, 0, false },
    { "eoc::inventory::IsOwnedComponent",  0x108903ca8, 0, false },
    { "eoc::EquipableComponent",           0x1089078f8, 0, false },

    // =====================================================================
    // Phase 2 Batch 5 Components (Issue #33) - Spell and boost components
    // =====================================================================
    { "eoc::spell::ContainerComponent",               0x108906ce0, 0, false },
    { "eoc::concentration::ConcentrationComponent",   0x108907450, 0, false },
    { "eoc::BoostsContainerComponent",                0x108910000, 0, false },
    { "eoc::DisplayNameComponent",                    0x10890ce20, 0, false },

    // =====================================================================
    // Phase 2 Batch 6 Components (Issue #33) - Simple components
    // =====================================================================
    { "eoc::death::StateComponent",                   0x1088f7a60, 0, false },
    { "eoc::death::DeathTypeComponent",               0x1089027c0, 0, false },
    { "eoc::inventory::WeightComponent",              0x1088f76d8, 0, false },
    { "eoc::combat::ThreatRangeComponent",            0x10890b6e8, 0, false },
    { "eoc::combat::IsInCombatComponent",             0x108912fd0, 0, false },

    // =====================================================================
    // Phase 2 Batch 7 Components (Issue #33) - Combat components
    // =====================================================================
    { "eoc::combat::ParticipantComponent",            0x10890e9b8, 0, false },
    { "eoc::combat::StateComponent",                  0x10890ea38, 0, false },

    // =====================================================================
    // Phase 2 Batch 8 Components (Issue #33) - Tag components (115 total)
    // Tag components have no fields - their presence on an entity is the data
    // Generated by tools/generate_tag_components.py
    // =====================================================================

    // ecl:: tag components
    { "ecl::camera::IsInSelectorModeComponent",       0x1088a4410, 0, false },
    { "ecl::camera::SpellTrackingComponent",          0x1088ab858, 0, false },
    { "ecl::dummy::IsCopyingFullPoseComponent",       0x1088a11f8, 0, false },
    { "ecl::dummy::LoadedComponent",                  0x10889de20, 0, false },

    // eoc:: tag components
    { "eoc::CanTriggerRandomCastsComponent",          0x1088ef2b8, 0, false },
    { "eoc::ClientControlComponent",                  0x1089153c0, 0, false },
    { "eoc::GravityDisabledComponent",                0x1088f8b48, 0, false },
    { "eoc::IsInTurnBasedModeComponent",              0x10890e088, 0, false },
    { "eoc::OffStageComponent",                       0x10890e238, 0, false },
    { "eoc::PickingStateComponent",                   0x1088ef828, 0, false },
    { "eoc::PlayerComponent",                         0x10890ea28, 0, false },
    { "eoc::SimpleCharacterComponent",                0x1088f4068, 0, false },
    { "eoc::active_roll::InProgressComponent",        0x1089017a8, 0, false },
    { "eoc::ambush::AmbushingComponent",              0x1088dfb88, 0, false },
    { "eoc::camp::PresenceComponent",                 0x10890c008, 0, false },
    { "eoc::character::CharacterComponent",           0x10890e248, 0, false },
    { "eoc::combat::DelayedFanfareComponent",         0x108912fe0, 0, false },
    { "eoc::exp::CanLevelUpComponent",                0x1088f9ed8, 0, false },
    { "eoc::falling::IsFallingComponent",             0x108912fa0, 0, false },
    { "eoc::ftb::IsFtbPausedComponent",               0x1088f4a08, 0, false },
    { "eoc::ftb::IsInFtbComponent",                   0x1088f62b0, 0, false },
    { "eoc::heal::BlockComponent",                    0x1088e1c60, 0, false },
    { "eoc::heal::MaxIncomingComponent",              0x1088e1c40, 0, false },
    { "eoc::heal::MaxOutgoingComponent",              0x1088e1c50, 0, false },
    { "eoc::improvised_weapon::CanBeWieldedComponent", 0x1088e2228, 0, false },
    { "eoc::inventory::CanBeInComponent",             0x1088fe0e0, 0, false },
    { "eoc::inventory::CannotBePickpocketedComponent", 0x1088fad78, 0, false },
    { "eoc::inventory::CannotBeTakenOutComponent",    0x108902320, 0, false },
    { "eoc::inventory::DropOnDeathBlockedComponent",  0x1088fadb8, 0, false },
    { "eoc::inventory::IsLockedComponent",            0x108905760, 0, false },
    { "eoc::inventory::NewItemsInsideComponent",      0x1088fa000, 0, false },
    { "eoc::inventory::NonTradableComponent",         0x1088fad98, 0, false },
    { "eoc::item::DestroyingComponent",               0x1088f87d0, 0, false },
    { "eoc::item::DoorComponent",                     0x1088f8c68, 0, false },
    { "eoc::item::ExamineDisabledComponent",          0x1088f8c88, 0, false },
    { "eoc::item::HasMovedComponent",                 0x1088f8c58, 0, false },
    { "eoc::item::HasOpenedComponent",                0x1088fab28, 0, false },
    { "eoc::item::InUseComponent",                    0x1088f8c38, 0, false },
    { "eoc::item::IsGoldComponent",                   0x1088f87f0, 0, false },
    { "eoc::item::IsPoisonedComponent",               0x1088f8c48, 0, false },
    { "eoc::item::ItemComponent",                     0x108914cb0, 0, false },
    { "eoc::item::NewInInventoryComponent",           0x1088f9ff0, 0, false },
    { "eoc::item::ShouldDestroyOnSpellCastComponent", 0x108904008, 0, false },
    { "eoc::item_template::CanMoveComponent",         0x108903f20, 0, false },
    { "eoc::item_template::ClimbOnComponent",         0x1088f8c18, 0, false },
    { "eoc::item_template::DestroyedComponent",       0x108903f00, 0, false },
    { "eoc::item_template::InteractionDisabledComponent", 0x108903f30, 0, false },
    { "eoc::item_template::IsStoryItemComponent",     0x1088f8c78, 0, false },
    { "eoc::item_template::LadderComponent",          0x108904b90, 0, false },
    { "eoc::item_template::WalkOnComponent",          0x1088f8c28, 0, false },
    { "eoc::multiplayer::HostComponent",              0x1088eb780, 0, false },
    { "eoc::ownership::OwnedAsLootComponent",         0x1088f87e0, 0, false },
    { "eoc::party::BlockFollowComponent",             0x1088f03c0, 0, false },
    { "eoc::party::CurrentlyFollowingPartyComponent", 0x10890be78, 0, false },
    { "eoc::pickup::PickUpExecutingComponent",        0x1088fdea0, 0, false },
    { "eoc::rest::LongRestInScriptPhase",             0x1088eaa78, 0, false },
    { "eoc::rest::ShortRestComponent",                0x108904f10, 0, false },
    { "eoc::spell_cast::CanBeTargetedComponent",      0x1089041e8, 0, false },
    { "eoc::status::IndicateDarknessComponent",       0x1088e7ad8, 0, false },
    { "eoc::tadpole_tree::FullIllithidComponent",     0x1088e9108, 0, false },
    { "eoc::tadpole_tree::HalfIllithidComponent",     0x1088e9118, 0, false },
    { "eoc::tadpole_tree::TadpoledComponent",         0x1088e9128, 0, false },
    { "eoc::tag::AvatarComponent",                    0x1089157a0, 0, false },
    { "eoc::tag::HasExclamationDialogComponent",      0x1088e9648, 0, false },
    { "eoc::tag::TraderComponent",                    0x1088fe310, 0, false },
    { "eoc::through::CanSeeThroughComponent",         0x1088f8df8, 0, false },
    { "eoc::through::CanShootThroughComponent",       0x1089072c8, 0, false },
    { "eoc::through::CanWalkThroughComponent",        0x1088f8e18, 0, false },
    { "eoc::trade::CanTradeComponent",                0x1088fe300, 0, false },

    // esv:: tag components
    { "esv::IsMarkedForDeletionComponent",            0x1088fd0d8, 0, false },
    { "esv::NetComponent",                            0x1088f6c90, 0, false },
    { "esv::ScriptPropertyCanBePickpocketedComponent", 0x1088dff30, 0, false },
    { "esv::ScriptPropertyIsDroppedOnDeathComponent", 0x1088e2420, 0, false },
    { "esv::ScriptPropertyIsTradableComponent",       0x1088e24f0, 0, false },
    { "esv::TurnOrderSkippedComponent",               0x10890ead8, 0, false },
    { "esv::VariableManagerComponent",                0x1088eb928, 0, false },
    { "esv::boost::StatusBoostsProcessedComponent",   0x108903e48, 0, false },
    { "esv::character_creation::IsCustomComponent",   0x1088f69e8, 0, false },
    { "esv::combat::CanStartCombatComponent",         0x1088f1670, 0, false },
    { "esv::combat::FleeBlockedComponent",            0x1088f0e80, 0, false },
    { "esv::combat::ImmediateJoinComponent",          0x1088f15c0, 0, false },
    { "esv::combat::LeaveRequestComponent",           0x1088f4858, 0, false },
    { "esv::cover::IsLightBlockerComponent",          0x1088e0498, 0, false },
    { "esv::cover::IsVisionBlockerComponent",         0x1088eb9b0, 0, false },
    { "esv::darkness::DarknessActiveComponent",       0x1088e05e8, 0, false },
    { "esv::death::DeathContinueComponent",           0x1088f04c0, 0, false },
    { "esv::escort::HasStragglersComponent",          0x1088e14b0, 0, false },
    { "esv::hotbar::OrderComponent",                  0x1088e4528, 0, false },
    { "esv::inventory::CharacterHasGeneratedTradeTreasureComponent", 0x1088f7a80, 0, false },
    { "esv::inventory::EntityHasGeneratedTreasureComponent", 0x1088f7a70, 0, false },
    { "esv::inventory::IsReplicatedWithComponent",    0x1088f6e30, 0, false },
    { "esv::inventory::ReadyToBeAddedToInventoryComponent", 0x1088f6b10, 0, false },
    { "esv::level::InventoryItemDataPopulatedComponent", 0x1088e2ae8, 0, false },
    { "esv::rest::ShortRestConsumeResourcesComponent", 0x1088ec6c0, 0, false },
    { "esv::sight::EventsEnabledComponent",           0x1088eb960, 0, false },
    { "esv::spell_cast::ClientInitiatedComponent",    0x108905a90, 0, false },
    { "esv::status::ActiveComponent",                 0x1088fd058, 0, false },
    { "esv::status::AddedFromSaveLoadComponent",      0x108902400, 0, false },
    { "esv::status::AuraComponent",                   0x1088e8000, 0, false },
    { "esv::summon::IsUnsummoningComponent",          0x1088f8ae8, 0, false },
    { "esv::trigger::LoadedHandledComponent",         0x1088ea2a8, 0, false },
    { "esv::trigger::TriggerWorldAutoTriggeredComponent", 0x10890bea8, 0, false },

    // =====================================================================
    // Template Components (Issue #41 - Ext.Template support)
    // =====================================================================
    { "eoc::templates::OriginalTemplateComponent",    0x108902230, 0, false },

    // ls:: tag components
    { "ls::AlwaysUpdateEffectComponent",              0x1089363d8, 0, false },
    { "ls::AnimationUpdateComponent",                 0x108935e68, 0, false },
    { "ls::IsGlobalComponent",                        0x10893f0c0, 0, false },
    { "ls::IsSeeThroughComponent",                    0x10893d628, 0, false },
    { "ls::LevelIsOwnerComponent",                    0x10893b1a8, 0, false },
    { "ls::LevelPrepareUnloadBusyComponent",          0x108935ed8, 0, false },
    { "ls::LevelUnloadBusyComponent",                 0x10893b448, 0, false },
    { "ls::SavegameComponent",                        0x108935ff8, 0, false },
    { "ls::VisualLoadedComponent",                    0x1089402a8, 0, false },
    { "ls::game::PauseComponent",                     0x10893e8f0, 0, false },
    { "ls::game::PauseExcludedComponent",             0x10893e930, 0, false },
    { "ls::level::LevelInstanceUnloadingComponent",   0x10893b468, 0, false },

    // =====================================================================
    // Issue #51 Event Components - One-frame event components for Ext.Events
    // These addresses contain POINTERS to TypeIndex storage.
    // Must dereference: TypeIndex = *(uint32_t*)(*ptr)
    // Discovered via Ghidra: RegisterQueryDescription uses PTR_m_TypeIndex pattern.
    // =====================================================================
    { "esv::TurnStartedEventOneFrameComponent",       0x1083ced18, 0, false, true },  // TypeIndex 167
    { "esv::TurnEndedEventOneFrameComponent",         0x1083ceca8, 0, false, true },  // TypeIndex 164

    // Sentinel
    { NULL, 0, 0, false, false }
};

// ============================================================================
// Global State
// ============================================================================

static void *g_BinaryBase = NULL;
static bool g_Initialized = false;

// ============================================================================
// Initialization
// ============================================================================

bool component_typeid_init(void *binaryBase) {
    if (!binaryBase) {
        LOG_ENTITY_DEBUG("ERROR: binaryBase is NULL");
        return false;
    }

    g_BinaryBase = binaryBase;
    g_Initialized = true;

    LOG_ENTITY_DEBUG("Initialized with binary base: %p", binaryBase);
    return true;
}

bool component_typeid_ready(void) {
    return g_Initialized && g_BinaryBase != NULL;
}

// ============================================================================
// TypeId Reading
// ============================================================================

bool component_typeid_read(uint64_t ghidraAddr, uint16_t *outIndex) {
    if (!component_typeid_ready() || !outIndex) {
        return false;
    }

    /* Calculate runtime address
     * Formula: runtime = ghidra - 0x100000000 + binary_base + per-version data shift.
     * The TypeId globals live in __DATA, which can shift uniformly between game
     * versions (e.g. +0x8000 for 7209685); component_data_shift carries that delta. */
    uint64_t offset = ghidraAddr - GHIDRA_BASE_ADDRESS;
    const VersionOffsets *vo = offset_table_get();
    if (vo) offset += vo->component_data_shift;
    mach_vm_address_t runtimeAddr = offset + (mach_vm_address_t)g_BinaryBase;

    /* Validate the runtime address before attempting to read */
    SafeMemoryInfo info = safe_memory_check_address(runtimeAddr);
    if (!info.is_valid || !info.is_readable) {
        LOG_ENTITY_DEBUG("  Address 0x%llx (Ghidra 0x%llx) is not readable",
                   (unsigned long long)runtimeAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Check for GPU carveout region */
    if (safe_memory_is_gpu_region(runtimeAddr)) {
        LOG_ENTITY_DEBUG("  Address 0x%llx (Ghidra 0x%llx) is in GPU region",
                   (unsigned long long)runtimeAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Safely read the 4-byte type index
     * TypeId<T>::m_TypeIndex is typically a 32-bit integer */
    int32_t rawValue = -1;
    if (!safe_memory_read_i32(runtimeAddr, &rawValue)) {
        LOG_ENTITY_DEBUG("  Failed to safely read from 0x%llx (Ghidra 0x%llx)",
                   (unsigned long long)runtimeAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Check for uninitialized (-1 or very large values indicate not yet registered) */
    if (rawValue < 0 || rawValue > 0xFFFF) {
        LOG_ENTITY_DEBUG("  Invalid TypeIndex value %d at 0x%llx (expected 0-65535)",
                   rawValue, (unsigned long long)runtimeAddr);
        return false;
    }

    *outIndex = (uint16_t)rawValue;
    LOG_ENTITY_DEBUG("  TypeIndex=%u at 0x%llx (Ghidra 0x%llx)",
               *outIndex, (unsigned long long)runtimeAddr, (unsigned long long)ghidraAddr);
    return true;
}

/**
 * Read TypeIndex from a pointer-based address.
 * Some components (like one-frame event components) store a pointer to TypeInfo,
 * and the TypeIndex is at offset 0 of that structure.
 *
 * Pattern from Ghidra:
 *   puVar3 = PTR_m_TypeIndex_XXXXXXXX;
 *   uVar1 = *(uint *)PTR_m_TypeIndex_XXXXXXXX;
 */
bool component_typeid_read_pointer(uint64_t ghidraAddr, uint16_t *outIndex) {
    if (!component_typeid_ready() || !outIndex) {
        return false;
    }

    /* Calculate runtime address of the pointer (with per-version data shift) */
    uint64_t offset = ghidraAddr - GHIDRA_BASE_ADDRESS;
    const VersionOffsets *vo = offset_table_get();
    if (vo) offset += vo->component_data_shift;
    mach_vm_address_t ptrAddr = offset + (mach_vm_address_t)g_BinaryBase;

    /* Validate the pointer address */
    SafeMemoryInfo info = safe_memory_check_address(ptrAddr);
    if (!info.is_valid || !info.is_readable) {
        LOG_ENTITY_DEBUG("  Pointer address 0x%llx (Ghidra 0x%llx) is not readable",
                   (unsigned long long)ptrAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Read the pointer value */
    void *typeInfoPtr = NULL;
    if (!safe_memory_read_pointer(ptrAddr, &typeInfoPtr)) {
        LOG_ENTITY_DEBUG("  Failed to read pointer from 0x%llx (Ghidra 0x%llx)",
                   (unsigned long long)ptrAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    if (!typeInfoPtr) {
        LOG_ENTITY_DEBUG("  Null pointer at 0x%llx (Ghidra 0x%llx)",
                   (unsigned long long)ptrAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Validate the dereferenced address */
    mach_vm_address_t valueAddr = (mach_vm_address_t)typeInfoPtr;
    SafeMemoryInfo derefInfo = safe_memory_check_address(valueAddr);
    if (!derefInfo.is_valid || !derefInfo.is_readable) {
        LOG_ENTITY_DEBUG("  Dereferenced address 0x%llx is not readable (ptr at Ghidra 0x%llx)",
                   (unsigned long long)valueAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Read the TypeIndex from the dereferenced address */
    int32_t rawValue = -1;
    if (!safe_memory_read_i32(valueAddr, &rawValue)) {
        LOG_ENTITY_DEBUG("  Failed to read TypeIndex from 0x%llx (ptr at Ghidra 0x%llx)",
                   (unsigned long long)valueAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Check for valid TypeIndex range */
    if (rawValue < 0 || rawValue > 0xFFFF) {
        LOG_ENTITY_DEBUG("  Invalid TypeIndex value %d at *0x%llx (expected 0-65535)",
                   rawValue, (unsigned long long)valueAddr);
        return false;
    }

    *outIndex = (uint16_t)rawValue;
    LOG_ENTITY_DEBUG("  TypeIndex=%u at *0x%llx (ptr at Ghidra 0x%llx)",
               *outIndex, (unsigned long long)valueAddr, (unsigned long long)ghidraAddr);
    return true;
}

// ============================================================================
// Discovery
// ============================================================================

int component_typeid_discover(void) {
    if (!component_typeid_ready()) {
        LOG_ENTITY_DEBUG("ERROR: Not initialized, cannot discover");
        return 0;
    }

    LOG_ENTITY_DEBUG("Discovering component type indices from TypeId globals...");

    int discovered = 0;

    for (int i = 0; g_KnownTypeIds[i].componentName != NULL; i++) {
        const TypeIdEntry *entry = &g_KnownTypeIds[i];

        uint16_t typeIndex;
        bool success;

        // Use pointer-based read for one-frame components (isPointer flag)
        if (entry->isPointer) {
            success = component_typeid_read_pointer(entry->ghidraAddr, &typeIndex);
        } else {
            success = component_typeid_read(entry->ghidraAddr, &typeIndex);
        }

        if (success) {
            // One-frame components (isPointer=true) need the 0x8000 bit set
            // This tells the storage lookup to search the OneFrameComponents pool
            uint16_t registeredIndex = typeIndex;
            if (entry->isPointer) {
                registeredIndex = typeIndex | 0x8000;  // Set one-frame bit
            }

            LOG_ENTITY_DEBUG("  %s: index=%u (registered=%u, from 0x%llx, oneFrame=%s)",
                       entry->componentName, typeIndex, registeredIndex,
                       (unsigned long long)entry->ghidraAddr,
                       entry->isPointer ? "yes" : "no");

            // Update the component registry with the proper index (with 0x8000 for one-frame)
            bool registered = component_registry_register(
                entry->componentName,
                registeredIndex,
                entry->expectedSize,
                entry->isProxy
            );

            if (registered) {
                // Also update the property system so layouts can be looked up by TypeIndex
                component_property_set_type_index(entry->componentName, typeIndex);
                discovered++;
            }
        } else {
            LOG_ENTITY_DEBUG("  %s: FAILED to read from 0x%llx (ptr=%s)",
                       entry->componentName, (unsigned long long)entry->ghidraAddr,
                       entry->isPointer ? "yes" : "no");
        }
    }

    LOG_ENTITY_DEBUG("Discovered %d component type indices from known list", discovered);

    // Also discover TypeIds for all 1999 generated components
    int generated = component_typeid_discover_all_generated();
    discovered += generated;

    LOG_ENTITY_DEBUG("Discovered %d total component type indices", discovered);
    return discovered;
}

// ============================================================================
// Debug
// ============================================================================

// Forward declaration for console output
extern void console_printf(const char *format, ...);

/**
 * Dump TypeId status to console.
 * Shows resolved/unresolved count and details for each component.
 */
void component_typeid_dump_to_console(void) {
    if (!component_typeid_ready()) {
        console_printf("TypeId system not initialized");
        return;
    }

    console_printf("Component TypeId Resolution Status:");
    console_printf("------------------------------------");

    int resolved = 0;
    int total = 0;

    for (int i = 0; g_KnownTypeIds[i].componentName != NULL; i++) {
        const TypeIdEntry *entry = &g_KnownTypeIds[i];
        total++;

        const VersionOffsets *vo = offset_table_get();
        mach_vm_address_t runtimeAddr = entry->ghidraAddr - GHIDRA_BASE_ADDRESS
                                        + (vo ? vo->component_data_shift : 0)
                                        + (mach_vm_address_t)g_BinaryBase;

        // Check if address is readable
        SafeMemoryInfo info = safe_memory_check_address(runtimeAddr);
        if (!info.is_valid || !info.is_readable) {
            console_printf("%-55s UNREADABLE", entry->componentName);
            continue;
        }

        if (safe_memory_is_gpu_region(runtimeAddr)) {
            console_printf("%-55s GPU_REGION", entry->componentName);
            continue;
        }

        // Safely read the value
        int32_t rawValue = -1;
        if (!safe_memory_read_i32(runtimeAddr, &rawValue)) {
            console_printf("%-55s READ_FAILED", entry->componentName);
            continue;
        }

        if (rawValue >= 0 && rawValue <= 0xFFFF && rawValue != 0xFFFF) {
            console_printf("%-55s RESOLVED (typeIndex=%u)", entry->componentName, (uint16_t)rawValue);
            resolved++;
        } else if (rawValue == 0xFFFF || rawValue == -1) {
            console_printf("%-55s UNRESOLVED (typeIndex=65535)", entry->componentName);
        } else {
            console_printf("%-55s INVALID (rawValue=%d)", entry->componentName, rawValue);
        }
    }

    console_printf("------------------------------------");
    console_printf("Resolved: %d/%d (%d%%)", resolved, total, total > 0 ? (resolved * 100 / total) : 0);
}

void component_typeid_dump(void) {
    if (!component_typeid_ready()) {
        LOG_ENTITY_DEBUG("Not initialized");
        return;
    }

    LOG_ENTITY_DEBUG("=== TypeId<T>::m_TypeIndex Dump ===");
    LOG_ENTITY_DEBUG("Binary base: %p", g_BinaryBase);

    for (int i = 0; g_KnownTypeIds[i].componentName != NULL; i++) {
        const TypeIdEntry *entry = &g_KnownTypeIds[i];

        const VersionOffsets *vo = offset_table_get();
        mach_vm_address_t runtimeAddr = entry->ghidraAddr - GHIDRA_BASE_ADDRESS
                                        + (vo ? vo->component_data_shift : 0)
                                        + (mach_vm_address_t)g_BinaryBase;

        LOG_ENTITY_DEBUG("  %s:", entry->componentName);
        LOG_ENTITY_DEBUG("    Ghidra addr: 0x%llx", (unsigned long long)entry->ghidraAddr);
        LOG_ENTITY_DEBUG("    Runtime addr: 0x%llx", (unsigned long long)runtimeAddr);

        /* Check if address is readable */
        SafeMemoryInfo info = safe_memory_check_address(runtimeAddr);
        if (!info.is_valid || !info.is_readable) {
            LOG_ENTITY_DEBUG("    => NOT READABLE");
            continue;
        }

        if (safe_memory_is_gpu_region(runtimeAddr)) {
            LOG_ENTITY_DEBUG("    => GPU REGION (unsafe)");
            continue;
        }

        /* Safely read the value */
        int32_t rawValue = -1;
        if (!safe_memory_read_i32(runtimeAddr, &rawValue)) {
            LOG_ENTITY_DEBUG("    => READ FAILED");
            continue;
        }

        LOG_ENTITY_DEBUG("    Raw value: %d (0x%x)", rawValue, rawValue);

        if (rawValue >= 0 && rawValue <= 0xFFFF) {
            LOG_ENTITY_DEBUG("    => TypeIndex: %u", (uint16_t)rawValue);
        } else {
            LOG_ENTITY_DEBUG("    => INVALID (uninitialized or error)");
        }
    }
}
