/*
 * BG3SE-macOS Enum Definitions
 * Hardcoded enum values sourced from Windows BG3SE Enumerations/Stats.inl
 */

#include "enum_registry.h"

// Helper macro for registering enum values
#define REG_VALUE(type_idx, label, val) \
    enum_registry_add_value(type_idx, label, val)

// ============================================================================
// DamageType
// ============================================================================
static void register_damage_type(void) {
    int idx = enum_registry_add_type("DamageType", false);
    if (idx < 0) return;

    REG_VALUE(idx, "None", 0);
    REG_VALUE(idx, "Slashing", 1);
    REG_VALUE(idx, "Piercing", 2);
    REG_VALUE(idx, "Bludgeoning", 3);
    REG_VALUE(idx, "Acid", 4);
    REG_VALUE(idx, "Thunder", 5);
    REG_VALUE(idx, "Necrotic", 6);
    REG_VALUE(idx, "Fire", 7);
    REG_VALUE(idx, "Lightning", 8);
    REG_VALUE(idx, "Cold", 9);
    REG_VALUE(idx, "Psychic", 10);
    REG_VALUE(idx, "Poison", 11);
    REG_VALUE(idx, "Radiant", 12);
    REG_VALUE(idx, "Force", 13);
}

// ============================================================================
// AbilityId
// ============================================================================
static void register_ability_id(void) {
    int idx = enum_registry_add_type("AbilityId", false);
    if (idx < 0) return;

    REG_VALUE(idx, "None", 0);
    REG_VALUE(idx, "Strength", 1);
    REG_VALUE(idx, "Dexterity", 2);
    REG_VALUE(idx, "Constitution", 3);
    REG_VALUE(idx, "Intelligence", 4);
    REG_VALUE(idx, "Wisdom", 5);
    REG_VALUE(idx, "Charisma", 6);
}

// ============================================================================
// SkillId
// ============================================================================
static void register_skill_id(void) {
    int idx = enum_registry_add_type("SkillId", false);
    if (idx < 0) return;

    REG_VALUE(idx, "Deception", 0);
    REG_VALUE(idx, "Intimidation", 1);
    REG_VALUE(idx, "Performance", 2);
    REG_VALUE(idx, "Persuasion", 3);
    REG_VALUE(idx, "Acrobatics", 4);
    REG_VALUE(idx, "SleightOfHand", 5);
    REG_VALUE(idx, "Stealth", 6);
    REG_VALUE(idx, "Arcana", 7);
    REG_VALUE(idx, "History", 8);
    REG_VALUE(idx, "Investigation", 9);
    REG_VALUE(idx, "Nature", 10);
    REG_VALUE(idx, "Religion", 11);
    REG_VALUE(idx, "Athletics", 12);
    REG_VALUE(idx, "AnimalHandling", 13);
    REG_VALUE(idx, "Insight", 14);
    REG_VALUE(idx, "Medicine", 15);
    REG_VALUE(idx, "Perception", 16);
    REG_VALUE(idx, "Survival", 17);
}

// ============================================================================
// StatusType
// ============================================================================
static void register_status_type(void) {
    int idx = enum_registry_add_type("StatusType", false);
    if (idx < 0) return;

    REG_VALUE(idx, "DYING", 1);
    REG_VALUE(idx, "HEAL", 2);
    REG_VALUE(idx, "KNOCKED_DOWN", 3);
    REG_VALUE(idx, "TELEPORT_FALLING", 4);
    REG_VALUE(idx, "BOOST", 5);
    REG_VALUE(idx, "REACTION", 6);
    REG_VALUE(idx, "STORY_FROZEN", 7);
    REG_VALUE(idx, "SNEAKING", 8);
    REG_VALUE(idx, "UNLOCK", 9);
    REG_VALUE(idx, "FEAR", 10);
    REG_VALUE(idx, "SMELLY", 11);
    REG_VALUE(idx, "INVISIBLE", 12);
    REG_VALUE(idx, "ROTATE", 13);
    REG_VALUE(idx, "MATERIAL", 14);
    REG_VALUE(idx, "CLIMBING", 15);
    REG_VALUE(idx, "INCAPACITATED", 16);
    REG_VALUE(idx, "INSURFACE", 17);
    REG_VALUE(idx, "POLYMORPHED", 18);
    REG_VALUE(idx, "EFFECT", 19);
    REG_VALUE(idx, "DEACTIVATED", 20);
    REG_VALUE(idx, "DOWNED", 21);
}

// ============================================================================
// SurfaceType
// ============================================================================
static void register_surface_type(void) {
    int idx = enum_registry_add_type("SurfaceType", false);
    if (idx < 0) return;

    REG_VALUE(idx, "None", 0);
    REG_VALUE(idx, "Water", 1);
    REG_VALUE(idx, "WaterElectrified", 2);
    REG_VALUE(idx, "WaterFrozen", 3);
    REG_VALUE(idx, "Blood", 4);
    REG_VALUE(idx, "BloodElectrified", 5);
    REG_VALUE(idx, "BloodFrozen", 6);
    REG_VALUE(idx, "Poison", 7);
    REG_VALUE(idx, "Oil", 8);
    REG_VALUE(idx, "Lava", 9);
    REG_VALUE(idx, "Grease", 10);
    REG_VALUE(idx, "WyvernPoison", 11);
    REG_VALUE(idx, "Web", 12);
    REG_VALUE(idx, "Deepwater", 13);
    REG_VALUE(idx, "Vines", 14);
    REG_VALUE(idx, "Fire", 15);
    REG_VALUE(idx, "Acid", 16);
    REG_VALUE(idx, "TrialFire", 17);
    REG_VALUE(idx, "BlackPowder", 18);
    REG_VALUE(idx, "ShadowCursedVines", 19);
    REG_VALUE(idx, "AlienOil", 20);
    REG_VALUE(idx, "Mud", 21);
    REG_VALUE(idx, "Alcohol", 22);
    REG_VALUE(idx, "InvisibleWeb", 23);
    REG_VALUE(idx, "BloodSilver", 24);
    REG_VALUE(idx, "Chasm", 25);
    REG_VALUE(idx, "Hellfire", 26);
    REG_VALUE(idx, "CausticBrine", 27);
    REG_VALUE(idx, "BloodExploding", 28);
    REG_VALUE(idx, "Ash", 29);
    REG_VALUE(idx, "SpikeGrowth", 30);
    REG_VALUE(idx, "HolyFire", 31);
    REG_VALUE(idx, "BlackTentacles", 32);
    REG_VALUE(idx, "Overgrowth", 33);
    REG_VALUE(idx, "PurpleWormPoison", 34);
    REG_VALUE(idx, "SerpentVenom", 35);
    REG_VALUE(idx, "InvisibleGithAcid", 36);
    REG_VALUE(idx, "BladeBarrier", 37);
    REG_VALUE(idx, "Sewer", 38);
    // Clouds
    REG_VALUE(idx, "WaterCloud", 39);
    REG_VALUE(idx, "WaterCloudElectrified", 40);
    REG_VALUE(idx, "PoisonCloud", 41);
    REG_VALUE(idx, "ExplosionCloud", 42);
    REG_VALUE(idx, "ShockwaveCloud", 43);
    REG_VALUE(idx, "CloudkillCloud", 44);
    REG_VALUE(idx, "MaliceCloud", 45);
    REG_VALUE(idx, "BloodCloud", 46);
    REG_VALUE(idx, "StinkingCloud", 47);
    REG_VALUE(idx, "DarknessCloud", 48);
    REG_VALUE(idx, "FogCloud", 49);
}

// ============================================================================
// SpellSchoolId
// ============================================================================
static void register_spell_school_id(void) {
    int idx = enum_registry_add_type("SpellSchoolId", false);
    if (idx < 0) return;

    REG_VALUE(idx, "None", 0);
    REG_VALUE(idx, "Abjuration", 1);
    REG_VALUE(idx, "Conjuration", 2);
    REG_VALUE(idx, "Divination", 3);
    REG_VALUE(idx, "Enchantment", 4);
    REG_VALUE(idx, "Evocation", 5);
    REG_VALUE(idx, "Illusion", 6);
    REG_VALUE(idx, "Necromancy", 7);
    REG_VALUE(idx, "Transmutation", 8);
}

// ============================================================================
// WeaponType
// ============================================================================
static void register_weapon_type(void) {
    int idx = enum_registry_add_type("WeaponType", false);
    if (idx < 0) return;

    REG_VALUE(idx, "None", 0);
    REG_VALUE(idx, "Sword", 1);
    REG_VALUE(idx, "Club", 2);
    REG_VALUE(idx, "Axe", 3);
    REG_VALUE(idx, "Staff", 4);
    REG_VALUE(idx, "Bow", 5);
    REG_VALUE(idx, "Crossbow", 6);
    REG_VALUE(idx, "Spear", 7);
    REG_VALUE(idx, "Knife", 8);
    REG_VALUE(idx, "Wand", 9);
    REG_VALUE(idx, "Arrow", 10);
    REG_VALUE(idx, "Rifle", 11);
}

// ============================================================================
// ArmorType
// ============================================================================
static void register_armor_type(void) {
    int idx = enum_registry_add_type("ArmorType", false);
    if (idx < 0) return;

    REG_VALUE(idx, "None", 0);
    REG_VALUE(idx, "Cloth", 1);
    REG_VALUE(idx, "Padded", 2);
    REG_VALUE(idx, "Leather", 3);
    REG_VALUE(idx, "StuddedLeather", 4);
    REG_VALUE(idx, "Hide", 5);
    REG_VALUE(idx, "ChainShirt", 6);
    REG_VALUE(idx, "ScaleMail", 7);
    REG_VALUE(idx, "BreastPlate", 8);
    REG_VALUE(idx, "HalfPlate", 9);
    REG_VALUE(idx, "RingMail", 10);
    REG_VALUE(idx, "ChainMail", 11);
    REG_VALUE(idx, "Splint", 12);
    REG_VALUE(idx, "Plate", 13);
}

// ============================================================================
// ItemSlot
// ============================================================================
static void register_item_slot(void) {
    int idx = enum_registry_add_type("ItemSlot", false);
    if (idx < 0) return;

    REG_VALUE(idx, "Helmet", 0);
    REG_VALUE(idx, "Breast", 1);
    REG_VALUE(idx, "Cloak", 2);
    REG_VALUE(idx, "MeleeMainHand", 3);
    REG_VALUE(idx, "MeleeOffHand", 4);
    REG_VALUE(idx, "RangedMainHand", 5);
    REG_VALUE(idx, "RangedOffHand", 6);
    REG_VALUE(idx, "Ring", 7);
    REG_VALUE(idx, "Underwear", 8);
    REG_VALUE(idx, "Boots", 9);
    REG_VALUE(idx, "Gloves", 10);
    REG_VALUE(idx, "Amulet", 11);
    REG_VALUE(idx, "Ring2", 12);
    REG_VALUE(idx, "Wings", 13);
    REG_VALUE(idx, "Horns", 14);
    REG_VALUE(idx, "Overhead", 15);
    REG_VALUE(idx, "MusicalInstrument", 16);
    REG_VALUE(idx, "VanityBody", 17);
    REG_VALUE(idx, "VanityBoots", 18);
    REG_VALUE(idx, "MainHand", 19);
    REG_VALUE(idx, "OffHand", 20);
}

// ============================================================================
// ItemDataRarity
// ============================================================================
static void register_item_rarity(void) {
    int idx = enum_registry_add_type("ItemDataRarity", false);
    if (idx < 0) return;

    REG_VALUE(idx, "Common", 0);
    REG_VALUE(idx, "Unique", 1);
    REG_VALUE(idx, "Uncommon", 2);
    REG_VALUE(idx, "Rare", 3);
    REG_VALUE(idx, "Epic", 4);
    REG_VALUE(idx, "Legendary", 5);
    REG_VALUE(idx, "Divine", 6);
}

// ============================================================================
// SpellType
// ============================================================================
static void register_spell_type(void) {
    int idx = enum_registry_add_type("SpellType", false);
    if (idx < 0) return;

    REG_VALUE(idx, "None", 0);
    REG_VALUE(idx, "Zone", 1);
    REG_VALUE(idx, "MultiStrike", 2);
    REG_VALUE(idx, "Projectile", 3);
    REG_VALUE(idx, "ProjectileStrike", 4);
    REG_VALUE(idx, "Rush", 5);
    REG_VALUE(idx, "Shout", 6);
    REG_VALUE(idx, "Storm", 7);
    REG_VALUE(idx, "Target", 8);
    REG_VALUE(idx, "Teleportation", 9);
    REG_VALUE(idx, "Wall", 10);
    REG_VALUE(idx, "Throw", 11);
}

// ============================================================================
// AttributeFlags (Bitfield)
// ============================================================================
static void register_attribute_flags(void) {
    int idx = enum_registry_add_type("AttributeFlags", true);
    if (idx < 0) return;

    // Set allowed_flags mask
    EnumTypeInfo *info = enum_registry_get(idx);
    if (info) {
        info->allowed_flags = 0x7FFFFF;  // All valid flags ORed together
    }

    REG_VALUE(idx, "SlippingImmunity", 0x1);
    REG_VALUE(idx, "Torch", 0x2);
    REG_VALUE(idx, "Arrow", 0x4);
    REG_VALUE(idx, "Unbreakable", 0x8);
    REG_VALUE(idx, "Unrepairable", 0x10);
    REG_VALUE(idx, "Unstorable", 0x20);
    REG_VALUE(idx, "Grounded", 0x40);
    REG_VALUE(idx, "Floating", 0x80);
    REG_VALUE(idx, "InventoryBound", 0x100);
    REG_VALUE(idx, "IgnoreClouds", 0x200);
    REG_VALUE(idx, "LootableWhenEquipped", 0x400);
    REG_VALUE(idx, "PickpocketableWhenEquipped", 0x800);
    REG_VALUE(idx, "LoseDurabilityOnCharacterHit", 0x1000);
    REG_VALUE(idx, "ThrownImmunity", 0x2000);
    REG_VALUE(idx, "InvisibilityImmunity", 0x4000);
    REG_VALUE(idx, "InvulnerableAndInteractive", 0x8000);
    REG_VALUE(idx, "Backstab", 0x10000);
    REG_VALUE(idx, "BackstabImmunity", 0x20000);
    REG_VALUE(idx, "EnableObscurityEvents", 0x40000);
    REG_VALUE(idx, "ObscurityWithoutSneaking", 0x80000);
    REG_VALUE(idx, "FloatingWhileMoving", 0x100000);
    REG_VALUE(idx, "ForceMainhandAlternativeEquipBones", 0x200000);
    REG_VALUE(idx, "UseMusicalInstrumentForCasting", 0x400000);
}

// ============================================================================
// WeaponFlags (Bitfield)
// ============================================================================
static void register_weapon_flags(void) {
    int idx = enum_registry_add_type("WeaponFlags", true);
    if (idx < 0) return;

    EnumTypeInfo *info = enum_registry_get(idx);
    if (info) {
        info->allowed_flags = 0x1FFFFF;
    }

    REG_VALUE(idx, "Light", 0x1);
    REG_VALUE(idx, "Ammunition", 0x2);
    REG_VALUE(idx, "Finesse", 0x4);
    REG_VALUE(idx, "Heavy", 0x8);
    REG_VALUE(idx, "Loading", 0x10);
    REG_VALUE(idx, "Range", 0x20);
    REG_VALUE(idx, "Reach", 0x40);
    REG_VALUE(idx, "Lance", 0x80);
    REG_VALUE(idx, "Net", 0x100);
    REG_VALUE(idx, "Thrown", 0x200);
    REG_VALUE(idx, "Twohanded", 0x400);
    REG_VALUE(idx, "Versatile", 0x800);
    REG_VALUE(idx, "Melee", 0x1000);
    REG_VALUE(idx, "Dippable", 0x2000);
    REG_VALUE(idx, "Torch", 0x4000);
    REG_VALUE(idx, "NoDualWield", 0x8000);
    REG_VALUE(idx, "Magical", 0x10000);
    REG_VALUE(idx, "NeedDualWieldingBoost", 0x20000);
    REG_VALUE(idx, "NotSheathable", 0x40000);
    REG_VALUE(idx, "Unstowable", 0x80000);
    REG_VALUE(idx, "AddToHotbar", 0x100000);
}

// ============================================================================
// DamageFlags (Bitfield)
// ============================================================================
static void register_damage_flags(void) {
    int idx = enum_registry_add_type("DamageFlags", true);
    if (idx < 0) return;

    EnumTypeInfo *info = enum_registry_get(idx);
    if (info) {
        info->allowed_flags = 0x3FFFF;
    }

    REG_VALUE(idx, "Hit", 0x1);
    REG_VALUE(idx, "Dodge", 0x2);
    REG_VALUE(idx, "Miss", 0x4);
    REG_VALUE(idx, "Critical", 0x8);
    REG_VALUE(idx, "Backstab", 0x10);
    REG_VALUE(idx, "Invisible", 0x20);
    REG_VALUE(idx, "Magical", 0x40);
    REG_VALUE(idx, "Invulnerable", 0x80);
    REG_VALUE(idx, "SavingThrow", 0x100);
    REG_VALUE(idx, "Projectile", 0x200);
    REG_VALUE(idx, "HitpointsDamaged", 0x400);
    REG_VALUE(idx, "Surface", 0x800);
    REG_VALUE(idx, "Status", 0x1000);
    REG_VALUE(idx, "AttackAdvantage", 0x2000);
    REG_VALUE(idx, "AttackDisadvantage", 0x4000);
    REG_VALUE(idx, "Calculated", 0x8000);
    REG_VALUE(idx, "KillingBlow", 0x10000);
    REG_VALUE(idx, "NonlethalCapped", 0x20000);
}

// ============================================================================
// Public API
// ============================================================================
void enum_register_definitions(void) {
    // Regular enums
    register_damage_type();
    register_ability_id();
    register_skill_id();
    register_status_type();
    register_surface_type();
    register_spell_school_id();
    register_weapon_type();
    register_armor_type();
    register_item_slot();
    register_item_rarity();
    register_spell_type();

    // Bitfields
    register_attribute_flags();
    register_weapon_flags();
    register_damage_flags();
}
