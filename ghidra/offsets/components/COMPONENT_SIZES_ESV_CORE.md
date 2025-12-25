# esv::core:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv:: (core) | ~35 |  |  |
| esv::AIHintAreaTrigger | 0x08 | 8 | AI hint trigger |
| esv::ActivationGroupContainerComponent | 0x10 | 16 | Activation groups |
| esv::ActiveCharacterLightComponent | 0x4 | 4 |  |
| esv::ActiveMusicVolumeComponent | 0x08 | 8 | Audio trigger |
| esv::AiGridAreaTrigger | 0x08 | 8 | AI grid trigger |
| esv::AnubisExecutorComponent | 8 (ptr) | `* 8` (ptr deref) | GetComponent<esv::AnubisExecutorComponent,false> @ 0x102af24e4 |
| esv::ArmorClassComponent | 0x20 | 32 |  |
| esv::AtmosphereTrigger | 0x08 | 8 | Atmosphere trigger |
| esv::AvailableLevelComponent | 0x8 | 8 |  |
| esv::AvatarContainerTrigger | 0x78 | 120 | Avatar container |
| esv::BaseDataComponent | 0x18 | 24 | Base entity data |
| esv::BaseHpComponent | 0x10 | 16 |  |
| esv::BaseSizeComponent | 0x02 | 2 | Size value |
| esv::BaseStatsComponent | 0x04 | 4 | Base stats |
| esv::BaseWeaponComponent | 0x10 | 16 | Weapon data |
| esv::BlockBronzeTimelinePlacementTrigger | 0x08 | 8 | Timeline trigger |
| esv::BreadcrumbComponent | 0x10c | 268 |  |
| esv::CampChestTrigger | 0x08 | 8 | Camp chest trigger |
| esv::CampRegionTrigger | 0x08 | 8 | Camp region trigger |
| esv::Character | 0x08 | 8 | Ptr to 0x1a8 (424b) malloc |
| esv::CharacterComponent | 0x18 | 24 |  |
| esv::CharacterCreationCustomIconComponent | 0x58 | 88 | Has invoke function |
| esv::ChasmDataComponent | 0x30 | 48 | Chasm data |
| esv::ChasmRegionTrigger | 0x88 | 136 | Chasm region |
| esv::ChasmSeederTrigger | 0x08 | 8 | Chasm seeder trigger |
| esv::CombatComponent | 0x8 | 8 |  |
| esv::CombatGroupMappingComponent | 0x8 | 8 |  |
| esv::CombatParticipantComponent | 0x30 | 48 |  |
| esv::ConstellationChildComponent | 0x8 | 8 |  |
| esv::ConstellationComponent | 0x40 | 64 | Constellation data |
| esv::ConstellationHelperComponent | 0x18 | 24 | Constellation helper |
| esv::CrimeAreaTrigger | 0x08 | 8 | Crime area trigger |
| esv::CrimeRegionTrigger | 0x80 | 128 | Crime region |
| esv::CrowdCharacterTrigger | 0x120 | 288 | Crowd character (largest!) |
| esv::CustomStatsComponent | 0x28 | 40 |  |
| esv::DarknessComponent | 0x68 | 104 |  |
| esv::DialogStateComponent | 0x38 | 56 |  |
| esv::DisplayNameListComponent | 0x28 | 40 | Name list |
| esv::Effect | 0x08 | 8 | Ptr to 0x70 (112b) malloc |
| esv::EocAreaTrigger | 0x78 | 120 | EOC area |
| esv::EocLevelComponent | 0x4 | 4 |  |
| esv::EocPointTrigger | 0x78 | 120 | EOC point |
| esv::EventTrigger | 0x80 | 128 | Event trigger |
| esv::ExperienceComponent | 0x8 | 8 |  |
| esv::ExplorationAwardStateComponent | 0x10 | 16 | Exploration awards |
| esv::ExplorationTrigger | 0x90 | 144 | Exploration |
| esv::FloorTrigger | 0x80 | 128 | Floor trigger |
| esv::FollowersComponent | 0x4 | 4 |  |
| esv::GameMasterComponent | 0x40 | 64 |  |
| esv::GameTimerComponent | 0x28 | 40 | Has invoke function |
| esv::GameplayLightEquipmentComponent | 48 | GetComponent | `* 0x30` = 48 bytes |
| esv::GravityActiveTimeoutComponent | 0x4 | 4 |  |
| esv::GravityInstigatorComponent | 0x1 | 1 |  |
| esv::HealthComponent | 0x10 | 16 |  |
| esv::IconListComponent | 0x10 | 16 | Icon list |
| esv::IdentifiedComponent | 0x18 | 24 |  |
| esv::InterruptDataComponent | 0x10 | 16 |  |
| esv::InterruptPreferencesComponent | 0x8 | 8 |  |
| esv::InterruptZoneParticipantComponent | 0x8 | 8 |  |
| esv::InventoryDataComponent | 0x20 | 32 |  |
| esv::InventoryMemberComponent | 0x10 | 16 |  |
| esv::InventoryOwnerComponent | 0x10 | 16 |  |
| esv::InventoryPropertyCanBePickpocketedComponent | 0x18 | 24 |  |
| esv::InventoryPropertyIsDroppedOnDeathComponent | 0x18 | 24 |  |
| esv::InventoryPropertyIsTradableComponent | 0x18 | 24 |  |
| esv::IsGlobalComponent | 0x4 | 4 |  |
| esv::IsMarkedForDeletionComponent | 0x01 | 1 | Deletion flag |
| esv::Item | 0x08 | 8 | Ptr to 0xb0 (176b) malloc |
| esv::ItemComponent | 0x18 | 24 |  |
| esv::JumpFollowComponent | 0x150 | 336 | Jump follow (large!) |
| esv::LeaderComponent | 48 |  |  |
| esv::LevelComponent | 0x4 | 4 |  |
| esv::LightingTrigger | 0x90 | 144 | Lighting |
| esv::LockComponent | 0x28 | 40 |  |
| esv::MusicVolumeTrigger | 0x88 | 136 | Music volume |
| esv::MusicVolumeTriggerStateComponent | 0x10 | 16 | Music trigger state |
| esv::NetComponent | 0x01 | 1 | Network flag |
| esv::OriginalTemplateComponent | 0x4 | 4 |  |
| esv::OsirisPingRequestSingletonComponent | 16 (0x10) | Struct analysis | Array<PingRequestData> = 16 bytes |
| esv::PartyMemberComponent | 0x4 | 4 |  |
| esv::PerItemSpellSourceComponent | 16 |  |  |
| esv::PingCooldownSingletonComponent | 64 (0x40) | Struct analysis | HashMap<int16_t, float> = 64 bytes |
| esv::PingRequestSingletonComponent | 16 (0x10) | Struct analysis | Array<PingRequestData> = 16 bytes |
| esv::PlayerComponent | 0x10 | 16 |  |
| esv::PortalTrigger | 0x78 | 120 | Portal |
| esv::Projectile | 0x08 | 8 | Ptr to 0x5b8 (1464b) malloc |
| esv::RegionTrigger | 0x80 | 128 | Region |
| esv::ReplicationDependencyComponent | 0x1 | 1 |  |
| esv::RoomTrigger | 0x80 | 128 | Room |
| esv::SafePositionComponent | 0x10 | 16 | Safe position |
| esv::SafePositionUpdatedEventOneFrameComponent | 0x18 | 24 | Safe position updated |
| esv::SaveCompletedOneFrameComponent | 0x01 | 1 | Save completed event |
| esv::SaveWorldPrepareEventComponent | 0x01 | 1 | Save prepare event |
| esv::SaveWorldRequestComponent | 0x108 | 264 | Save world request (large!) |
| esv::SavegameComponent | 0x50 | 80 |  |
| esv::ScriptPropertyCanBePickpocketedComponent | 0x1 | 1 |  |
| esv::ScriptPropertyIsDroppedOnDeathComponent | 0x1 | 1 |  |
| esv::ScriptPropertyIsTradableComponent | 0x1 | 1 |  |
| esv::ServerDisplayNameListComponent | 0x4 | 4 |  |
| esv::ServerReplicationDependencyOwnerComponent | 0x1 | 1 |  |
| esv::ServerTimelineCreationConfirmationComponent | 88 |  |  |
| esv::ServerTimelineDataComponent | 24 |  |  |
| esv::ServerTimelineWorldCinematicComponent | 16 |  |  |
| esv::SetGravityActiveRequestOneFrameComponent | 0x10 | 16 | OneFrame component |
| esv::ShapeshiftCustomIconComponent | 0x58 | 88 | Has invoke function |
| esv::SightComponent | 0x60 | 96 |  |
| esv::SoundVolumeTrigger | 0xB0 | 176 | Sound volume (large!) |
| esv::StartTrigger | 0x08 | 8 | Start trigger ptr |
| esv::StatesComponent | 0x18 | 24 | States data |
| esv::StatusContainerComponent | 0x4 | 4 |  |
| esv::StealthComponent | 0x28 | 40 |  |
| esv::SummonContainerComponent | 0x18 | 24 |  |
| esv::SurfacePathInfluencesComponent | 0x18 | 24 |  |
| esv::TurnBasedComponent | 0x48 | 72 |  |
| esv::TurnOrderComponent | 0x80 | 128 |  |
| esv::TurnOrderSkippedComponent | 0x1 | 1 |  |
| esv::TurnEndedEventOneFrameComponent | 0x10 | 16 | OneFrame, TypeId: 0x1083f1810 |
| esv::TurnStartedEventOneFrameComponent | 0x10 | 16 | OneFrame, TypeId: 0x1083f1848 |
| esv::UseComponent | 0x28 | 40 |  |
| esv::UseSocketComponent | 0x10 | 16 |  |
| esv::UserReservedComponent | 0x18 | 24 |  |
| esv::VariableManagerComponent | 0x01 | 1 | Tag - variable manager |

**Total: 123 components**
