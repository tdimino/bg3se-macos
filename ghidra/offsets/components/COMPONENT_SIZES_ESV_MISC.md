# esv:: Miscellaneous Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::action_resource:: | 1 |  |  |
| esv::action_resource::CooldownTrackingComponent | 0x10 | 16 | Has invoke function |
| esv::action_resource::ResourcesOnLastCombatTurnComponent | 0x40 | 64 | Has invoke function |
| esv::active_roll:: | 1 |  |  |
| esv::active_roll::InProgressComponent | 0x18 | 24 |  |
| esv::approval::RatingsChangedOneFrameComponent | 0x30 | 48 |  |
| esv::background::GoalFailedOneFrameComponent | 0x18 | 24 |  |
| esv::background::GoalRecordedEventOneFrameComponent | 0x28 | 40 |  |
| esv::boost:: | 3 |  |  |
| esv::boost::ApplyRequestOneFrameComponent | 0x68 | 104 | Boost apply request |
| esv::boost::ApplyViaModRequestOneFrameComponent | 0x50 | 80 | Boost via mod request |
| esv::boost::ChangedEventOneFrameComponent | 0x10 | 16 | Boost changed event |
| esv::boost::DebugRequestsComponent | 16 | `<< 4` | 0x105121b64 |
| esv::boost::ProviderComponent | 0x20 | 32 | Boost provider |
| esv::boost::RemoveRequestOneFrameComponent | 0x30 | 48 | Boost remove request |
| esv::boost::StatusBoostsRefreshedOneFrameComponent | 0x10 | 16 | Status boosts refreshed |
| esv::boost::StoryRequestsComponent | 16 | `<< 4` | 0x10512227c |
| esv::combine::AddToInventoryRequestOneFrameComponent | 0x38 | 56 | Inventory add request |
| esv::combine::ResultOneFrameComponent | 0x30 | 48 | Combine result data |
| esv::combine::TransformedEntitiesOneFrameComponent | 0x30 | 48 | Transformed entities |
| esv::combine::UnlockRecipeOneFrameComponent | 0x30 | 48 | Recipe unlock |
| esv::concentration::OnConcentrationClearedEventOneFrameComponent | 0x18 | 24 | Concentration cleared |
| esv::darkness::DarknessActiveComponent | 0x01 | 1 |  |
| esv::dialog::ADRateLimitingDataComponent | 0x20 | 32 |  |
| esv::dialog::ADRateLimitingHistoryComponent | 0x40 | 64 |  |
| esv::drop:: | 1 |  |  |
| esv::drop::DropEntitiesListComponent | 0x10 | 16 |  |
| esv::drop::DropEntitiesToProcessComponent | 0x04 | 4 |  |
| esv::drop::DropEntityExecutionComponent | 0x20 | 32 |  |
| esv::drop::DropEntityStateComponent | 0x40 | 64 |  |
| esv::drop::DropEntityTargetComponent | 0x30 | 48 |  |
| esv::drop::DropFinishedEventComponent | 0x01 | 1 | Event |
| esv::exp::ExperienceGaveOutComponent | 0x04 | 4 | Experience given out |
| esv::falling:: | 3 |  |  |
| esv::falling::DataComponent | 0xc0 | 192 | Fall data (large!) |
| esv::history:: | 2 |  |  |
| esv::history::TargetUUIDComponent | 16 | 0x10 | GetComponent (shift << 4) |
| esv::hit::AnimationEventOneFrameComponent | 0x08 | 8 | Hit animation event |
| esv::hit::HitComponent | 0x158 | 344 |  |
| esv::hit::HitNotificationEventOneFrameComponent | 0x50 | 80 | Hit notification event |
| esv::hit::HitNotificationRequestOneFrameComponent | 0x48 | 72 | Hit notification request |
| esv::hit::HitResultEventOneFrameComponent | 0x1e8 | 488 | Hit result event (large!) |
| esv::hit::OnRollsResolvedEventOneFrameComponent | 0x18 | 24 | Rolls resolved event |
| esv::hit::RequestOneFrameComponent | 0x01 | 1 | Tag - hit request |
| esv::hit::UnresolvedHitNotificationComponent | 0x10 | 16 | Unresolved hit notification |
| esv::hotbar::OrderComponent | 0x01 | 1 | Hotbar order flag |
| esv::improvised_weapon::CancelRequestOneFrameComponent | 0x01 | 1 | Cancel request |
| esv::improvised_weapon::SetPositionOneFrameComponent | 0x18 | 24 | Set position event |
| esv::improvised_weapon::SetVisibilityOneFrameComponent | 0x01 | 1 | Set visibility event |
| esv::interrupt:: | 1 |  |  |
| esv::interrupt::ConditionalRollAdjustmentOneFrameComponent | 0x88 | 136 | Conditional roll adjustment |
| esv::interrupt::InitialParticipantsComponent | Not found | No GetComponent function |  |
| esv::interrupt::TurnOrderInZoneComponent | 48 | 0x30 | GetComponent (* 0x30) |
| esv::interrupt::ZoneRequestsComponent | esv::interrupt | Interrupt zone requests |  |
| esv::itemwall::AnimationComponent | 0x48 | 72 | Animation state |
| esv::itemwall::CreateComponent | 0xc8 | 200 | Create wall |
| esv::itemwall::CreateSurfaceCapsuleOneFrameComponent | 0x80 | 128 | OneFrame event |
| esv::itemwall::ForcePushRequestOneFrameComponent | 0x60 | 96 | OneFrame event |
| esv::itemwall::RequestSummonOneFrameComponent | 0x88 | 136 | OneFrame event |
| esv::level::InventoryItemDataPopulatedComponent | 0x01 | 1 | Tag component |
| esv::light::GameplayLightChangesComponent | Not found | No GetComponent function |  |
| esv::lock:: | 1 |  |  |
| esv::lock::ActiveRollRequestOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::lock::LockpickingStateComponent | 0x70 | 112 | Lockpicking state |
| esv::lock::NotificationEventOneFrameComponent | 0x18 | 24 | OneFrame event |
| esv::lock::StateChangeComponent | 0x01 | 1 | State change tag |
| esv::move::EnterAttackRangeEventOneFrameComponent | 0x20 | 32 | OneFrame event |
| esv::move::LeaveAttackRangeEventOneFrameComponent | 0x20 | 32 | OneFrame event |
| esv::one_time_reward::RewardListComponent | 0x10 | 16 | Reward list |
| esv::ownership:: | 9 |  |  |
| esv::ownership::IsCurrentOwnerComponent | 0x30 | 48 | Current owner |
| esv::ownership::IsLatestOwnerComponent | 0x30 | 48 | Latest owner |
| esv::ownership::IsOriginalOwnerComponent | 0x30 | 48 | Original owner |
| esv::ownership::IsPreviousOwnerComponent | 0x30 | 48 | Previous owner |
| esv::ownership::OwneeHistoryComponent | 0x18 | 24 | Ownership history |
| esv::ownership::OwneeRequestComponent | 0x30 | 48 | Ownership request |
| esv::party:: | 1 |  |  |
| esv::party::BlockDismissComponent | 0x01 | 1 | Tag component |
| esv::party::UserSnapshotComponent | 64 | 0x40 | AccessAddStorage, GetComponent |
| esv::patrol:: | 2 |  |  |
| esv::patrol::CaretComponent | 0x54 (84) |  |  |
| esv::photo_mode:: | 1 |  |  |
| esv::photo_mode::SessionFailedEventSingletonComponent | 0x1 (1) |  |  |
| esv::pickpocket:: | 1 |  |  |
| esv::pickpocket::PickpocketComponent | 0x10 | 16 | Pickpocket data |
| esv::pickup:: | 1 |  |  |
| esv::pickup::OriginalPickUpTargetComponent | 0x01 | 1 | Tag |
| esv::pickup::PickUpExecutionInFlightComponent | 0x08 | 8 | Execution in flight |
| esv::pickup::PickUpFinishedComponent | 0x01 | 1 | Tag |
| esv::pickup::PickUpPermissionComponent | 0x30 | 48 | Permission data |
| esv::pickup::PickUpPermissionGrantedComponent | 0x01 | 1 | Tag |
| esv::pickup::PickUpRequestComponent | 0x40 | 64 | Request data |
| esv::pickup::PickUpSplitListComponent | 0x10 | 16 | Split list |
| esv::placement:: | 1 |  |  |
| esv::placement::ValidationComponent | 0x3 (3) |  |  |
| esv::platform:: | 1 |  |  |
| esv::platform::MovementContinueComponent | 0x1 | 1 |  |
| esv::platform::MovementPausedReasonsComponent | 0x8 (8) |  |  |
| esv::platform::MovementRequestComponent | 0x38 | 56 |  |
| esv::projectile:: | 4 |  |  |
| esv::projectile::AttachmentComponent | 0x08 | 8 | Projectile attachment |
| esv::projectile::ImpactEventOneFrameComponent | ptr (8) |  |  |
| esv::projectile::InitializationComponent | Not found | No GetComponent function |  |
| esv::projectile::SpellComponent | 184 | 0xb8 | GetComponent @ 0x104cbeb88 |
| esv::recruit:: | 1 |  |  |
| esv::recruit::RecruitedByComponent | 8 | 0x8 | AccessAddStorage @ 0x1045d141c |
| esv::replication:: | 4 |  |  |
| esv::replication::IsReplicatedComponent | 0x01 | 1 | Tag - replicated |
| esv::replication::IsReplicatedWithComponent | 0x01 | 1 | Tag - replicated with |
| esv::replication::MemberIsReplicatedWithComponent | 0x01 | 1 | Tag - member replicated |
| esv::replication::PeersInRangeComponent | 16 (0x10) | Struct analysis | Array<int32_t> = 16 bytes |
| esv::replication::PrototypeModificationComponent | 0x10 | 16 | Prototype mods |
| esv::replication::ReplicationDependencyComponent | 0x08 | 8 | Replication dep |
| esv::replication::ReplicationDependencyOwnerComponent | 0x10 | 16 | Replication owner |
| esv::repose:: | 1 |  |  |
| esv::repose::UsedEntitiesToCleanSingletonComponent | 0x30 (48) |  |  |
| esv::rest::PendingTypeComponent | 0x48 | 72 | Pending rest type |
| esv::rest::RestCancelledEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::rest::RestFinishedEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::rest::RestTypeChosenEventOneFrameComponent | 0x50 | 80 | Type chosen event |
| esv::rest::RestTypeRequestOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::rest::ScriptPhaseStartedEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::rest::ScriptRestConfirmedEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::rest::StartRequestFailedEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::rest::UserCharacterRestedEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::restore::RestorePartyEventOneFrameComponent | 0x10 | 16 |  |
| esv::reward::FillRewardInventoriesRequestComponent | 0x80 | 128 |  |
| esv::reward::GiveRewardRequestComponent | 0x10 | 16 |  |
| esv::reward::TransferRewardsRequestComponent | 0x40 | 64 |  |
| esv::roll::stream::StreamsComponent | 40 | 0x28 | AccessAddStorage |
| esv::savegame::LoadComponent | 0x01 | 1 | Tag - savegame load |
| esv::script::light::LitComponent | 0x1 | 1 |  |
| esv::shapeshift:: | 3 |  |  |
| esv::shapeshift::AnubisStateComponent | 0x20 | 32 |  |
| esv::shapeshift::HealthReservationComponent | 64 | GetComponent | `>> 10 & 0x3fffc0` pattern = 64 bytes |
| esv::shapeshift::StatesComponent | 0x18 | 24 | Shapeshift states |
| esv::sight::EntityLosCheckQueueComponent | 0x70 | 112 | Entity LOS check queue |
| esv::sight::EntityLosCheckResultComponent | 0x30 | 48 | Entity LOS check result |
| esv::sight::LightLosCheckQueueComponent | 0x20 | 32 |  |
| esv::sound::PlayServerSoundRequestOneFrameComponent | 0x18 | 24 | OneFrame request |
| esv::spell:: | 3 |  |  |
| esv::spell::NewSpellsAddedEventOneFrameComponent | ptr (8) |  |  |
| esv::spell::OnDamageSpellsComponent | 0x10 | 16 | On-damage spells |
| esv::stats::LevelChangedOneFrameComponent | 0x10 | 16 | OneFrame, TypeId: 0x1083f2050 |
| esv::stats::proficiency::ProficiencyGroupStatsComponent | 4 (0x4) | Struct analysis | FixedString = 4 bytes |
| esv::steering:: | 2 |  |  |
| esv::surface::SurfaceComponent | esv::surface | Referenced in queries only |  |
| esv::tadpole_tree::AddedPowerOneFrameComponent | 0x10 | 16 | OneFrame event |
| esv::tadpole_tree::RemovedPowerOneFrameComponent | 0x10 | 16 | OneFrame event |
| esv::tags:: | 12 |  |  |
| esv::tags::AnubisTagComponent | 0x10 | 16 | Anubis tags |
| esv::tags::BoostTagComponent | 0x10 | 16 | Boost tags |
| esv::tags::DebugTagComponent | 0x10 | 16 | Debug tags |
| esv::tags::DialogTagComponent | 0x10 | 16 | Dialog tags |
| esv::tags::OsirisTagComponent | 0x10 | 16 | Osiris tags |
| esv::tags::RaceTagComponent | 0x10 | 16 | Race tags |
| esv::tags::TemplateTagComponent | 0x10 | 16 | Template tags (GUID array) |
| esv::teleport:: | 3 |  |  |
| esv::teleport::FinishedEventOneFrameComponent | 0x20 | 32 | Teleport finished event |
| esv::teleport::HasTargetOverrideComponent | 0x08 | 8 | Target override |
| esv::teleport::SpellComponent | unknown | No GetComponent found |  |
| esv::timeline::ActorControlComponent | 0xb8 | 184 | Actor control (large!) |
| esv::timeline::BackgroundActorRequestOneFrameComponent | 0x28 | 40 | Background actor request |
| esv::timeline::InterruptActorComponent | 0x10 | 16 | Interrupt actor |
| esv::timeline::RemovedOneShotActorOneFrameComponent | 0x10 | 16 | Removed one-shot actor |
| esv::timeline::ScriptEventOneFrameComponent | 0x20 | 32 |  |
| esv::timeline::TimelineActorVisibilityOneFrameComponent | 0x1 | 1 |  |
| esv::timeline::TimelineBehaviorFlagModificationComponent | 0x01 | 1 | Flag modification |
| esv::timeline::TimelineFadeClearRequestOneFrameComponent | 0x8 | 8 |  |
| esv::trade:: | 1 |  |  |
| esv::trade::CanTradeSetComponent | 0x01 | 1 | Tag |
| esv::trade::LegacyCanTradeProcessedComponent | 0x01 | 1 | Tag |
| esv::trade::PresentTraderComponent | 0x01 | 1 | Tag |
| esv::trade::TraderHostileToAllPlayersComponent | 0x01 | 1 | Tag |
| esv::trade::TraderHostileToIndivPlayersComponent | 0x30 | 48 | Hostile to individuals |
| esv::trade::TraderMapMarkerLinkedWithComponent | 0x08 | 8 | Map marker link |
| esv::trap:: | 3 |  |  |
| esv::trap::DisarmAttemptComponent | 0x10 | 16 | Disarm attempt |
| esv::trap::DisarmResultEventOneFrameComponent | 0x18 | 24 | Disarm result event |
| esv::trap::DisarmingStateComponent | 0x58 | 88 | Disarming state (large) |
| esv::trap::NotificationEventOneFrameComponent | 0x18 | 24 | Notification event |
| esv::turn::SurfaceTeamSingletonComponent | 0x70 | 112 | Singleton (large) |
| esv::turn::SurfaceTrackingComponent | 0x30 | 48 | Surface tracking |
| esv::tutorial:: | 2 |  |  |
| esv::tutorial::ProfileEventDataComponent | 0x38 | 56 | Profile event data |
| esv::unsheath:: | 2 |  |  |
| esv::unsheath::DefaultComponent | 0x08 | 8 | Default unsheath |
| esv::unsheath::ScriptOverrideComponent | 0x10 | 16 | Script override |
| esv::uuid:: | 2 |  |  |
| esv::uuid::HistoryMappingComponent | 0x40 | 64 | Two HashTable structures |
| esv::uuid::HistoryTrackedComponent | 0x1 | 1 | Single byte/flag |
| esv::zone:: | 1 |  |  |
| esv::zone::SpellComponent | 128 | 0x80 | GetComponent @ 0x10500a3bc |
| esv::zone::StateComponent | 0x01 | 1 | Zone state |

**Total: 194 components**
