# Unified Component Database

Merged from all available sources:
- **Ghidra ARM64**: Direct decompilation of macOS BG3 binary (highest priority)
- **Windows BG3SE**: Estimated from C++ struct definitions (fallback)
- **TypeIds**: Registered component addresses (no size info)

## Statistics

| Metric | Count |
|--------|-------|
| Total components | 2652 |
| With Ghidra ARM64 size | 1571 (59.2%) |
| With Windows estimate | 702 (26.5%) |
| With any size info | 1730 (65.2%) |
| Missing sizes | 922 |
| Tag components | 163 |

## Coverage by Namespace

| Namespace | Total | Ghidra | Windows | Missing |
|-----------|-------|--------|---------|---------|
| ecl | 542 | 155 | 56 | 351 |
| ecs | 1 | 0 | 0 | 1 |
| eoc | 913 | 758 | 367 | 126 |
| esv | 889 | 512 | 222 | 298 |
| gui | 26 | 0 | 0 | 26 |
| ls | 263 | 130 | 57 | 118 |
| navcloud | 18 | 16 | 0 | 2 |

---

## ecl:: Components

| Component | Ghidra | Windows | TypeId | Source |
|-----------|--------|---------|--------|--------|
| ActivationCulledcomponent | - | - | 0x10889c4d8 | typeid |
| Activeturncomponent | 12 | - | 0x1088a5a58 | ghidra |
| AiSeederTrigger | 120 | - | - | ghidra |
| Aipathsurfacescomponent | - | - | 0x1088a0e38 | typeid |
| Aipathvisualcomponent | - | - | 0x1088a0e70 | typeid |
| Aipathvisualdatacomponent | - | - | 0x1088a0e80 | typeid |
| AtmosphereTrigger | 144 | - | - | ghidra |
| AttackRangeChangedcomponent | - | - | 0x1088930f0 | typeid |
| AttackRangeEffectscomponent | - | - | 0x1088872e8 | typeid |
| Basicgovisualfadeactiveview0Component | - | - | 0x10889b590 | typeid |
| Basicgovisualfadeactiveview1Component | - | - | 0x10889b580 | typeid |
| Basicgovisualfaderequestssingletoncomponent | - | - | 0x10889b4e0 | typeid |
| Basicgovisualfadeview0Component | - | - | 0x10889b320 | typeid |
| Basicgovisualfadeview1Component | - | - | 0x10889b330 | typeid |
| CameraArrivewatchercomponent | - | - | 0x1088a1638 | typeid |
| CameraBlockerTrigger | 120 | - | - | ghidra |
| CameraCameramodetrackersingletoncomponent | - | - | 0x1088a16b8 | typeid |
| CameraClearscreenfaderequestmanualoneframecomponent | - | - | 0x1088a2150 | typeid |
| CameraCombattargetcomponent | 24 | 8 | 0x1088a2578 | ghidra |
| CameraCombattargetrequestscomponent | 48 | - | 0x1088a20f0 | ghidra |
| CameraEnterphotomoderequestsingletoncomponent | - | - | 0x1088a5900 | typeid |
| CameraIsinselectormodecomponent (tag) | - | 1 | 0x1088a4410 | windows |
| CameraIsinselectorwhileinactivecomponent | - | - | 0x1088a2598 | typeid |
| CameraLockTrigger | 128 | - | - | ghidra |
| CameraPhotomodecamerabehaviorcomponent | - | - | 0x1088a5910 | typeid |
| CameraPhotomodecamerainputcomponent | - | - | 0x1088a56f8 | typeid |
| CameraPhotomodecameraoriginaltransformcomponent | - | - | 0x1088a5898 | typeid |
| CameraPhotomodecameratransformrequestssingletoncomponent | - | - | 0x1088a56d8 | typeid |
| CameraPhotomodedestructionrequestssingletoncomponent | - | - | 0x1088a58d0 | typeid |
| CameraPhotomodeexitscreenfadeclearrequestssingletoncomponent | - | - | 0x1088a58e0 | typeid |
| CameraPhotomodeexitscreenfadecreaterequestssingletoncomponent | - | - | 0x1088a58f0 | typeid |
| CameraPlatformtargetcomponent | - | - | 0x1088a5a78 | typeid |
| CameraScreenfadetorequestmanualoneframecomponent | - | - | 0x1088a2160 | typeid |
| CameraSelectormodecomponent | - | 1 | 0x1088ab838 | windows |
| CameraSpelltrackingcomponent (tag) | - | 1 | 0x1088ab858 | windows |
| CameraSplineClearscreenfaderequestmanualoneframecomponent | - | - | 0x1088a1fe8 | typeid |
| CameraSplineScreenfadetorequestmanualoneframecomponent | - | - | 0x1088a1ff8 | typeid |
| CameraTargetcomponent | - | 8 | 0x1088a2588 | windows |
| Character | 344 | - | - | ghidra |
| Character (no template) | 344 | - | - | ghidra |
| CharacterAssignedcomponent | - | - | 0x1088aa2a0 | typeid |
| CharacterCharacterupdateconfigcomponent | 12 | - | 0x1088a2ef0 | ghidra |
| CharacterCreationAccumulatedchangescomponent | - | - | 0x1088a50c8 | typeid |
| CharacterCreationAppearancecachecomponent | - | - | 0x1088a6090 | typeid |
| CharacterCreationBasedefinitioncomponent | - | - | 0x1088a60a0 | typeid |
| CharacterCreationCameracomponent | - | - | 0x1088a6060 | typeid |
| CharacterCreationChangeappearancedefinitioncomponent | - | - | 0x1088a2808 | typeid |
| CharacterCreationChangespreviewcomponent | - | - | 0x1088a60b0 | typeid |
| CharacterCreationClearscreenfaderequestcomponent | - | - | 0x1088a2930 | typeid |
| CharacterCreationCommandqueuecomponent | - | - | 0x1088a6050 | typeid |
| CharacterCreationCompaniondefinitioncomponent | - | - | 0x1088a3938 | typeid |
| CharacterCreationCurrentvisualcomponent | - | - | 0x1088a2c38 | typeid |
| CharacterCreationCustomiconstateexcomponent | - | - | 0x1088a3948 | typeid |
| CharacterCreationDefinitionstatecomponent | - | - | 0x1088a6070 | typeid |
| CharacterCreationDefinitionstateexcomponent | - | - | 0x1088a60c0 | typeid |
| CharacterCreationDummycomponent | - | - | 0x1088a7468 | typeid |
| CharacterCreationDummydefinitioncomponent | - | - | 0x1088a50d8 | typeid |
| CharacterCreationEquipmentvisualcomponent | - | - | 0x1088a2818 | typeid |
| CharacterCreationFullrespecdefinitioncomponent | - | - | 0x1088a3f50 | typeid |
| CharacterCreationIcondefinitioncomponent | - | - | 0x1088a50e8 | typeid |
| CharacterCreationLevelupdefinitioncomponent | - | - | 0x1088a50f8 | typeid |
| CharacterCreationPlayercamerachangedelaycomponent | - | - | 0x1088a2970 | typeid |
| CharacterCreationRandomappearancescomponent | - | - | 0x1088a2838 | typeid |
| CharacterCreationRandomcharacterscomponent | - | - | 0x1088a2828 | typeid |
| CharacterCreationRenderframevisibilityrequestscomponent | - | - | 0x1088a2738 | typeid |
| CharacterCreationScreenfadeplayeridmapsingletoncomponent | - | - | 0x1088a2940 | typeid |
| CharacterCreationScreenfadetorequestcomponent | - | - | 0x1088a2920 | typeid |
| CharacterCreationSessioncharactercomponent | - | - | 0x1088a2848 | typeid |
| CharacterCreationSessionstatecomponent | - | - | 0x1088a6030 | typeid |
| CharacterCreationStatemachinecomponent | - | - | 0x1088a6040 | typeid |
| CharacterCreationTargetvisualcomponent | - | - | 0x1088a2c48 | typeid |
| CharacterLightsRenderframevisibilityrequestscomponent | - | - | 0x10889c1d8 | typeid |
| CharacterRenderframevisibilityrequestscomponent | - | - | 0x1088a2ec0 | typeid |
| CharacterTradingcomponent | - | - | 0x1088ab790 | typeid |
| Characterattachtoscenefadeactiveview0Component | - | - | 0x1088a26a0 | typeid |
| Characterattachtoscenefadeactiveview1Component | - | - | 0x10889b570 | typeid |
| Characterattachtoscenefaderequestssingletoncomponent | - | - | 0x10889b4b0 | typeid |
| Characterattachtoscenefadeview0Component | - | - | 0x10889b3e0 | typeid |
| Characterattachtoscenefadeview1Component | - | - | 0x10889b460 | typeid |
| Charactercreationfadeactiveview0Component | - | - | 0x1088a2c58 | typeid |
| Charactercreationfadeactiveview1Component | - | - | 0x10889b560 | typeid |
| Charactercreationfaderequestssingletoncomponent | - | - | 0x1088a2c08 | typeid |
| Charactercreationfadeview0Component | - | - | 0x10889b340 | typeid |
| Charactercreationfadeview1Component | - | - | 0x10889b350 | typeid |
| Charactericonrequestcomponent | 432 | 96 | 0x1088a2e50 | ghidra |
| Charactericonresultcomponent | 88 | 8 | 0x1088a2e60 | ghidra |
| Characterlightcomponent | 24 | 24 | 0x10889a4e8 | ghidra |
| Characterlightsingletoncomponent | - | 16 | 0x10889a4d8 | windows |
| Characteroutofsightfadeactiveview0Component | - | - | 0x1088a2f60 | typeid |
| Characteroutofsightfadeactiveview1Component | - | - | 0x10889b550 | typeid |
| Characteroutofsightfaderequestssingletoncomponent | - | - | 0x1088a2f00 | typeid |
| Characteroutofsightfadeview0Component | - | - | 0x10889b3f0 | typeid |
| Characteroutofsightfadeview1Component | - | - | 0x10889b470 | typeid |
| CinematicArenaTrigger | 176 | - | - | ghidra |
| Clientrootlevelstartdialogreadycomponent | - | - | 0x1088aa390 | typeid |
| Clienttimelineactorcontrolcomponent | 40 | 40 | 0x1088a9d40 | ghidra |
| Clienttimelinecontrolcomponent | 136 | - | 0x1088a9d30 | ghidra |
| Combattimelinecreationcomponent | - | - | 0x1088aa1a0 | typeid |
| Combattimelinedatacomponent | 352 | - | 0x1088a9ea0 | ghidra |
| ContainerClosedexplorationsingletoncomponent | - | - | 0x10889a918 | typeid |
| ContainerOngoingexplorationcomponent | 16 | - | 0x1088a4bc0 | ghidra |
| Crowdfadeactiveview0Component | - | - | 0x10889b540 | typeid |
| Crowdfadeactiveview1Component | - | - | 0x10889b530 | typeid |
| Crowdfaderequestssingletoncomponent | - | - | 0x10889b480 | typeid |
| Crowdfadeview0Component | - | - | 0x10889b3d0 | typeid |
| Crowdfadeview1Component | - | - | 0x10889b450 | typeid |
| CrowdsProxycomponent | - | - | 0x10889ddf0 | typeid |
| CrowdsRenderframevisibilityrequestscomponent | - | - | 0x10889c1e8 | typeid |
| CrowdsSoundclustercomponent | - | - | 0x1088a3a98 | typeid |
| CrowdsSoundclusterfiltercomponent | - | - | 0x1088a39b8 | typeid |
| CrowdsSoundclusterrequestscomponent | - | - | 0x1088a39a8 | typeid |
| CrowdsSoundmembercomponent | - | - | 0x1088a3c10 | typeid |
| CrowdsSoundstatecomponent | - | - | 0x1088a3ab8 | typeid |
| CrowdsSoundstationcomponent | - | - | 0x1088a3a88 | typeid |
| CrowdsSoundstationrequestssingletoncomponent | - | - | 0x1088a6a78 | typeid |
| CrowdsSoundstationstatesingletoncomponent | - | - | 0x1088a3aa8 | typeid |
| CrowdsSoundvolumecomponent | 56 | - | 0x1088a3c00 | ghidra |
| CrowdsTransformrequestscomponent | - | - | 0x10889a9f8 | typeid |
| CullTrigger | 120 | - | - | ghidra |
| CustomdiceSelectedsingletoncomponent | - | - | 0x10889aab0 | typeid |
| Customicontexturecomponent | - | - | 0x10889c078 | typeid |
| Customportraittexturecomponent | - | - | 0x10889c088 | typeid |
| Customstatdefinitioncomponent | - | - | 0x10889ab58 | typeid |
| DeathDeathimpactcomponent | 24 | - | 0x1088a2690 | ghidra |
| DeathDelayedanimationtriggercomponent | - | - | 0x10889a4a0 | typeid |
| DeathDetachEffectRequestOneFrameComponent | 1 | - | - | ghidra |
| DeathSetvisualimmediaterequestoneframecomponent | 1 | - | 0x1088a2f70 | ghidra |
| DeathStatecomponent | 16 | - | 0x1088a5cfc | ghidra |
| DeathUpdatedeathvisualstimercomponent | - | - | 0x1088a2fb0 | typeid |
| Deatheffectcomponent | 8 | - | 0x10889b000 | ghidra |
| DetachedComponent | 4 | - | - | ghidra |
| DialogCharacterdialogueeventssingletoncomponent | - | - | 0x1088a3cc8 | typeid |
| DialogDialoginstancecomponent | - | - | 0x1088a3ce8 | typeid |
| DialogEndedeventssingletoncomponent | - | - | 0x1088a3ca8 | typeid |
| DialogNodeeventssingletoncomponent | - | - | 0x1088a3cd8 | typeid |
| DialogStartedeventssingletoncomponent | - | - | 0x1088a3cb8 | typeid |
| DifficultyCheckComponent | 72 | - | - | ghidra |
| DisabledEquipmentComponent | 1 | - | - | ghidra |
| DisarmableComponent | 24 | - | - | ghidra |
| DisplayNameComponent | 32 | - | - | ghidra |
| DummyAnimationstatecomponent | - | 8 | 0x1088a0fc8 | windows |
| DummyAvailableanimationscomponent | - | 32 | 0x10889ad80 | windows |
| DummyCharactervfxinitializationcomponent | - | 16 | 0x10889af08 | windows |
| DummyDummiescreatedsingletoncomponent | 64 | 64 | 0x10889ae28 | ghidra |
| DummyDummycomponent | 8 | 8 | 0x1088a1208 | ghidra |
| DummyEquipmentvisualsstatecomponent | - | 4 | 0x1088a2d58 | windows |
| DummyFootikstatecomponent | - | 16 | 0x1088a0fd8 | windows |
| DummyHasdummycomponent | 8 | 8 | 0x10889f678 | ghidra |
| DummyIscopyingfullposecomponent (tag) | - | 1 | 0x1088a11f8 | windows |
| DummyLoadedcomponent (tag) | - | 1 | 0x10889de20 | windows |
| DummyOriginaltransformcomponent | 48 | 8 | 0x10889dcf0 | ghidra |
| DummySpellvfxinitializationcomponent | - | 16 | 0x10889af18 | windows |
| DummySplattercomponent | - | 20 | 0x10889adb8 | windows |
| DummyStatusvfxinitializationcomponent | - | 64 | 0x10889af28 | windows |
| DummyStoredclothcomponent | - | 80 | 0x10889adf0 | windows |
| DummyTransformrequestssingletoncomponent | - | 128 | 0x10889aed0 | windows |
| DummyUnsheathcomponent | - | 16 | 0x10889b1f0 | windows |
| DummyVfxentitiescomponent | - | 80 | 0x10889d540 | windows |
| EffectHandlercomponent | 8 | 8 | 0x10889d524 | ghidra |
| EffectInitializedcomponent | - | - | 0x10889d550 | typeid |
| EocCameraBehavior | 64 | - | - | ghidra |
| EquipmentColormasktexturecomponent | - | - | 0x10889b178 | typeid |
| EquipmentVisualsdesiredstatecomponent | - | 64 | 0x10889b188 | windows |
| EquipmentVisualsvisibilitystatecomponent | - | 72 | 0x10889dc00 | windows |
| Equipmentvisualscomponent | 72 | 72 | 0x1088a7a98 | ghidra |
| Equipmentvisualsvfxtargetcomponent | - | - | 0x10889f608 | typeid |
| FadeTrigger | 128 | - | - | ghidra |
| FloorTrigger | 128 | - | - | ghidra |
| FtbTogglerequestcomponent | - | - | 0x10889bc40 | typeid |
| GameCameraBehavior | 600 | 608 | - | ghidra |
| GamestateStatesingletoncomponent | - | - | 0x1088a7598 | typeid |
| Gamestateloadsessioncomponent | - | - | 0x1088a0d18 | typeid |
| Gamestateunloadsessioncomponent | - | - | 0x1088a7cf0 | typeid |
| Groundmaterialcomponent | 2 | - | 0x1088a41d0 | ghidra |
| HighlightDatacomponent | - | - | 0x10889bf50 | typeid |
| HitHitvfxcomponent | 576 | - | 0x1088a4830 | ghidra |
| HitReactioncomponent | - | - | 0x1088a4840 | typeid |
| HoveringPlayerhoveredsurfacesingletoncomponent | - | - | 0x10889e278 | typeid |
| IgnoredComponent | 1 | - | - | ghidra |
| InSelectComponent | 1 | - | - | ghidra |
| InterruptPlayerdecisioncomponent | 64 | 64 | 0x10889c190 | ghidra |
| InventoryDeferredcharacterdropanimationcomponent | - | - | 0x1088a0f58 | typeid |
| InventoryShowinventoryrequestssingletoncomponent | - | - | 0x10889cba8 | typeid |
| InvisibilityVisibilitysetuprequestscomponent | - | - | 0x10889c1f8 | typeid |
| Invisibilityattachmentcomponent | 1 | - | 0x10889fa78 | ghidra |
| Invisibilityfadeactiveview0Component | - | - | 0x10889c288 | typeid |
| Invisibilityfadeactiveview1Component | - | - | 0x10889c278 | typeid |
| Invisibilityfaderequestssingletoncomponent | - | - | 0x10889c1c8 | typeid |
| Invisibilityfadeview0Component | - | - | 0x10889b3a0 | typeid |
| Invisibilityfadeview1Component | - | - | 0x10889b420 | typeid |
| Invisibilityfadingcomponent | 12 | - | 0x10889c268 | ghidra |
| Invisibilityvisualcomponent | 12 | - | 0x1088a9870 | ghidra |
| IsHoveredOverComponent | 1 | - | - | ghidra |
| Item | 112 | - | - | ghidra |
| Item (no template) | 8 | - | - | ghidra |
| ItemAnimationFallbacktimercomponent | - | - | 0x10889c4e8 | typeid |
| ItemAnimationPendingrequestcomponent | - | - | 0x10889c4a0 | typeid |
| ItemAnimationRequestcomponent | - | - | 0x10889c528 | typeid |
| ItemAnimationRequestsingletoncomponent | - | - | 0x10889c4f8 | typeid |
| ItemAnimationStatecomponent | 6 | - | 0x1088a4c24 | ghidra |
| ItemDestroyinghandledcomponent | - | - | 0x1088a4f38 | typeid |
| ItemRetrylinkdynphysicsrequestcomponent | - | - | 0x1088a4c60 | typeid |
| Itempreviewfadeactiveview0Component | - | - | 0x10889b520 | typeid |
| Itempreviewfadeactiveview1Component | - | - | 0x10889b510 | typeid |
| Itempreviewfaderequestssingletoncomponent | - | - | 0x1088a8768 | typeid |
| Itempreviewfadeview0Component | - | - | 0x10889b390 | typeid |
| Itempreviewfadeview1Component | - | - | 0x10889b410 | typeid |
| JumpLandeventoneframecomponent | - | - | 0x1088a44d0 | typeid |
| JumpTakeoffeventoneframecomponent | - | - | 0x1088a44c0 | typeid |
| LariannetTrackingblockeduserssingletoncomponent | - | - | 0x10889c7d0 | typeid |
| LariannetTrackingfriendssingletoncomponent | - | - | 0x10889c780 | typeid |
| LariannetTrackingjoinedlobbiessingletoncomponent | - | - | 0x10889c790 | typeid |
| LariannetTrackinglobbiesupdatedmemberssingletoncomponent | - | - | 0x10889c7a0 | typeid |
| LariannetTrackinglobbydeletedsingletoncomponent | - | - | 0x10889c7b0 | typeid |
| LariannetTrackingsingletoncomponent | - | - | 0x10889ce38 | typeid |
| LariannetTrackingunblockeduserssingletoncomponent | - | - | 0x10889c7e0 | typeid |
| LariannetTrackingupdatedlobbiessingletoncomponent | - | - | 0x10889c7c0 | typeid |
| LevelPresencecomponent | - | - | 0x1088a4c70 | typeid |
| LightbarHapticsLightbarcolorcomponent | - | - | 0x10889ca20 | typeid |
| LightbarHapticsLightbarsoundfallbackcomponent | - | - | 0x10889ca30 | typeid |
| LightbarHapticsLightbarsoundrequestssingletoncomponent | - | - | 0x1088a6b18 | typeid |
| LightbarHapticsLightbarsoundstatecomponent | - | - | 0x10889c9e8 | typeid |
| LightingTrigger | 144 | - | - | ghidra |
| MarkersAvailableportalcomponent | - | - | 0x10889ccf0 | typeid |
| MarkersAvailableportalssingletoncomponent | - | - | 0x10889ccc0 | typeid |
| MarkersPortalcandidatecomponent | - | - | 0x10889cda0 | typeid |
| MeshPreviewComponent | 88 | - | - | ghidra |
| ModConsolesinfosingletoncomponent | - | - | 0x10889d168 | typeid |
| ModModstatechangesingletoncomponent | - | - | 0x10889d018 | typeid |
| ModPendingreportssingletoncomponent | - | - | 0x10889da10 | typeid |
| ModRequestiteminfosingletoncomponent | - | - | 0x10889e6a0 | typeid |
| ModSyncrequestsingletoncomponent | - | - | 0x10889cde8 | typeid |
| ModValidationsingletoncomponent | - | - | 0x1088a3f98 | typeid |
| Moduleloadcomponent | - | - | 0x10889d408 | typeid |
| Moduleunloadcomponent | - | - | 0x10889d440 | typeid |
| MovementComponent | 24 | - | - | ghidra |
| MovementDashtransformrequestssingletoncomponent | - | - | 0x10889ac18 | typeid |
| MovementMsidlecomponent | - | - | 0x10889cbe0 | typeid |
| MultiplayerAttemptstojoinsingletoncomponent | - | - | 0x10889ad48 | typeid |
| MultiplayerDestroyplayerrequestssingletoncomponent | - | - | 0x10889e2d0 | typeid |
| MultiplayerDropinapprovedplayerssingletoncomponent | - | - | 0x10889f3c0 | typeid |
| MultiplayerMessageboxrequestssingletoncomponent | - | - | 0x1088a09a0 | typeid |
| NavigationCloudTrigger | 120 | - | - | ghidra |
| NotificationAcceptedcomponent | - | - | 0x1088a9ee0 | typeid |
| NotificationSeencomponent | - | - | 0x1088a9ef0 | typeid |
| ObjectInteractionComponent | 16 | - | - | ghidra |
| ObstructionRaycastresultssingletoncomponent | - | - | 0x10889d788 | typeid |
| ObstructionStopfadetimerview0Component | - | - | 0x10889d630 | typeid |
| ObstructionStopfadetimerview1Component | - | - | 0x10889d650 | typeid |
| Obstructionfadeactiveview0Component | - | - | 0x10889d640 | typeid |
| Obstructionfadeactiveview1Component | - | - | 0x10889d660 | typeid |
| Obstructionfaderequestssingletoncomponent | - | - | 0x10889d600 | typeid |
| Obstructionfadeview0Component | - | - | 0x10889b3b0 | typeid |
| Obstructionfadeview1Component | - | - | 0x10889b430 | typeid |
| Paperdollcomponent | 16 | 8 | 0x10889f688 | ghidra |
| PartyLoadedeventoneframecomponent | - | - | 0x10889d870 | typeid |
| PartyPartychangedeventoneframecomponent | - | - | 0x1088a09c0 | typeid |
| PathingComponent | 80 | - | - | ghidra |
| PhotoModeCameraoffsetcomponent | - | - | 0x1088a56e8 | typeid |
| PhotoModeCamerasavedtransformcomponent | - | - | 0x1088a5728 | typeid |
| PhotoModeCameratiltcomponent | - | - | 0x1088a5718 | typeid |
| PhotoModeCameratrackingcomponent | - | - | 0x1088a5708 | typeid |
| PhotoModeDummyanimationupdatesingletoncomponent | - | - | 0x10889dbc8 | typeid |
| PhotoModeDummyequipmentvisualupdatesingletoncomponent | - | - | 0x10889dc38 | typeid |
| PhotoModeDummysplatterupdatesingletoncomponent | - | - | 0x10889dca8 | typeid |
| PhotoModeDummytransformupdatesingletoncomponent | - | - | 0x10889dce0 | typeid |
| PhotoModeInvisibilityrequestsingletoncomponent | - | - | 0x10889dde0 | typeid |
| PhotoModeRequestedsingletoncomponent | - | - | 0x1088a3778 | typeid |
| PickingStateComponent | 1 | - | - | ghidra |
| PingHighlighttargetsingletoncomponent | - | - | 0x10889e060 | typeid |
| PingIsinselectorwhileinactivecomponent | - | - | 0x1088a5a38 | typeid |
| PingPlaysingletoncomponent | - | - | 0x10889e070 | typeid |
| PingTargetingsingletoncomponent | - | - | 0x1088a5a88 | typeid |
| PlatformDeadreckoningcomponent | - | - | 0x10889e1d8 | typeid |
| PlatformSoundcomponent | - | - | 0x10889e230 | typeid |
| PlatformSoundplayrequestbuscomponent | - | - | 0x1088a6aa8 | typeid |
| PlayerAssignmenthistorysingletoncomponent | - | - | 0x10889e400 | typeid |
| PlayerComponent | 1 | - | - | ghidra |
| PlayerManagementEventssingletoncomponent | - | - | 0x1088ab990 | typeid |
| PlayerManagementPlayeridtoplayerinputindexmappingsingletoncomponent | - | - | 0x1088a8520 | typeid |
| PlayerManagementPlayerswithrenderviewassignedsingletoncomponent | - | - | 0x10889f3f0 | typeid |
| PlayerManagementUsercomponent | - | - | 0x10889a948 | typeid |
| Playersintimelineglobalcomponent | - | - | 0x1088a9c90 | typeid |
| Playertargetentitychangedoneframecomponent | - | - | 0x1088a71c0 | typeid |
| PointSoundTrigger | 168 | - | - | ghidra |
| PointSoundTriggerDummy | 8 | - | - | ghidra |
| PointTrigger | 8 | - | - | ghidra |
| PortalTrigger | 8 | - | - | ghidra |
| PortraitPaintingPortraitpaintingcomponent | - | - | 0x10889e3c8 | typeid |
| Projectile | 576 | - | - | ghidra |
| ProjectileAttachmentcomponent | 8 | - | 0x10889fe20 | ghidra |
| ProjectileSpellcomponent | - | - | 0x10889f028 | typeid |
| RagdollSoundrequestbussingletoncomponent | - | - | 0x1088a5ea8 | typeid |
| RagdollUpdatelastgroundrequestsingletoncomponent | - | - | 0x1088a5ed8 | typeid |
| RegionTrigger | 8 | - | - | ghidra |
| RelationFactionchangedeventoneframecomponent | - | - | 0x10889e748 | typeid |
| RelationRelationchangedeventoneframecomponent | 8 | - | 0x10889e778 | ghidra |
| RollActiverolleventssingletoncomponent | - | - | 0x10889e8c8 | typeid |
| RollPassiverollsuccessoneframeeventcomponent | - | - | 0x1088a5d40 | typeid |
| RoomTrigger | 8 | - | - | ghidra |
| Roomtriggercharacterfadeactiveview0Component | - | - | 0x10889e9d8 | typeid |
| Roomtriggercharacterfadeactiveview1Component | - | - | 0x10889e9c8 | typeid |
| Roomtriggercharacterfaderequestssingletoncomponent | - | - | 0x10889e958 | typeid |
| Roomtriggercharacterfadeview0Component | - | - | 0x10889b3c0 | typeid |
| Roomtriggercharacterfadeview1Component | - | - | 0x10889b440 | typeid |
| Roomtriggerfadeactiveview0Component | - | - | 0x10889e9b8 | typeid |
| Roomtriggerfadeactiveview1Component | - | - | 0x10889e9a8 | typeid |
| Roomtriggerfaderequestssingletoncomponent | - | - | 0x10889e948 | typeid |
| Roomtriggerfadeview0Component | - | - | 0x10889b360 | typeid |
| Roomtriggerfadeview1Component | - | - | 0x10889b370 | typeid |
| SavegameIssavingcomponent | - | - | 0x1088a9b00 | typeid |
| SceneCameraBehavior | 264 | - | - | ghidra |
| Scenery | 64 | 72 | - | ghidra |
| ScreenFadeMoviefadeendrequestsingletoncomponent | - | - | 0x10889ed48 | typeid |
| ScreenFadeMoviefademovietoguidsingletoncomponent | - | - | 0x10889eb98 | typeid |
| ScreenFadeMoviefaderemovalcountdownsingletoncomponent | - | - | 0x10889eb88 | typeid |
| ScreenFadeMoviefaderequestsingletoncomponent | - | - | 0x10889ed38 | typeid |
| ScreenFadeScreenfadecomponent | - | - | 0x10889ecd8 | typeid |
| ScreenFadeScreenfadesyncsingletoncomponent | - | - | 0x1088a2980 | typeid |
| ScreenFadeScreenfadetimercomponent | - | - | 0x10889ece8 | typeid |
| ScreenFadeScreenfadevisualdatacomponent | - | - | 0x1088a4948 | typeid |
| ScriptPlayanimationcomponent | - | - | 0x1088a4c50 | typeid |
| SelectedComponent | 1 | - | - | ghidra |
| ServerControlledEffectDestroyRequestOneFrameComponent | 1 | - | - | ghidra |
| ServerControlledEffectForgetRequestOneFrameComponent | 1 | - | - | ghidra |
| Servercontrolledeffectattachedcomponent | - | - | 0x1088a6330 | typeid |
| Servercontrolledeffectcomponent | - | - | 0x1088a6320 | typeid |
| Servercontrolledeffectreferencecomponent | - | - | 0x1088a6310 | typeid |
| SoundAmbiencemixrtpceventrequestsingletoncomponent | - | - | 0x1088a6be8 | typeid |
| SoundAmbiencemixstatecomponent | - | - | 0x1088a6558 | typeid |
| SoundAutofoleydatacomponent | 8 | - | 0x1088a12d8 | ghidra |
| SoundAutofoleyparentcomponent | - | - | 0x1088a12c8 | typeid |
| SoundAutofoleysettingscomponent | - | - | 0x1088a12b8 | typeid |
| SoundCharacteractivationrequestscomponent | - | - | 0x1088a41a0 | typeid |
| SoundCharacterswitchdatacomponent | 120 | - | 0x1088a4400 | ghidra |
| SoundDistantsoundentitymapcomponent | - | - | 0x1088a6428 | typeid |
| SoundDistantsoundposteventrequestsingletoncomponent | - | - | 0x1088a6ad8 | typeid |
| SoundDistantsoundrequestbuscomponent | - | - | 0x1088a6bb8 | typeid |
| SoundDistantsoundsetsoundswitchrequestsingletoncomponent | - | - | 0x1088a6b78 | typeid |
| SoundDistantsoundstatetrackercomponent | 8 | - | 0x1088a7498 | ghidra |
| SoundFeatsoundrequestbuscomponent | - | - | 0x1088a3e00 | typeid |
| SoundFlagsoundrequestssingletoncomponent | - | - | 0x1088a3ea8 | typeid |
| SoundFootstepmixstatecomponent | - | - | 0x1088a68c8 | typeid |
| SoundHovermixstatecomponent | - | - | 0x1088a7190 | typeid |
| SoundItemactivationrequestscomponent | - | - | 0x1088a4f48 | typeid |
| SoundItemswitchdatacomponent | 64 | - | 0x1088a4f78 | ghidra |
| SoundListenerspatializationsingletoncomponent | - | - | 0x1088a7078 | typeid |
| SoundMixstatecomponent | - | - | 0x1088a72e0 | typeid |
| SoundMixstateposthudeventrequestssingletoncomponent | - | - | 0x1088a7300 | typeid |
| SoundMixstatertpcrequestssingletoncomponent | - | - | 0x1088a72f0 | typeid |
| SoundMusicrequestssingletoncomponent | - | - | 0x1088a5520 | typeid |
| SoundMusicstatesingletoncomponent | - | - | 0x1088a54f0 | typeid |
| SoundPhotomoderequestssingletoncomponent | - | - | 0x1088a6b48 | typeid |
| SoundPointandclicksoundrequestcomponent | - | - | 0x1088a67b8 | typeid |
| SoundPointandclicksoundstatecomponent | - | - | 0x1088a5d30 | typeid |
| SoundPointsoundcustommixradiuscomponent | - | - | 0x1088a6588 | typeid |
| SoundPreloadstatesingletoncomponent | - | - | 0x1088a7588 | typeid |
| SoundSneakstatesingletoncomponent | - | - | 0x1088a6520 | typeid |
| SoundSoundfinishedplayingeventoneframecomponent | - | - | 0x1088a6788 | typeid |
| SoundSpellimpactrequestbuscomponent | - | - | 0x1088a8490 | typeid |
| SoundSpellimpactstatecomponent | - | - | 0x1088a84c0 | typeid |
| SoundTagsoundrequestssingletoncomponent | - | - | 0x1088a9138 | typeid |
| SoundTagswitchdatacomponent | - | - | 0x1088a9178 | typeid |
| SoundTagswitchrequestssingletoncomponent | - | - | 0x1088a9148 | typeid |
| SoundTimelinesaveposthudeventrequestssingletoncomponent | - | - | 0x1088a9ad0 | typeid |
| SoundTimelinestatesingletoncomponent | - | - | 0x1088aa2b0 | typeid |
| SoundUipanelposthudrequestssingletoncomponent | - | - | 0x1088ab950 | typeid |
| SoundUipanelstatesingletoncomponent | - | - | 0x1088ab960 | typeid |
| SoundVolumeTrigger | 8 | - | - | ghidra |
| Soundattachmentcomponent | 16 | - | 0x1088a8e80 | ghidra |
| Soundattachmenttransformrequestscomponent | - | - | 0x1088a66a8 | typeid |
| SpectatorCameraBehavior | 136 | - | - | ghidra |
| SpectatorTrigger | 8 | - | - | ghidra |
| SpellCastCachecomponent | - | - | 0x1088a8b30 | typeid |
| SpellCastCachedanimationrequestscomponent | - | - | 0x1088a7bb0 | typeid |
| SpellCastEffectscomponent | - | - | 0x1088a7b60 | typeid |
| SpellCastEffecttimefactorrequestssingletoncomponent | - | - | 0x1088a79d0 | typeid |
| SpellCastInterruptpauserequestscomponent | - | - | 0x1088a7b70 | typeid |
| SpellCastMovementcomponent | - | - | 0x1088a7cd0 | typeid |
| SpellCastPlaysoundrequestoneframecomponent | - | - | 0x1088a7b20 | typeid |
| SpellCastRollscomponent | - | - | 0x1088a7b50 | typeid |
| SpellCastSetsoundswitchesrequestoneframecomponent | - | - | 0x1088a7b30 | typeid |
| SpellCastSharedtocliententitycomponent | - | - | 0x1088a7be0 | typeid |
| SpellCastSoundimpacteventoneframecomponent | - | - | 0x1088a84f0 | typeid |
| SpellCastSoundscomponent | - | - | 0x1088a7ba0 | typeid |
| SpellCastStatecomponent | - | - | 0x1088a9408 | typeid |
| SpellCastTargetingcomponent | - | - | 0x1088a8b40 | typeid |
| SpellCastTempsoundeventrequestsoneframecomponent | - | - | 0x1088a7b40 | typeid |
| SpellCastZonerangecomponent | - | - | 0x1088a7cb0 | typeid |
| SpellPreviewEffectscomponent | - | - | 0x1088a8b50 | typeid |
| SpellPreviewForcecomponent | - | - | 0x1088a87b8 | typeid |
| SpellPreviewHighlightscomponent | - | - | 0x1088a8798 | typeid |
| SpellPreviewProjectilepathcomponent | - | - | 0x1088a8b20 | typeid |
| SpellPreviewSurfacetilescomponent | - | - | 0x1088a87a8 | typeid |
| SpellPreviewTargetingcomponent | - | - | 0x1088a8b60 | typeid |
| SplitscreenAnimationsingletoncomponent | - | - | 0x1088a34c0 | typeid |
| SplitscreenFullscreenturnactivecomponent | 4 | - | 0x1088a7d50 | ghidra |
| SplitscreenGoalsingletoncomponent | - | - | 0x1088a2120 | typeid |
| SplitscreenHeightsplitreasonssingletoncomponent | - | - | 0x1088a18c8 | typeid |
| SplitscreenLetterboxsingletoncomponent | - | - | 0x1088a17c8 | typeid |
| SplitscreenMergedfocussingletoncomponent | - | - | 0x1088a7d20 | typeid |
| SplitscreenPlayerssingletoncomponent | - | - | 0x1088a9ce0 | typeid |
| SplitscreenRequestcountssingletoncomponent | - | - | 0x1088a1848 | typeid |
| SplitscreenRequestssingletoncomponent | - | - | 0x1088a1868 | typeid |
| SplitscreenSelectedanimationsingletoncomponent | - | - | 0x1088a2190 | typeid |
| SplitscreenSoundcamerasingletoncomponent | - | - | 0x1088a7098 | typeid |
| SplitscreenSplitreasonssingletoncomponent | - | - | 0x1088a18a8 | typeid |
| SplitscreenSplittimersingletoncomponent | - | - | 0x1088a1828 | typeid |
| SplitscreenViewsingletoncomponent | - | - | 0x1088a9770 | typeid |
| StatusSpellsoundstaterequestssingletoncomponent | - | - | 0x1088a8cd0 | typeid |
| StatusvisualFadecomponent | - | - | 0x10889f800 | typeid |
| Stealthvfxcomponent | - | - | 0x10889f838 | typeid |
| SteeringSssteercomponent | - | - | 0x1088a2f50 | typeid |
| SummonAnimationrequestcomponent | - | - | 0x1088a4c40 | typeid |
| Surfaceinstancegrouptagcomponent | - | - | 0x10889f8e0 | typeid |
| Surfacelightcomponent | 64 | - | 0x10889f874 | ghidra |
| SyncedTimelineControlComponent | 248 | - | - | ghidra |
| TLPreviewDummy | 8 | 232 | - | ghidra |
| TadpoleTreeStatepowercontainercomponent | - | - | 0x10889fb38 | typeid |
| TagSpellcheckedtagcomponent | 1 | - | 0x10889fc98 | ghidra |
| TerrainWalkableAreaComponent | 80 | - | - | ghidra |
| ThrownCurrentrotationcomponent | - | - | 0x10889fde8 | typeid |
| ThrownDummyattachmentcomponent | 8 | - | 0x1088a8b70 | ghidra |
| ThrownSoundrequestbuscomponent | - | - | 0x1088a93d8 | typeid |
| ThrownThrownsoundcomponent | - | - | 0x1088a9428 | typeid |
| TimeTemporarypausecomponent | - | - | 0x10888e668 | typeid |
| TimelineActivateeventcamerarequestcomponent | - | - | 0x1088aa250 | typeid |
| TimelineActivemainmenutriggercomponent | - | - | 0x1088aa170 | typeid |
| TimelineActorparticipationsingletoncomponent | - | - | 0x1088a95a0 | typeid |
| TimelineArenacomponent | - | - | 0x1088aa150 | typeid |
| TimelineArenatriggerhasplayerscomponent | 4 | - | 0x1088aa130 | ghidra |
| TimelineGlobalactiveeventcomponent | - | - | 0x1088aa1b0 | typeid |
| TimelineGlobaleventfrequencycomponent | - | - | 0x10889a678 | typeid |
| TimelineGlobalrunthothcomponent | - | - | 0x1088a1398 | typeid |
| TimelineGlobalthothcomponent | - | - | 0x10889a6a8 | typeid |
| TimelineGlobalthothresultcomponent | - | - | 0x1088a13c8 | typeid |
| TimelineLoadedmainmenutriggercomponent | - | - | 0x1088a5278 | typeid |
| TimelineMainmenuactiveeventcomponent | - | - | 0x1088aa240 | typeid |
| TimelineMainmenuactorcomponent | - | - | 0x1088aa2e0 | typeid |
| TimelineOnlevelloadedtimelinesplayingcomponent | - | - | 0x1088a5298 | typeid |
| TimelinePlayedmainmenutriggercomponent | - | - | 0x1088a5288 | typeid |
| TimelineRenderframevisibilityrequestscomponent | - | - | 0x1088aa0e0 | typeid |
| TimelineSceneTrigger | 8 | - | - | ghidra |
| TimelineTimelinefadetransitionsingletoncomponent | - | - | 0x1088a9eb0 | typeid |
| TimelineTimelineloadedcomponent | - | - | 0x1088aa160 | typeid |
| Timelineactorvisibilityswapsingletoncomponent | - | - | 0x1088a9d70 | typeid |
| Timelineanimationstatecomponent | 8 | - | 0x1088aa0d0 | ghidra |
| Timelineautomatedlookatcomponent | 32 | - | 0x1088aa0b0 | ghidra |
| Timelinecamerarequestcomponent | 32 | - | 0x1088a9e90 | ghidra |
| Timelinecamerashotcomponent | 104 | - | 0x1088aa270 | ghidra |
| Timelinedummyanimationthrottlesingletoncomponent | - | - | 0x1088a9840 | typeid |
| Timelineemotionmaterialcomponent | 144 | - | 0x1088a8e48 | ghidra |
| Timelineeyelookatoverridecomponent | 48 | - | 0x1088aa0c0 | ghidra |
| Timelinefadeactiveview0Component | - | - | 0x1088aa340 | typeid |
| Timelinefadeactiveview1Component | - | - | 0x1088aa350 | typeid |
| Timelinefaderequestssingletoncomponent | - | - | 0x1088a9d60 | typeid |
| Timelinefadeview0Component | - | - | 0x10889b380 | typeid |
| Timelinefadeview1Component | - | - | 0x10889b400 | typeid |
| Timelinematerialcomponent | 128 | - | 0x1088aa090 | ghidra |
| Timelineongoingscreenfadescomponent | - | - | 0x1088a9da0 | typeid |
| Timelineplaceholderdummycomponent | - | - | 0x1088aa260 | typeid |
| Timelinequestionholdautomationcomponent | 28 | - | 0x1088aa280 | ghidra |
| Timelineshapeshiftcomponent | 4 | - | 0x1088aa080 | ghidra |
| Timelinesplattercomponent | 36 | - | 0x1088a9058 | ghidra |
| Timelinesplitscreenprioritycomponent | - | - | 0x1088a9f20 | typeid |
| Timelinespringscomponent | 8 | - | 0x1088aa110 | ghidra |
| Timelinesteppingfadecomponent | 8 | - | 0x1088aa0a0 | ghidra |
| Timelinetransformcomponent | 280 | - | 0x1088aa310 | ghidra |
| Timelinetransformflushsingletoncomponent | - | - | 0x1088ab608 | typeid |
| TriggerSighthelpercomponent | 1 | - | 0x1088a3dc0 | ghidra |
| TurnActionsDoneOneFrameComponent | 1 | - | - | ghidra |
| TurnBasedComponent | 48 | - | - | ghidra |
| TutorialCameraatleashlimitcomponent | - | - | 0x1088a06e0 | typeid |
| TutorialCameramovingcomponent | - | - | 0x1088a06f0 | typeid |
| TutorialCamerarotatingcomponent | - | - | 0x1088a0700 | typeid |
| TutorialCameratrackingcomponent | - | - | 0x1088a0710 | typeid |
| TutorialUilayercomponent | - | - | 0x1088a08a0 | typeid |
| UiMessageboxresponseeventoneframecomponent | - | - | 0x1088a0a10 | typeid |
| UiPadcursorvisiblecomponent | - | - | 0x1088ab848 | typeid |
| Uiframeidsingletoncomponent | - | - | 0x1088a0c20 | typeid |
| UnsheathVisualstatecomponent | 8 | - | 0x1088a7a88 | ghidra |
| UseComponent | 80 | - | - | ghidra |
| VoiceComponent | 24 | - | - | ghidra |
| WalkableSurfaceComponent | 16 | - | - | ghidra |
| WeaponComponent | 80 | - | - | ghidra |
| BaseDefinitionComponent | - | 8 | - | windows |
| ChangeAppearanceDefinitionComponent | - | 8 | - | windows |
| ChangesPreviewComponent | 8 | - | - | ghidra |
| CommandQueueComponent | 32 | - | - | ghidra |
| CompanionDefinitionComponent | - | 104 | - | windows |
| DefinitionStateComponent | 200 | 16 | - | ghidra |
| DefinitionStateExComponent | 40 | 32 | - | ghidra |
| DummyComponent | 24 | - | - | ghidra |
| DummyDefinitionComponent | 432 | 136 | - | ghidra |
| FullRespecDefinitionComponent | 168 | 64 | - | ghidra |
| LevelUpDefinitionComponent | - | 8 | - | windows |
| SessionStateComponent | 40 | - | - | ghidra |
| TargetVisualComponent | 240 | - | - | ghidra |
| BlockAfterGroupPrepareComponent | 1 | - | - | ghidra |
| DialogTimelineUpdateStateComponent | 4 | - | - | ghidra |
| IsInDialogComponent | 1 | - | - | ghidra |
| DistributorTrackerComponent | 136 | - | - | ghidra |
| InfluenceTrackerComponent | 96 | - | - | ghidra |
| InteractionEventOneFrameComponent | 40 | - | - | ghidra |
| SharedTimerComponent | 24 | - | - | ghidra |
| SpawnedComponent | 24 | - | - | ghidra |
| BlockedFTBToggleRequestOneFrameComponent | 4 | - | - | ghidra |
| ExamineInventoryComponent | 1 | - | - | ghidra |
| UsersComponent | 24 | - | - | ghidra |
| CameraOffsetComponent | - | 32 | - | windows |
| CameraSavedTransformComponent | - | 24 | - | windows |
| CameraTiltComponent | - | 8 | - | windows |
| CameraTrackingComponent | - | 8 | - | windows |
| DummyAnimationUpdateSingletonComponent | - | 64 | - | windows |
| DummyEquipmentSetupOneFrameComponent | - | 4 | - | windows |
| DummyEquipmentVisualUpdateSingletonComponent | - | 64 | - | windows |
| DummySplatterUpdateSingletonComponent | - | 64 | - | windows |
| DummyTransformUpdateSingletonComponent | - | 64 | - | windows |
| InvisibilityRequestSingletonComponent | - | 16 | - | windows |
| RequestedSingletonComponent | - | 1 | - | windows |
| UserComponent | 2 | - | - | ghidra |
| DecoratorSwitchDataComponent | 48 | - | - | ghidra |
| SoundCacheComponent | 40 | - | - | ghidra |
| CacheComponent | 96 | - | - | ghidra |
| CachedAnimationRequestsComponent | 112 | - | - | ghidra |
| MovementComponent | 20 | - | - | ghidra |
| PlaySoundRequestOneFrameComponent | 16 | - | - | ghidra |
| RollsComponent | 16 | - | - | ghidra |
| SetSoundSwitchesRequestOneFrameComponent | 16 | - | - | ghidra |
| SharedToClientEntityComponent | 8 | - | - | ghidra |
| SoundImpactEventOneFrameComponent | 80 | - | - | ghidra |
| SoundsComponent | 12 | - | - | ghidra |
| StateComponent | 168 | - | - | ghidra |
| TargetingComponent | 392 | - | - | ghidra |
| ZoneRangeComponent | 16 | - | - | ghidra |
| EffectsComponent | 8 | - | - | ghidra |
| ProjectilePathComponent | 24 | - | - | ghidra |
| SurfaceTilesComponent | 16 | - | - | ghidra |
| TargetingComponent | 56 | - | - | ghidra |
| PlayerTransitionEventOneFrameComponent | 64 | - | - | ghidra |
| TurnActionsDoneOneFrameComponent | 1 | - | - | ghidra |
| VisualFXViewComponent | 136 | - | - | ghidra |

---

## ecs:: Components

| Component | Ghidra | Windows | TypeId | Source |
|-----------|--------|---------|--------|--------|
| Isreplicationownedcomponent | - | - | 0x1089415f8 | typeid |

---

## eoc:: Components

| Component | Ghidra | Windows | TypeId | Source |
|-----------|--------|---------|--------|--------|
| Abilityboostcomponent | 16 | - | 0x108907868 | ghidra |
| Abilityfailedsavingthrowboostcomponent | 1 | - | 0x1088ede90 | ghidra |
| Abilityoverrideminimumboostcomponent | 12 | - | 0x108907878 | ghidra |
| Acoverrideformulaboostcomponent | 24 | - | 0x108907ac8 | ghidra |
| ActionActionuseconditionscomponent | 16 | 16 | 0x108905750 | ghidra |
| Actionresourceblockboostcomponent | 24 | - | 0x1088f0bf0 | ghidra |
| Actionresourceconsumemultiplierboostcomponent | 32 | - | 0x1088edeb0 | ghidra |
| Actionresourceeventsoneframecomponent | - | - | 0x10890f888 | typeid |
| Actionresourcemultiplierboostcomponent | 32 | - | 0x1088f0c10 | ghidra |
| Actionresourcepreventreductionboostcomponent | 24 | - | 0x1088edea0 | ghidra |
| Actionresourcereplenishtypeoverrideboostcomponent | 24 | - | 0x1088edec0 | ghidra |
| Actionresourcescomponent | 64 | 64 | 0x10890eb08 | ghidra |
| Actionresourcevalueboostcomponent | 40 | - | 0x1088f0c00 | ghidra |
| ActiveRollInprogresscomponent | - | - | 0x1089017a8 | typeid |
| ActiveRollModifierscomponent | - | - | 0x1088eca00 | typeid |
| Activecharacterlightboostcomponent | 4 | - | 0x1088eded0 | ghidra |
| Activecomponent | 1 | - | 0x108905780 | ghidra |
| Addtagboostcomponent | 16 | - | 0x1088edee0 | ghidra |
| Advancespellsboostcomponent | - | - | 0x108906078 | typeid |
| Advantageboostcomponent | 24 | - | 0x1089017e8 | ghidra |
| AiCombatRequestcameramovecomponent | 8 | - | 0x1088f0ca8 | ghidra |
| AiSwarmActivecomponent | 1 | - | 0x1088ebc00 | ghidra |
| AiSwarmDebugselectedcomponent | 24 | - | 0x1088eab38 | ghidra |
| AiSwarmDebugturnactionscomponent | 304 | - | 0x10888fb80 | ghidra |
| AiSwarmExecutingactioncomponent | 1 | - | 0x1088ebde0 | ghidra |
| AiSwarmMembercomponent | 4 | - | 0x10890e640 | ghidra |
| AiSwarmRequestcamerafollowgroupcomponent | 16 | - | 0x1088ebca8 | ghidra |
| Aiarchetypeoverrideboostcomponent | 8 | - | 0x1088edef0 | ghidra |
| AigridAffectedbylayerheightchangeoneframecomponent | - | - | 0x1088f8c08 | typeid |
| AigridCancelfloodrequestcomponent | - | - | 0x10888fc50 | typeid |
| AigridFloodrequestcomponent | - | - | 0x10888fc40 | typeid |
| AigridPrivateFloodrequeststatecomponent | - | - | 0x10888fc80 | typeid |
| AigridRefreshalllayersoneframerequestcomponent | 1 | - | 0x1088e2998 | ghidra |
| AigridSubgridproximityforcerefreshrequestcomponent | - | - | 0x10888e710 | typeid |
| AigridSubgridproximitylistcomponent | - | - | 0x10889ef48 | typeid |
| AigridSubgridproximitylistenercomponent | - | - | 0x108889010 | typeid |
| AmbushAmbushingcomponent (tag) | 1 | 1 | 0x1088dfb88 | ghidra |
| AnalyticsDestinationcomponent | - | - | 0x1088fe8b0 | typeid |
| AnalyticsEventapprovalratingcomponent | 64 | - | 0x1088f4d68 | ghidra |
| AnalyticsEventcombatstartedcomponent | 88 | - | 0x1088f4c78 | ghidra |
| AnalyticsEventcombatturncomponent | 96 | - | 0x1088f4c88 | ghidra |
| AnalyticsEventdisturbanceinvestigatedcomponent | 24 | - | 0x1088f4df8 | ghidra |
| AnalyticsEventdisturbanceresolvedcomponent | 24 | - | 0x1088f4e08 | ghidra |
| AnalyticsEventdisturbancestartedcomponent | 24 | - | 0x1088f4de8 | ghidra |
| AnalyticsEventftbstartedcomponent | 32 | - | 0x1088f4c98 | ghidra |
| AnalyticsEventglobalflagsetcomponent | 24 | - | 0x1088f4d28 | ghidra |
| AnalyticsEventgoalachievedcomponent | 32 | - | 0x1088f4cc8 | ghidra |
| AnalyticsEventgoldchangedcomponent | 16 | - | 0x1088f4d78 | ghidra |
| AnalyticsEventinterruptusedcomponent | 32 | - | 0x1088f4e58 | ghidra |
| AnalyticsEventinventoryaddedcomponent | 64 | - | 0x1088f4dd8 | ghidra |
| AnalyticsEventinventoryremovedcomponent | 48 | - | 0x1088f4dc8 | ghidra |
| AnalyticsEventitemcombinecomponent | 48 | - | 0x1088f4db8 | ghidra |
| AnalyticsEventitemusecomponent | 24 | - | 0x1088f4e78 | ghidra |
| AnalyticsEventlevelupendedcomponent | 104 | - | 0x1088f4cd8 | ghidra |
| AnalyticsEventosiriscomponent | 40 | - | 0x1088f4ce8 | ghidra |
| AnalyticsEventresttypeandsupplieschosencomponent | 56 | - | 0x1088f4e38 | ghidra |
| AnalyticsEventrollcomponent | 48 | - | 0x1088f4d18 | ghidra |
| AnalyticsEventsavegameerrorcomponent | 16 | - | 0x1088f4e68 | ghidra |
| AnalyticsEventspellusecomponent | 128 | - | 0x1088f4d38 | ghidra |
| AnimationBlueprintrefreshedeventoneframecomponent | 1 | - | 0x1089122c0 | ghidra |
| AnimationDooreventcachingsingletoncomponent | 192 | - | 0x1088ecc38 | ghidra |
| AnimationRefreshanimationrequestoneframecomponent | 16 | - | 0x1088e0068 | ghidra |
| ApprovalRatingscomponent | 112 | 112 | 0x1088fae98 | ghidra |
| ArmorSetStatecomponent | - | - | 0x1089024e0 | typeid |
| Armorabilitymodifiercapoverrideboostcomponent | 8 | - | 0x108907aa8 | ghidra |
| Armorclassboostcomponent | 4 | - | 0x108907ab8 | ghidra |
| Armorcomponent | 16 | 24 | 0x108912e40 | ghidra |
| Attackspelloverrideboostcomponent | 8 | - | 0x1088edf10 | ghidra |
| AttitudeAttitudestoplayerscomponent | 64 | 64 | 0x1089075c0 | ghidra |
| Attributeboostcomponent | 4 | - | 0x108906a90 | ghidra |
| Attributeflagscomponent | 4 | 4 | 0x108906d88 | ghidra |
| BackgroundGoalscomponent | 64 | 64 | 0x1088eab28 | ghidra |
| Backgroundcomponent | 16 | 16 | 0x1089004e0 | ghidra |
| Backgroundpassivescomponent | - | 16 | 0x1088fcf08 | windows |
| Backgroundtagcomponent | - | 16 | 0x1088efd20 | windows |
| Basehpcomponent | 8 | 8 | 0x108907888 | ghidra |
| Basestatscomponent | 28 | 8 | 0x108907d48 | ghidra |
| Blockabilitymodifierfromaccomponent | - | 1 | 0x108907a98 | windows |
| Blockregainhpboostcomponent | 1 | - | 0x1088ef208 | ghidra |
| Bodytypecomponent | 2 | 2 | 0x1089075d0 | ghidra |
| Boostconditioncomponent | 8 | 8 | 0x1088ee250 | ghidra |
| Boostinfocomponent | 88 | 32 | 0x108907988 | ghidra |
| BoostsComponent | 832 | - | - | ghidra |
| Boostscontainercomponent | 16 | 16 | 0x108910000 | ghidra |
| Boundcomponent | 8 | 8 | 0x10890b808 | ghidra |
| CalendarDayspassedcomponent | 4 | 4 | 0x1088eab18 | ghidra |
| CalendarStartingdatecomponent | 8 | 8 | 0x1088e0760 | ghidra |
| CameraMovecomponent | 16 | - | 0x1088eab08 | ghidra |
| CameraSpellwaitcomponent | 4 | - | 0x1088dfd38 | ghidra |
| CampAvatarcontainercomponent | 1 | - | 0x1088f8e68 | ghidra |
| CampChestcomponent | 40 | 56 | 0x10890a908 | ghidra |
| CampEndthedaystatecomponent | 16 | 16 | 0x1088eaaf8 | ghidra |
| CampPresencecomponent (tag) | 1 | 1 | 0x10890c008 | ghidra |
| CampQualitycomponent | 8 | 8 | 0x1088f4e28 | ghidra |
| CampSettingscomponent | 8 | 8 | 0x1088ef288 | ghidra |
| CampSupplycomponent | 4 | 4 | 0x1088f4e48 | ghidra |
| CampTotalsuppliescomponent | 4 | 4 | 0x1088f4e18 | ghidra |
| Canbedisarmedcomponent | 2 | 2 | 0x1088ef1b8 | ghidra |
| Canbelootedcomponent | 2 | 2 | 0x1088f7a90 | ghidra |
| Candeflectprojectilescomponent | 2 | 2 | 0x1088ef1a8 | ghidra |
| Candoactionscomponent | 2 | 8 | 0x108905770 | ghidra |
| Candorestcomponent | 6 | 8 | 0x1088ef2c8 | ghidra |
| Caninteractcomponent | 4 | 16 | 0x1088fc060 | ghidra |
| Canmodifyhealthcomponent | 2 | 2 | 0x108909000 | ghidra |
| Canmovecomponent | 6 | 16 | 0x108903f10 | ghidra |
| Cannotharmcauseentityboostcomponent | 4 | - | 0x1088edf20 | ghidra |
| Canseethroughboostcomponent | 1 | - | 0x1088edf50 | ghidra |
| Cansensecomponent | 2 | 2 | 0x108904b80 | ghidra |
| Canshootthroughboostcomponent | 1 | - | 0x1088edf60 | ghidra |
| Canspeakcomponent | 2 | 2 | 0x1088fa4c0 | ghidra |
| Cantravelcomponent | 6 | 24 | 0x1088fac68 | ghidra |
| Cantriggerrandomcastscomponent (tag) | 1 | 1 | 0x1088ef2b8 | ghidra |
| Canwalkthroughboostcomponent | 1 | - | 0x1088edf70 | ghidra |
| Carrycapacitymultiplierboostcomponent | 4 | - | 0x1088f3068 | ghidra |
| Changeuseboostscomponent | - | - | 0x108907a08 | typeid |
| CharacterCharactercomponent (tag) | 1 | 1 | 0x10890e248 | ghidra |
| CharacterCreationAppearancecomponent | - | - | 0x1089004f0 | typeid |
| CharacterCreationChangeappearancedefinitioncomponent | - | - | 0x1088ef780 | typeid |
| CharacterCreationCharacterdefinitioncomponent | - | - | 0x1088f1ee8 | typeid |
| CharacterCreationCompaniondefinitioncomponent | - | - | 0x1088f1ef8 | typeid |
| CharacterCreationDefinitionChangeappearancecomponent | - | - | 0x1088efd10 | typeid |
| CharacterCreationDefinitionCreationcomponent | - | - | 0x1088fc7e8 | typeid |
| CharacterCreationDefinitionFullrespeccomponent | - | - | 0x1088f4bd8 | typeid |
| CharacterCreationDefinitionHenchmencomponent | - | - | 0x1088f1ed8 | typeid |
| CharacterCreationDefinitionLevelupcomponent | - | - | 0x1088f9ee8 | typeid |
| CharacterCreationDefinitionRespeccomponent | - | - | 0x108900580 | typeid |
| CharacterCreationDefinitioncommoncomponent | - | - | 0x1089005b0 | typeid |
| CharacterCreationFullrespecdefinitioncomponent | - | - | 0x1088f4be8 | typeid |
| CharacterCreationLevelupcomponent | - | - | 0x108900500 | typeid |
| CharacterCreationLevelupdefinitioncomponent | - | - | 0x1088f9ef8 | typeid |
| CharacterCreationRespecdefinitioncomponent | - | - | 0x1089005c0 | typeid |
| CharacterCreationSessioncommoncomponent | - | - | 0x108900590 | typeid |
| CharacterCreationStatecomponent | - | - | 0x108900510 | typeid |
| CharacterEquipmentvisualcomponent | 1 | 1 | 0x1088e0fc8 | ghidra |
| CharacterTradingcomponent | 1 | - | 0x1088f79a8 | ghidra |
| Charactercreationstatscomponent | 88 | 88 | 0x108900520 | ghidra |
| Characterunarmeddamageboostcomponent | 40 | - | 0x1088edf30 | ghidra |
| Characterweapondamageboostcomponent | 40 | - | 0x1088edf40 | ghidra |
| ChasmCanenterchasmcomponent | 1 | 1 | 0x1088ef218 | ghidra |
| Classescomponent | 16 | 16 | 0x10890b098 | ghidra |
| Classtagcomponent | 16 | 16 | 0x1088efd50 | ghidra |
| Clientcontrolcomponent (tag) | 1 | 1 | 0x1089153c0 | ghidra |
| Climbingcomponent | 52 | - | 0x1089124a0 | ghidra |
| Closesttrackedsoundentitycomponent | - | - | 0x1088ab758 | typeid |
| CombatDelayedfanfarecomponent (tag) | 1 | 1 | 0x108912fe0 | ghidra |
| CombatInitiatordebugcomponent | 288 | - | 0x10888eb48 | ghidra |
| CombatIscombatpausedcomponent | 1 | - | 0x10890ea98 | ghidra |
| CombatIsincombatcomponent (tag) | 1 | 1 | 0x108912fd0 | ghidra |
| CombatIsthreatenedcomponent | 16 | 16 | 0x10890b818 | ghidra |
| CombatParticipantcomponent | 40 | 40 | 0x10890e9b8 | ghidra |
| CombatStatecomponent | 152 | 152 | 0x10890ea38 | ghidra |
| CombatThreatrangecomponent | 12 | 12 | 0x10890b6e8 | ghidra |
| Combinedlightcomponent | 64 | 32 | 0x1088f40a8 | ghidra |
| ConcentrationConcentrationcomponent | 80 | 8 | 0x108907450 | ghidra |
| Concentrationignoredamageboostcomponent | 1 | - | 0x1088edf80 | ghidra |
| ControllerFloodcomponent | - | - | 0x1088a38d8 | typeid |
| ControllerLocomotioncomponent | 132 | - | 0x1088ac510 | ghidra |
| ControllerNudgedatacomponent | 28 | - | 0x1088a3708 | ghidra |
| ControllerPhysicscomponent | - | - | 0x1088a38c8 | typeid |
| Criticalhitboostcomponent | 8 | - | 0x1088edf90 | ghidra |
| Criticalhitextradiceboostcomponent | 2 | - | 0x1088edfa0 | ghidra |
| CrowdsAppearancecomponent | 64 | - | 0x1088f2c00 | ghidra |
| CrowdsBehaviourcomponent | 1 | - | 0x1088f2980 | ghidra |
| CrowdsCharactercomponent | 16 | - | 0x1088f2b60 | ghidra |
| CrowdsCustomanimationcomponent | 4 | - | 0x1088f2098 | ghidra |
| CrowdsDeadreckoningcomponent | 20 | - | 0x1088f2140 | ghidra |
| CrowdsIsfadingcomponent | 1 | - | 0x1088f2c40 | ghidra |
| CrowdsProxycomponent | 8 | - | 0x1088f2be0 | ghidra |
| CrowdsProxydynamicanimationsetcomponent | 16 | - | 0x1088f2c30 | ghidra |
| CrowdsProxytransformcomponent | 16 | - | 0x1088fe8a0 | ghidra |
| CustomdiceUsersdicesingletoncomponent | 64 | - | 0x1088eaae8 | ghidra |
| Customiconcomponent | 96 | 16 | 0x1088e5750 | ghidra |
| Customiconsstoragesingletoncomponent | 64 | 64 | 0x1088f1f28 | ghidra |
| Customnamecomponent | 16 | 32 | 0x10890ce10 | ghidra |
| Customstatscomponent | 24 | 8 | 0x10889ab68 | ghidra |
| Damagebonusboostcomponent | 40 | - | 0x1088edfb0 | ghidra |
| Damagereductionboostcomponent | 56 | 24 | 0x108907a78 | ghidra |
| Damagetakenbonusboostcomponent | 40 | - | 0x1088edfc0 | ghidra |
| Darknesscomponent | 16 | 2 | 0x1088e7648 | ghidra |
| Darkvisionrangeboostcomponent | 4 | - | 0x1088edfd0 | ghidra |
| Darkvisionrangeminboostcomponent | 4 | - | 0x1088ef7d8 | ghidra |
| Darkvisionrangeoverrideboostcomponent | 4 | - | 0x1088edfe0 | ghidra |
| Datacomponent | 12 | 12 | 0x10890b088 | ghidra |
| Deadreckoningcomponent | 16 | - | 0x10889cc18 | ghidra |
| Deadreckoningsynccomponent | 20 | - | 0x1088e07a8 | ghidra |
| DeathDeadbydefaultcomponent | 1 | 1 | 0x1088f04b0 | ghidra |
| DeathDeathcomponent | 120 | - | 0x108912fc0 | ghidra |
| DeathDeathtypecomponent | 1 | 1 | 0x1089027c0 | ghidra |
| DeathDownedcomponent | 24 | 24 | 0x108912fb0 | ghidra |
| DeathStatecomponent | 4 | 4 | 0x1088f7a60 | ghidra |
| Detachedcomponent | 4 | 4 | 0x108905730 | ghidra |
| Detectcrimesblockboostcomponent | - | - | 0x1088ef020 | typeid |
| DialogDialogueprivacysingletoncomponent | 64 | - | 0x1088eaad8 | ghidra |
| DialogIslisteningsingletoncomponent | 64 | - | 0x1088fec40 | ghidra |
| DialogNoprivatedialogssingletoncomponent | 48 | - | 0x1088e0c68 | ghidra |
| DialogStatecomponent | 12 | 4 | 0x10890c018 | ghidra |
| Difficultycheckcomponent | 72 | 40 | 0x10890b078 | ghidra |
| Disabledequipmentcomponent | 1 | 1 | 0x1089078a8 | ghidra |
| Disarmablecomponent | 24 | 24 | 0x1088fbe40 | ghidra |
| Displaynamecomponent | 32 | - | 0x10890ce20 | ghidra |
| Dodgeattackrollboostcomponent | 12 | - | 0x1088edf00 | ghidra |
| Downedstatusboostcomponent | 8 | - | 0x1088edff0 | ghidra |
| DropAnimationcomponent | 1 | - | 0x1088ed100 | ghidra |
| DropDropentitystatecomponent | 1 | - | 0x1088e0e78 | ghidra |
| DropOriginaldroptargetcomponent | 8 | - | 0x1088e0e88 | ghidra |
| Dualwieldingboostcomponent | 1 | - | 0x1088ee000 | ghidra |
| Dualwieldingcomponent | 7 | 2 | 0x1089111c0 | ghidra |
| EncumbranceStatecomponent | 4 | 4 | 0x1088f3048 | ghidra |
| EncumbranceStatscomponent | 12 | - | 0x108907d38 | ghidra |
| Entitythrowdamageboostcomponent | 16 | - | 0x1088ee010 | ghidra |
| Equipablecomponent | 24 | 8 | 0x1089078f8 | ghidra |
| ExpAvailablelevelcomponent | 4 | 4 | 0x108907918 | ghidra |
| ExpCanlevelupcomponent (tag) | 1 | 1 | 0x1088f9ed8 | ghidra |
| ExpExperiencecomponent | 16 | 16 | 0x1088ef818 | ghidra |
| ExpertiseExpertisecomponent | 48 | 48 | 0x108909418 | ghidra |
| Expertisebonusboostcomponent | 1 | - | 0x1088ee020 | ghidra |
| Factionoverrideboostcomponent | 24 | - | 0x1088ee030 | ghidra |
| Falldamagemultiplierboostcomponent | 4 | - | 0x1088ee040 | ghidra |
| FallingIsfallingcomponent (tag) | 1 | 1 | 0x108912fa0 | ghidra |
| Fleecapabilitycomponent | 12 | 8 | 0x1088f47e8 | ghidra |
| Floatingcomponent | 8 | 8 | 0x1088ecbd8 | ghidra |
| FloorInfocomponent | 32 | - | 0x1088e1758 | ghidra |
| Fogvolumerequestcomponent | 16 | 16 | 0x1088e17e0 | ghidra |
| FtbIsftbpausedcomponent (tag) | - | 1 | 0x1088f4a08 | windows |
| FtbIsinftbcomponent (tag) | 1 | 1 | 0x1088f62b0 | ghidra |
| FtbParticipantcomponent | 8 | 8 | 0x10890ea68 | ghidra |
| FtbRespectcomponent | 1 | - | 0x10890dee8 | ghidra |
| FtbZoneblockreasoncomponent | 1 | 1 | 0x1088f49e8 | ghidra |
| GamePausecomponent | 1 | - | 0x1088eaac8 | ghidra |
| Gameobjectvisualcomponent | 20 | 20 | 0x1088fdc80 | ghidra |
| Gameovercomponent | - | - | 0x1088eaab8 | typeid |
| Gameplaylightboostcomponent | 16 | - | 0x1088ee060 | ghidra |
| Gameplaylightcomponent | - | 12 | 0x1088e19d8 | windows |
| Gameplayobscurityboostcomponent | - | - | 0x1088ee050 | typeid |
| GamestateAbortedcomponent | - | - | 0x10889bea8 | typeid |
| GamestateIdlingcomponent | - | - | 0x1088a9e00 | typeid |
| GamestateInitconnectioncomponent | - | - | 0x10889d048 | typeid |
| GamestateLoadmainmenucomponent | - | - | 0x1088a7558 | typeid |
| GamestateMainmenucomponent | - | - | 0x1088dfd70 | typeid |
| GamestateMainmenupostinstantiatecomponent | 1 | - | 0x1088a9dd0 | ghidra |
| GamestatePausedcomponent | 1 | - | 0x1089060c8 | ghidra |
| GamestatePreparerunningcomponent | - | - | 0x1088fd0c8 | typeid |
| GamestateRunningcomponent | 1 | - | 0x108911618 | ghidra |
| GamestateSavegameloadcomponent | 32 | - | 0x108914d00 | ghidra |
| GamestateSavingcomponent | - | - | 0x1088f2440 | typeid |
| GamestateSyncingcomponent | - | - | 0x1088ea1f8 | typeid |
| GamestateUnloadlevelcomponent | 1 | - | 0x10890cf68 | ghidra |
| GamestateUnloadmodulecomponent | 1 | - | 0x1088e1968 | ghidra |
| Globallongrestdisabledcomponent | 1 | - | 0x1088ef198 | ghidra |
| Globalshortrestdisabledcomponent | 1 | - | 0x1088ef188 | ghidra |
| GodGodcomponent | 40 | 24 | 0x1088faf68 | ghidra |
| GodTagcomponent | 16 | 16 | 0x1088e9298 | ghidra |
| Gravityactivecomponent | 8 | - | 0x1088e1da8 | ghidra |
| Gravitydisabledcomponent (tag) | 1 | 1 | 0x1088f8b48 | ghidra |
| Gravitydisableduntilmovedcomponent | 40 | 8 | 0x1088e1b98 | ghidra |
| Guaranteedchancerolloutcomeboostcomponent | 1 | - | 0x1088ee070 | ghidra |
| Halveweapondamageboostcomponent | 1 | - | 0x1088ee080 | ghidra |
| HealBlockcomponent (tag) | 1 | 1 | 0x1088e1c60 | ghidra |
| HealMaxincomingcomponent (tag) | 1 | 1 | 0x1088e1c40 | ghidra |
| HealMaxoutgoingcomponent (tag) | 1 | 1 | 0x1088e1c50 | ghidra |
| HealthRegenBoostComponent | 16 | - | - | ghidra |
| Healthcomponent | 40 | 32 | 0x10890a360 | ghidra |
| HearingBoostComponent | 4 | - | - | ghidra |
| Hearingcomponent | 4 | 4 | 0x108907908 | ghidra |
| HitAttackercomponent | - | 8 | 0x1088fe9c0 | windows |
| HitLifetimecomponent | 8 | 8 | 0x1088e1d58 | ghidra |
| HitMetacomponent | 16 | 16 | 0x1088f16d0 | ghidra |
| HitProxycomponent | 16 | 16 | 0x108904ba0 | ghidra |
| HitProxyownercomponent | 16 | 16 | 0x108903ef0 | ghidra |
| HitReactioncomponent | - | 64 | 0x1088e1d68 | windows |
| HitTargetcomponent | - | 24 | 0x1088fe9b0 | windows |
| HitThrownobjectcomponent | - | 8 | 0x1088fe9e0 | windows |
| HitWeaponcomponent | - | 8 | 0x1088fe9d0 | windows |
| Horizontalfovoverrideboostcomponent | 4 | - | 0x1088ee090 | ghidra |
| HotbarContainercomponent | 72 | 72 | 0x1088f3fc8 | ghidra |
| HotbarCurrentdeckscomponent | - | 64 | 0x1088f3fd8 | windows |
| Iconcomponent | 4 | 4 | 0x1088f3ed8 | ghidra |
| IdentityIdentitycomponent | 1 | 1 | 0x1088e92f8 | ghidra |
| IdentityOriginalidentitycomponent | 1 | 1 | 0x1088e21f0 | ghidra |
| IdentityStatecomponent | 1 | - | 0x1089075e0 | ghidra |
| Ignoredamagethresholdminboostcomponent | 4 | - | 0x108907a68 | ghidra |
| Ignorelowgroundpenaltyboostcomponent | 1 | - | 0x1088ee0a0 | ghidra |
| Ignorepointblankdisadvantageboostcomponent | 1 | - | 0x1088ee0b0 | ghidra |
| Ignoreresistanceboostcomponent | 24 | - | 0x1088ee0c0 | ghidra |
| Ignoresurfacecoverboostcomponent | 1 | - | 0x1088ee0d0 | ghidra |
| ImprovisedWeaponCanbewieldedcomponent | - | - | 0x1088e2228 | typeid |
| ImprovisedWeaponWieldedcomponent | - | - | 0x1088fcc30 | typeid |
| ImprovisedWeaponWieldingcomponent | - | - | 0x10890a3b0 | typeid |
| Increasemaxhpboostcomponent | 48 | 16 | 0x108907af8 | ghidra |
| Initiativeboostcomponent | 4 | - | 0x108907998 | ghidra |
| Interactionfiltercomponent | - | 56 | 0x1088f3f38 | windows |
| InterruptActionstatecomponent | 296 | 40 | 0x1089024a0 | ghidra |
| InterruptConditionallydisabledcomponent | 1 | 1 | 0x1088f5d58 | ghidra |
| InterruptContainercomponent | 16 | 16 | 0x1088fa440 | ghidra |
| InterruptDatacomponent | 32 | 8 | 0x108909950 | ghidra |
| InterruptDecisioncomponent | 64 | 64 | 0x1088f5d48 | ghidra |
| InterruptPreferencescomponent | 64 | 64 | 0x1088f5dc8 | ghidra |
| InterruptPreparedcomponent | 1 | 1 | 0x1088f5e80 | ghidra |
| InterruptZonecomponent | 16 | 16 | 0x1088f6260 | ghidra |
| InterruptZoneparticipantcomponent | 64 | 64 | 0x1088fc610 | ghidra |
| InterruptZonesourcecomponent | 1 | 1 | 0x1088f62c0 | ghidra |
| InventoryCanbeincomponent (tag) | 1 | 1 | 0x1088fe0e0 | ghidra |
| InventoryCannotbepickpocketedcomponent (tag) | 1 | 1 | 0x1088fad78 | ghidra |
| InventoryCannotbetakenoutcomponent (tag) | 1 | 1 | 0x108902320 | ghidra |
| InventoryContainercomponent | 64 | 64 | 0x108908f08 | ghidra |
| InventoryDatacomponent | 4 | - | 0x108903c38 | ghidra |
| InventoryDropondeathblockedcomponent (tag) | 1 | 1 | 0x1088fadb8 | ghidra |
| InventoryIslockedcomponent (tag) | 1 | 1 | 0x108905760 | ghidra |
| InventoryIsownedcomponent | 8 | 8 | 0x108903ca8 | ghidra |
| InventoryMembercomponent | 16 | 16 | 0x1089153b0 | ghidra |
| InventoryMembertransformcomponent | 40 | 8 | 0x1088f6f38 | ghidra |
| InventoryNewitemsinsidecomponent (tag) | 1 | 1 | 0x1088fa000 | ghidra |
| InventoryNontradablecomponent (tag) | 1 | 1 | 0x1088fad98 | ghidra |
| InventoryOwnercomponent | 24 | 24 | 0x108908ef8 | ghidra |
| InventoryStackcomponent | 32 | - | 0x1088fccb0 | ghidra |
| InventoryStackmembercomponent | 8 | 8 | 0x1088f7d88 | ghidra |
| InventoryTopownercomponent | 8 | 8 | 0x1088f7870 | ghidra |
| InventoryTradebuybackdatacomponent | 24 | 24 | 0x1088f79b8 | ghidra |
| InventoryWeightcomponent | 4 | 4 | 0x1088f76d8 | ghidra |
| InventoryWieldedcomponent | - | 16 | 0x1088f7c38 | windows |
| InventoryWieldinghistorycomponent | - | 16 | 0x1088fce98 | windows |
| Invisibilitycomponent | 20 | 24 | 0x10890d548 | ghidra |
| Isinturnbasedmodecomponent (tag) | 1 | 1 | 0x10890e088 | ghidra |
| ItemAnimationRequestcomponent | 4 | - | 0x1088f8188 | ghidra |
| ItemDestroyedcomponent | 12 | 8 | 0x1088f84f8 | ghidra |
| ItemDestroyingcomponent (tag) | 1 | 1 | 0x1088f87d0 | ghidra |
| ItemDoorcomponent (tag) | 1 | 1 | 0x1088f8c68 | ghidra |
| ItemDyecomponent | 16 | 16 | 0x1088f8700 | ghidra |
| ItemExaminedisabledcomponent (tag) | 1 | 1 | 0x1088f8c88 | ghidra |
| ItemHasmovedcomponent (tag) | 1 | 1 | 0x1088f8c58 | ghidra |
| ItemHasopenedcomponent (tag) | 1 | 1 | 0x1088fab28 | ghidra |
| ItemInusecomponent (tag) | 1 | 1 | 0x1088f8c38 | ghidra |
| ItemIsdoorclosedcomponent | 8 | - | 0x1088f8be8 | ghidra |
| ItemIsdoorclosingcomponent | 1 | - | 0x1088f8bd8 | ghidra |
| ItemIsdooropenedcomponent | 8 | - | 0x1088f8bc8 | ghidra |
| ItemIsdooropeningcomponent | 1 | - | 0x1088f8bb8 | ghidra |
| ItemIsfallingcomponent | 1 | - | 0x1088e20a0 | ghidra |
| ItemIsgoldcomponent (tag) | 1 | 1 | 0x1088f87f0 | ghidra |
| ItemIspoisonedcomponent (tag) | 1 | 1 | 0x1088f8c48 | ghidra |
| ItemIsrotatecomponent | 1 | - | 0x1088e20d8 | ghidra |
| ItemIsteleportfallcomponent | 1 | - | 0x1088e2110 | ghidra |
| ItemItemcomponent (tag) | 1 | 1 | 0x108914cb0 | ghidra |
| ItemMapmarkerstylecomponent | 4 | 4 | 0x1088f8e38 | ghidra |
| ItemNewininventorycomponent (tag) | 1 | 1 | 0x1088f9ff0 | ghidra |
| ItemPortalcomponent | 2 | 2 | 0x1088f8e28 | ghidra |
| ItemShoulddestroyonspellcastcomponent (tag) | 1 | 1 | 0x108904008 | ghidra |
| ItemTemplateActiontypecomponent | - | - | 0x108902050 | typeid |
| ItemTemplateCanmovecomponent | - | - | 0x108903f20 | typeid |
| ItemTemplateClimboncomponent | - | - | 0x1088f8c18 | typeid |
| ItemTemplateDestroyedcomponent | - | - | 0x108903f00 | typeid |
| ItemTemplateInteractiondisabledcomponent | - | - | 0x108903f30 | typeid |
| ItemTemplateIsstoryitemcomponent | - | - | 0x1088f8c78 | typeid |
| ItemTemplateLaddercomponent | - | - | 0x108904b90 | typeid |
| ItemTemplateScriptcontrolleddoorcomponent | - | - | 0x108902060 | typeid |
| ItemTemplateUseactioncomponent | - | - | 0x108902040 | typeid |
| ItemTemplateWalkoncomponent | - | - | 0x1088f8c28 | typeid |
| Itemboostscomponent | - | 16 | 0x108905f28 | windows |
| JumpInfocomponent | 32 | - | 0x108909220 | ghidra |
| JumpStatecomponent | 40 | - | 0x108912f90 | ghidra |
| Jumpmaxdistancebonusboostcomponent | 4 | - | 0x1088ee0e0 | ghidra |
| Jumpmaxdistancemultiplierboostcomponent | 4 | - | 0x1088ee0f0 | ghidra |
| LadderClimbingcomponent | 1 | - | 0x1088e2858 | ghidra |
| LegacyActionAscombineitemcomponent | - | - | 0x108912598 | typeid |
| LegacyActionAsincapacitatedcomponent | - | - | 0x108912f80 | typeid |
| LegacyActionAsknockeddowncomponent | - | - | 0x108912f70 | typeid |
| LegacyActionAsuseitemcomponent | - | - | 0x1089125d4 | typeid |
| LegacyBehaviourBsspawncomponent | - | - | 0x108912f60 | typeid |
| LegacyBehaviourBstalktocomponent | - | - | 0x1088dfc94 | typeid |
| Levelcomponent | 4 | 4 | 0x10890b068 | ghidra |
| LightActivecharacterlightcomponent | 4 | 4 | 0x1088dfae0 | ghidra |
| LockAnimationstatecomponent | 1 | - | 0x1088ed0b0 | ghidra |
| LockKeycomponent | 4 | 4 | 0x1088f8760 | ghidra |
| LockLifetimecomponent | 1 | - | 0x1089126b0 | ghidra |
| LockLockcomponent | 40 | 40 | 0x1089095a0 | ghidra |
| Lockboostcomponent | 16 | - | 0x108901828 | ghidra |
| LookatTargetcomponent | 16 | - | 0x1088e2e50 | ghidra |
| Lootcomponent | 2 | 2 | 0x1088fabc8 | ghidra |
| Lootingstatecomponent | 16 | 16 | 0x1088ea608 | ghidra |
| Materialparameteroverridecomponent | 32 | 32 | 0x1088c4748 | ghidra |
| MaxHitPointsBoostComponent | 24 | - | - | ghidra |
| Maximizehealingboostcomponent | 2 | - | 0x1088ee100 | ghidra |
| Maximumrollresultboostcomponent | 2 | - | 0x1088ee110 | ghidra |
| Minimumrollresultboostcomponent | 2 | - | 0x1088ee120 | ghidra |
| Monkweapondamagediceoverrideboostcomponent | 4 | - | 0x1088ee130 | ghidra |
| MovementDashingcomponent | 28 | - | 0x1088ef9b0 | ghidra |
| Movementcomponent | 24 | 24 | 0x108909240 | ghidra |
| Movementspeedlimitboostcomponent | 1 | - | 0x1088ef248 | ghidra |
| MultiplayerHostcomponent (tag) | 1 | 1 | 0x1088eb780 | ghidra |
| MultiplayerUsercomponent | 4 | 4 | 0x1088eb750 | ghidra |
| NotificationApprovalratingcomponent | 40 | - | 0x1088e35d0 | ghidra |
| NotificationBackgroundgoalcomponent | 32 | - | 0x1088e35f0 | ghidra |
| NotificationCancelscriptanimationcomponent | 24 | - | 0x1088e3600 | ghidra |
| NotificationCharacterchangedappearancecomponent | 304 | - | 0x1088e3610 | ghidra |
| NotificationCharactercreatedcomponent | 992 | - | 0x1088e3620 | ghidra |
| NotificationCinematicarenascripteventcomponent | 48 | - | 0x1088e35e0 | ghidra |
| NotificationCombatantkillednotificationcomponent | 40 | - | 0x1088e3850 | ghidra |
| NotificationCombineresultcreatedcomponent | 48 | - | 0x1088e3630 | ghidra |
| NotificationConcentrationchangedcomponent | 136 | - | 0x1088e37a0 | ghidra |
| NotificationDestinationcomponent | 48 | - | 0x1088fe960 | ghidra |
| NotificationDropinapprovalpendingnotificationcomponent | 2 | - | 0x1088e3890 | ghidra |
| NotificationDropinapprovalrequestnotificationcomponent | 40 | - | 0x1088e3880 | ghidra |
| NotificationDropinapprovednotificationcomponent | 2 | - | 0x1088e38a0 | ghidra |
| NotificationDropincanceledrequestnotificationcomponent | 4 | - | 0x1088e38b0 | ghidra |
| NotificationEndcreditsrequestedcomponent | 4 | - | 0x1088e3640 | ghidra |
| NotificationEnterphotomodefailednotificationcomponent | 1 | - | 0x1088e38c0 | ghidra |
| NotificationEntityreceivedcomponent | 32 | - | 0x1088e3650 | ghidra |
| NotificationFailedprivatedialogjoinattemptnotificationcomponent | 72 | - | 0x1088e3800 | ghidra |
| NotificationGatheratcampcheckcomponent | 2 | - | 0x1088e3660 | ghidra |
| NotificationGoalactualscomponent | - | - | 0x1088e3490 | typeid |
| NotificationInventorymemberscreatednotificationcomponent | 16 | - | 0x1088e3860 | ghidra |
| NotificationLearnedspellcomponent | 24 | - | 0x1088e3670 | ghidra |
| NotificationLockpickedeventcomponent | 32 | - | 0x1088e36c0 | ghidra |
| NotificationLongrestcancelcomponent | 8 | - | 0x1088e3680 | ghidra |
| NotificationModifyspellcamerafocusnotificationcomponent | 40 | - | 0x1088e38e0 | ghidra |
| NotificationMovieendfadeinrequestnotificationcomponent | 48 | - | 0x1088e3870 | ghidra |
| NotificationNewmemberaddedtoplayerinventorynotificationcomponent | 32 | - | 0x1088e3830 | ghidra |
| NotificationNotifyinventorynotificationcomponent | 16 | - | 0x1088e3840 | ghidra |
| NotificationPerformfailedcomponent | 1 | - | 0x1088e3690 | ghidra |
| NotificationPickupresultnotificationcomponent | 24 | - | 0x1088e38d0 | ghidra |
| NotificationPingrequestcomponent | 40 | - | 0x1088e36a0 | ghidra |
| NotificationPlayserversoundcomponent | 32 | - | 0x1088e3730 | ghidra |
| NotificationProfileshowntutorialsupdatenotificationcomponent | 56 | - | 0x1088e37e0 | ghidra |
| NotificationProfileupdatenotificationcomponent | 8 | - | 0x1088e37d0 | ghidra |
| NotificationRandomcastresultcomponent | 80 | - | 0x1088e36b0 | ghidra |
| NotificationRecipesunlockednotificationcomponent | 48 | - | 0x1088e3820 | ghidra |
| NotificationReposeresultcomponent | 1 | - | 0x1088e36d0 | ghidra |
| NotificationResettutorialsmessagerequestnotificationcomponent | 8 | - | 0x1088e37b0 | ghidra |
| NotificationShortrestresultcomponent | 2 | - | 0x1088e36e0 | ghidra |
| NotificationSkillchecknotificationcomponent | 40 | - | 0x1088e37c0 | ghidra |
| NotificationSpellcastconfirmcomponent | 48 | - | 0x1088e3790 | ghidra |
| NotificationSpellcastdestroyedcomponent | 16 | - | 0x1088e3780 | ghidra |
| NotificationSpellcastfailedcomponent | 24 | - | 0x1088e3760 | ghidra |
| NotificationSpellcastmovementandprecalculationendcomponent | 24 | - | 0x1088e3740 | ghidra |
| NotificationSpellcastrollabortcomponent | 16 | - | 0x1088e3770 | ghidra |
| NotificationSpellcastzonerangecomputedcomponent | 16 | - | 0x1088e3750 | ghidra |
| NotificationStatecomponent | - | - | 0x1088fe950 | typeid |
| NotificationTimelinebackgroundactorrequestcomponent | 48 | - | 0x1088e37f0 | ghidra |
| NotificationTutorialhiderequestcomponent | 16 | - | 0x1088e36f0 | ghidra |
| NotificationTutorialshowrequestcomponent | 16 | - | 0x1088e3700 | ghidra |
| NotificationUnlockedeventcomponent | 32 | - | 0x1088e3710 | ghidra |
| NotificationUnsheathuserrequestfailedcomponent | 16 | - | 0x1088e3720 | ghidra |
| NotificationWeapondisarmednotificationcomponent | 16 | - | 0x1088e3810 | ghidra |
| Nullifyabilityboostcomponent | 1 | - | 0x1088ee140 | ghidra |
| ObjectVisualAppearanceoverridecomponent | - | - | 0x1088e7148 | typeid |
| ObjectVisualCharactercreationtemplateoverridecomponent | - | - | 0x1088e7138 | typeid |
| Objectinteractioncomponent | 16 | 16 | 0x1088fc110 | ghidra |
| Objectsizeboostcomponent | 4 | - | 0x1088fa1c0 | ghidra |
| Objectsizecomponent | 2 | 1 | 0x108906d78 | ghidra |
| Objectsizeoverrideboostcomponent | 1 | - | 0x1088fa1b0 | ghidra |
| Offstagecomponent (tag) | 1 | 1 | 0x10890e238 | ghidra |
| Originappearancetagcomponent | 16 | 16 | 0x1088efd40 | ghidra |
| Origincomponent | 24 | 24 | 0x108900530 | ghidra |
| Originpassivescomponent | 16 | 16 | 0x1088fcf18 | ghidra |
| Origintagcomponent | 16 | 16 | 0x1088efd30 | ghidra |
| OwnershipOwnedaslootcomponent (tag) | 1 | 1 | 0x1088f87e0 | ghidra |
| OwnershipOwneecurrentcomponent | 8 | 8 | 0x1089112e8 | ghidra |
| PartyBlockfollowcomponent (tag) | 1 | 1 | 0x1088f03c0 | ghidra |
| PartyCompositioncomponent | 40 | 24 | 0x1088f1430 | ghidra |
| PartyCurrentlyfollowingpartycomponent (tag) | 1 | 1 | 0x10890be78 | ghidra |
| PartyFollowercomponent | 8 | 8 | 0x108900218 | ghidra |
| PartyMembercomponent | 56 | 8 | 0x10890e660 | ghidra |
| PartyPortalscomponent | 48 | 48 | 0x1088fac88 | ghidra |
| PartyRecipescomponent | 16 | 16 | 0x1088fac98 | ghidra |
| PartyViewcomponent | 48 | 32 | 0x108911838 | ghidra |
| PartyWaypointscomponent | 48 | 48 | 0x1088faca8 | ghidra |
| PassiveUsagecountcomponent | 64 | 64 | 0x1088fd0a8 | ghidra |
| Passivecomponent | 32 | 8 | 0x1089113f8 | ghidra |
| Passivecontainercomponent | 16 | 16 | 0x108907158 | ghidra |
| Pathingcomponent | 80 | 64 | 0x1089124b0 | ghidra |
| PhotoModeCameratransformcomponent | - | - | 0x1088e4ad8 | typeid |
| PhotoModeDummyanimationstatecomponent | - | - | 0x1088e4b98 | typeid |
| PhotoModeDummycomponent | - | - | 0x1088eaaa8 | typeid |
| PhotoModeDummyequipmentvisualcomponent | - | - | 0x1088e4c08 | typeid |
| PhotoModeDummyshowsplattercomponent | - | - | 0x1088e4c78 | typeid |
| PhotoModeDummytransformcomponent | - | - | 0x1088e4ec8 | typeid |
| PhotoModeSessioncomponent | - | - | 0x1088e6498 | typeid |
| Physicalforcerangebonusboostcomponent | 8 | - | 0x108907bb8 | ghidra |
| Pickingstatecomponent (tag) | 1 | 1 | 0x1088ef828 | ghidra |
| PickupPickupexecutingcomponent (tag) | 1 | 1 | 0x1088fdea0 | ghidra |
| PickupPickuprequestcomponent | 24 | 24 | 0x108906888 | ghidra |
| PlatformDestructionparticipantcomponent | 1 | - | 0x1088f8b38 | ghidra |
| PlatformMovableplatformcomponent | 1 | - | 0x10890e998 | ghidra |
| PlatformMovementcomponent | 16 | - | 0x10890eac8 | ghidra |
| PlatformMovementpausedcomponent | 1 | - | 0x1088f16c0 | ghidra |
| PlatformMoveonsplinecomponent | 28 | - | 0x1088e54a8 | ghidra |
| PlatformMoveonsplineprogresscomponent | 24 | - | 0x1088e5498 | ghidra |
| PlatformMovetotargetcomponent | 40 | - | 0x1088e54c8 | ghidra |
| PlatformMovetotargetprogresscomponent | 12 | - | 0x1088e54b8 | ghidra |
| PlatformPassengercomponent | 48 | - | 0x1088fe910 | ghidra |
| PlatformPlatformcomponent | 72 | - | 0x1088fae48 | ghidra |
| PlatformRepresentativecomponent | 8 | - | 0x1088fe900 | ghidra |
| Playercomponent (tag) | 1 | 1 | 0x10890ea28 | ghidra |
| PortraitPaintingDatacomponent | - | - | 0x1088e5760 | typeid |
| Proficiencybonusboostcomponent | - | - | 0x108907a48 | typeid |
| Proficiencybonusincreaseboostcomponent | - | - | 0x108907ae8 | typeid |
| Proficiencybonusoverrideboostcomponent | - | - | 0x108907ad8 | typeid |
| Proficiencyboostcomponent | - | - | 0x1088ee150 | typeid |
| ProgressionAbilityimprovementscomponent | - | 24 | 0x1088ee360 | windows |
| ProgressionFeatcomponent | 128 | 104 | 0x108906048 | ghidra |
| ProgressionLevelupcomponent | 16 | - | 0x108907948 | ghidra |
| ProgressionMetacomponent | 128 | 32 | 0x108905f38 | ghidra |
| ProgressionPassivescomponent | 32 | 32 | 0x1088fce48 | ghidra |
| ProgressionReplicatedfeatcomponent | 24 | 24 | 0x1088e58c8 | ghidra |
| ProgressionSkillscomponent | - | 32 | 0x1088ee350 | windows |
| ProgressionSpellscomponent | - | 32 | 0x108906038 | windows |
| Progressioncontainercomponent | 16 | 16 | 0x108905f68 | ghidra |
| ProjectileSourceinfocomponent | 64 | 16 | 0x1088f4088 | ghidra |
| Projectiledeflectboostcomponent | - | - | 0x1088ef1c8 | typeid |
| QuestModifiedjournalentrysingletoncomponent | 64 | - | 0x1088eaa98 | ghidra |
| Racecomponent | 16 | 16 | 0x1089075f0 | ghidra |
| Ragdollsoundcomponent | - | - | 0x1088a5f08 | typeid |
| ReadyCheckBlockedcomponent | - | - | 0x1088e5b28 | typeid |
| ReadyCheckStatecomponent | - | - | 0x1088e5ae8 | typeid |
| ReadyCheckUsercomponent | - | - | 0x1088fe970 | typeid |
| Receivingcriticaldamageonhitboostcomponent | - | - | 0x1088ee160 | typeid |
| RecruitRecruitercomponent | 48 | 48 | 0x108905740 | ghidra |
| Redirectdamageboostcomponent | 8 | - | 0x1088ee170 | ghidra |
| Reducecriticalattackthresholdboostcomponent | 8 | - | 0x1088ee180 | ghidra |
| RelationFactioncomponent | 48 | 40 | 0x108907600 | ghidra |
| RelationRelationcomponent | 416 | 416 | 0x1088eaa88 | ghidra |
| ReposeStatecomponent | 48 | 48 | 0x108912f50 | ghidra |
| Requestedrollcomponent | 480 | 224 | 0x108911648 | ghidra |
| Rerollboostcomponent | 3 | - | 0x1088ee190 | ghidra |
| Resistanceboostcomponent | 3 | - | 0x108910020 | ghidra |
| Resistancescomponent | - | 32 | 0x108910010 | windows |
| RestShortrestcomponent (tag) | 1 | 1 | 0x108904f10 | ghidra |
| RewardChoicecomponent | 56 | - | 0x108900d70 | ghidra |
| RewardShowrequestcomponent | 48 | - | 0x108900eb8 | ghidra |
| Rollbonusboostcomponent | 48 | - | 0x1089017f8 | ghidra |
| RoomPortalPortalcomponent | - | - | 0x1088fe8f0 | typeid |
| RoomPortalRoomstatecomponent | - | - | 0x1088e5f68 | typeid |
| Rpgstatscomponent | - | - | 0x1088ec680 | typeid |
| RulesetRulesetcomponent | 96 | 96 | 0x1088eaa68 | ghidra |
| RulesetRulesetmodifierscomponent | 64 | 64 | 0x10890deb8 | ghidra |
| Savantboostcomponent | - | - | 0x108905990 | typeid |
| Scalemultiplierboostcomponent | 4 | - | 0x1088ee1a0 | ghidra |
| ScreenFadeScreenfadefromservercomponent | - | - | 0x1088feb00 | typeid |
| ScriptAnimationstatecomponent | 16 | - | 0x1088f8ba8 | ghidra |
| ScriptPlayanimationcomponent | 64 | - | 0x1088fc100 | ghidra |
| Serverrootlevelloadedcomponent | - | - | 0x10890e9f8 | typeid |
| Serverrootlevelstartdialogcomponent | 1 | - | 0x1088e60d0 | ghidra |
| ShapeshiftAnimationcomponent | 8 | 8 | 0x1088e72b0 | ghidra |
| ShapeshiftRecoveryanimationcomponent | 4 | 4 | 0x1088e7508 | ghidra |
| ShapeshiftReplicatedchangescomponent | 168 | 88 | 0x108909428 | ghidra |
| ShapeshiftSourcecachecomponent | 16 | 16 | 0x1088e74f8 | ghidra |
| ShapeshiftStatecomponent | 24 | 16 | 0x1088e7578 | ghidra |
| SightBasecomponent | 16 | - | 0x108904b70 | ghidra |
| SightDatacomponent | 40 | 8 | 0x10890d578 | ghidra |
| SightEntityviewshedcomponent | 48 | - | 0x10890d588 | ghidra |
| SightIgnoresurfacescomponent | 48 | 48 | 0x108909088 | ghidra |
| Sightrangeadditiveboostcomponent | 4 | - | 0x1088ee1b0 | ghidra |
| Sightrangemaximumboostcomponent | 4 | - | 0x1088ee1d0 | ghidra |
| Sightrangeminimumboostcomponent | 4 | - | 0x1088ee1c0 | ghidra |
| Sightrangeoverrideboostcomponent | 4 | - | 0x1088ee1e0 | ghidra |
| Simplecharactercomponent (tag) | - | 1 | 0x1088f4068 | windows |
| Skillboostcomponent | 40 | - | 0x1088ee1f0 | ghidra |
| SneakIssneakingcomponent | 1 | - | 0x1088f1680 | ghidra |
| SneakRollscontainercomponent | 24 | - | 0x1088e76b8 | ghidra |
| SoundDistantsoundinfocomponent | 16 | - | 0x1088e7010 | ghidra |
| SoundDistantsoundstatecomponent | 120 | - | 0x1088fea10 | ghidra |
| SoundFlagswitchdatacomponent | 16 | - | 0x1088e16b0 | ghidra |
| SoundPerformancezonecomponent | 128 | - | 0x108909920 | ghidra |
| Sourceadvantageboostcomponent | 16 | - | 0x1088ee200 | ghidra |
| SpatialGridCharactercomponent | - | - | 0x1088ac550 | typeid |
| SpatialGridDatacomponent | - | - | 0x10890b7c8 | typeid |
| SpatialGridItemcomponent | - | - | 0x1088ac560 | typeid |
| Speakercomponent | 16 | 24 | 0x1088e7878 | ghidra |
| SpellAdddebugspellsrequestoneframecomponent | - | - | 0x108905fb8 | typeid |
| SpellAddedspellscomponent | 16 | 16 | 0x108905f58 | ghidra |
| SpellAiconditionscomponent | 64 | 64 | 0x108905f48 | ghidra |
| SpellAttackspelloverridecomponent | 64 | 64 | 0x10890b038 | ghidra |
| SpellBookcomponent | 24 | 16 | 0x10890ae78 | ghidra |
| SpellBookcooldownscomponent | 16 | 16 | 0x108904f20 | ghidra |
| SpellBookpreparescomponent | 144 | 16 | 0x108906088 | ghidra |
| SpellCastAnimationinfocomponent | - | - | 0x1089043e8 | typeid |
| SpellCastCachecomponent | - | - | 0x108906cc0 | typeid |
| SpellCastCanbetargetedcomponent | - | - | 0x1089041e8 | typeid |
| SpellCastCasteventoneframecomponent | - | - | 0x10890a320 | typeid |
| SpellCastDatacachesingletoncomponent | - | - | 0x108906ea8 | typeid |
| SpellCastExecutiontimecomponent | - | - | 0x1089066c8 | typeid |
| SpellCastFinishedeventoneframecomponent | - | - | 0x10890a300 | typeid |
| SpellCastInterruptresultscomponent | - | - | 0x1089066b8 | typeid |
| SpellCastIscastingcomponent | - | - | 0x1089130f0 | typeid |
| SpellCastLogicexecutionstarteventoneframecomponent | - | - | 0x10890a310 | typeid |
| SpellCastMovementcomponent | - | - | 0x108905ce8 | typeid |
| SpellCastOutcomecomponent | - | - | 0x108904318 | typeid |
| SpellCastRollscomponent | - | - | 0x1089066a8 | typeid |
| SpellCastStatecomponent | - | - | 0x108913020 | typeid |
| SpellCastSynctargetingcomponent | - | - | 0x108905e98 | typeid |
| SpellCcpreparespellcomponent | 16 | 16 | 0x1089060b8 | ghidra |
| SpellContainercomponent | 16 | 16 | 0x108906ce0 | ghidra |
| SpellIconOverrideBoostComponent | 24 | - | - | ghidra |
| SpellLastusedlimbcomponent | 1 | - | 0x108904bc0 | ghidra |
| SpellLearnedspellscomponent | 112 | 48 | 0x108905f78 | ghidra |
| SpellModificationcontainercomponent | 64 | 64 | 0x108905e28 | ghidra |
| SpellPlayerpreparespellcomponent | 24 | 16 | 0x108906098 | ghidra |
| SpellPlayerpreparespellsrequestoneframecomponent | - | - | 0x1089060a8 | typeid |
| SpellScriptedexplosioncomponent | 4 | 4 | 0x108903eb8 | ghidra |
| SpellSpellinvalidationlockedcomponent | 1 | - | 0x108905f88 | ghidra |
| Spellresistanceboostcomponent | 1 | - | 0x108907a88 | ghidra |
| Spellsavedcboostcomponent | 4 | - | 0x108907b38 | ghidra |
| SplatterStatecomponent | 28 | - | 0x1088fadd8 | ghidra |
| SplatterSweatchangecomponent | 4 | - | 0x1088e7918 | ghidra |
| StatsArealevelcomponent | 4 | - | 0x1088e15c0 | ghidra |
| StatsEntitydamagedeventoneframecomponent | - | - | 0x108907be8 | typeid |
| StatsEntityhealedeventoneframecomponent | - | - | 0x108907bc8 | typeid |
| StatsEntityhealthchangedeventoneframecomponent | - | - | 0x108907bd8 | typeid |
| StatsMusicalinstrumentcomponent | 1 | - | 0x108907a38 | ghidra |
| StatsProficiencyIntrinsicallyproficientwieldercomponent | 24 | - | 0x108907a18 | ghidra |
| StatsProficiencyProficiencycomponent | 8 | - | 0x10890af58 | ghidra |
| StatsProficiencyProficiencygroupcomponent | 8 | - | 0x108907a28 | ghidra |
| Statscomponent | 160 | 64 | 0x10890b058 | ghidra |
| StatusCausecomponent | 8 | 8 | 0x1088f5c08 | ghidra |
| StatusContainercomponent | 64 | 64 | 0x1089130e0 | ghidra |
| StatusExternalstatusbackupcomponent | 48 | - | 0x1088e7ae8 | ghidra |
| StatusIdcomponent | 4 | 4 | 0x1088fcfb8 | ghidra |
| StatusIncapacitatedcomponent | 80 | 80 | 0x10890e650 | ghidra |
| StatusIndicatedarknesscomponent (tag) | 1 | 1 | 0x1088e7ad8 | ghidra |
| StatusLifetimecomponent | 8 | 4 | 0x1088f7210 | ghidra |
| StatusLosecontrolcomponent | 1 | 1 | 0x10890eaa8 | ghidra |
| StatusTauntedcomponent | 8 | - | 0x1088ebe68 | ghidra |
| StatusVisualDisabledcomponent | 48 | 48 | 0x1088e8cd8 | ghidra |
| Statusimmunitiescomponent | - | 64 | 0x1089078d8 | windows |
| Statusimmunityboostcomponent | 24 | - | 0x108907b48 | ghidra |
| Stealthcomponent | 36 | 40 | 0x1088f1510 | ghidra |
| SteeringSynccomponent | 4 | - | 0x1088e8da0 | ghidra |
| Steeringcomponent | 32 | 24 | 0x108908fb8 | ghidra |
| StoryCountercomponent | 12 | - | 0x1088e8f20 | ghidra |
| StoryDisplayedmessagecomponent | 8 | - | 0x1088eaa58 | ghidra |
| StoryTimercomponent | 16 | - | 0x1088e19a0 | ghidra |
| Storyshortrestdisabledcomponent | 1 | - | 0x1088ef178 | ghidra |
| SummonAnimationcomponent | 1 | - | 0x1088e8fc8 | ghidra |
| SummonContainercomponent | 160 | 96 | 0x108900208 | ghidra |
| SummonIsspawncomponent | 1 | - | 0x1089146e8 | ghidra |
| SummonIssummoncomponent | 48 | 32 | 0x1089146d8 | ghidra |
| SummonLifetimecomponent | 8 | 8 | 0x1088f0cb8 | ghidra |
| Surfacepathinfluencescomponent | - | 16 | 0x1088ef838 | windows |
| SwapPlacesAnimationrequestcomponent | - | - | 0x1088fe9f0 | typeid |
| Syncedtimelineactorcontrolcomponent | 40 | - | 0x10890be68 | ghidra |
| Syncedtimelinecontrolcomponent | 248 | - | 0x10890bde8 | ghidra |
| TadpoleTreeFullillithidcomponent | - | - | 0x1088e9108 | typeid |
| TadpoleTreeHalfillithidcomponent | - | - | 0x1088e9118 | typeid |
| TadpoleTreePowercontainercomponent | - | - | 0x1088fd028 | typeid |
| TadpoleTreeTadpoledcomponent | - | - | 0x1088e9128 | typeid |
| TadpoleTreeTreestatecomponent | - | - | 0x1088e9138 | typeid |
| TagAvatarcomponent (tag) | 1 | 1 | 0x1089157a0 | ghidra |
| TagHasexclamationdialogcomponent (tag) | 1 | 1 | 0x1088e9648 | ghidra |
| TagTradercomponent (tag) | 1 | 1 | 0x1088fe310 | ghidra |
| Tagcomponent | 16 | 16 | 0x10890b048 | ghidra |
| TemplatesOriginaltemplatecomponent | 8 | 8 | 0x108902230 | ghidra |
| Temporaryhpboostcomponent | 32 | - | 0x108907b28 | ghidra |
| ThroughCanseethroughcomponent (tag) | 1 | 1 | 0x1088f8df8 | ghidra |
| ThroughCanshootthroughcomponent (tag) | 1 | 1 | 0x1089072c8 | ghidra |
| ThroughCanwalkthroughcomponent (tag) | 1 | 1 | 0x1088f8e18 | ghidra |
| ThroughShootthroughtypecomponent | 1 | 1 | 0x1088f7df8 | ghidra |
| ThrownAttachcomponent | 16 | - | 0x1088eced0 | ghidra |
| ThrownIsthrowncomponent | 16 | - | 0x1088f8d78 | ghidra |
| ThrownRotationparameterscomponent | 56 | - | 0x1088f8cd8 | ghidra |
| TimelineActorvisualdatacomponent | 8 | - | 0x10890bfc8 | ghidra |
| TimelineHideequipmentcomponent | 1 | - | 0x10890c078 | ghidra |
| TimelineLongrestcomponent | - | - | 0x10890bfa8 | typeid |
| TimelineSteeringTimelinesteeringcomponent | 120 | - | 0x1088e6338 | ghidra |
| Timelineactordatacomponent | 40 | 40 | 0x1088a9d20 | ghidra |
| Timelinedatacomponent | 168 | - | 0x1088a9d10 | ghidra |
| Timelinereplicationcomponent | - | - | 0x10890bff8 | typeid |
| Trackedsoundentitycomponent | 4 | - | 0x1088e9ee0 | ghidra |
| TradeCantradecomponent (tag) | 1 | 1 | 0x1088fe300 | ghidra |
| TradeShowntradermapmarkerguidcomponent | 16 | - | 0x10890d3a8 | ghidra |
| TradeShowntradermapmarkernamecomponent | 16 | - | 0x10890ce00 | ghidra |
| TradeShowntradermapmarkertranslatecomponent | 12 | - | 0x10890d320 | ghidra |
| TradeTradermapmarkerhostileplayerscomponent | 48 | - | 0x10890cda8 | ghidra |
| TranslateChangedcomponent | 64 | 64 | 0x1088f02d0 | ghidra |
| TrapDisarminganimationstatecomponent | 1 | - | 0x1088ea080 | ghidra |
| TriggerTreecomponent | - | - | 0x1088ea208 | typeid |
| TriggerTypecomponent | 1 | 1 | 0x1088f4038 | ghidra |
| Turnbasedcomponent | 48 | 3 | 0x10890e9a8 | ghidra |
| Turnordercomponent | 80 | 48 | 0x10890ea48 | ghidra |
| TutorialRevealedentriescomponent | 48 | - | 0x10890f640 | ghidra |
| Unlockinterruptboostcomponent | 4 | - | 0x1088f5fa8 | ghidra |
| Unlockspellboostcomponent | - | - | 0x108906058 | typeid |
| Unlockspellvariantboostcomponent | - | - | 0x1088ee210 | typeid |
| UnsheathSpellanimationoverridecomponent | 4 | - | 0x108912f40 | ghidra |
| UnsheathStatecomponent | 32 | 8 | 0x108914880 | ghidra |
| UseSocketcomponent | 64 | 64 | 0x1088f8330 | ghidra |
| Useboostscomponent | 16 | 16 | 0x108907bf8 | ghidra |
| Usecomponent | 80 | 80 | 0x108907898 | ghidra |
| UserAvatarcomponent | 12 | 8 | 0x1089157c0 | ghidra |
| UserDismissedcomponent | 1 | - | 0x1089157b0 | ghidra |
| UserReservedforcomponent | 4 | 4 | 0x108915790 | ghidra |
| Valuecomponent | 8 | 8 | 0x1089078e8 | ghidra |
| Voicecomponent | 16 | 16 | 0x108900540 | ghidra |
| Voicetagcomponent | 16 | 16 | 0x1088f1f18 | ghidra |
| WeaponSetChangedEventOneFrameComponent | 2 | - | - | ghidra |
| Weaponattackrollabilityoverrideboostcomponent | 1 | - | 0x1088ee220 | ghidra |
| Weaponattackrollbonusboostcomponent | 32 | - | 0x108907b98 | ghidra |
| Weaponattacktypeoverrideboostcomponent | 1 | - | 0x1088ee230 | ghidra |
| Weaponcomponent | 80 | 56 | 0x108912e00 | ghidra |
| Weapondamageboostcomponent | 48 | - | 0x1088ee240 | ghidra |
| Weapondamagedieoverrideboostcomponent | 12 | - | 0x108907b78 | ghidra |
| Weapondamageresistanceboostcomponent | 16 | - | 0x108907a58 | ghidra |
| Weapondamagetypeoverrideboostcomponent | 1 | - | 0x108907b58 | ghidra |
| Weaponenchantmentboostcomponent | 4 | - | 0x108907b88 | ghidra |
| Weaponpropertyboostcomponent | 4 | - | 0x108907ba8 | ghidra |
| Weaponsetcomponent | 1 | 8 | 0x1089111b0 | ghidra |
| Weightboostcomponent | 4 | - | 0x1089079b8 | ghidra |
| Weightcategoryboostcomponent | 4 | - | 0x1089079c8 | ghidra |
| Wieldingcomponent | 8 | 8 | 0x1089130b0 | ghidra |
| ActionStateComponent | 8 | - | - | ghidra |
| RequestPushComponent | 80 | - | - | ghidra |
| InProgressComponent (tag) | 1 | 1 | - | ghidra |
| ModifiersComponent | 144 | 136 | - | ghidra |
| AiGridLoadedOneFrameComponent | 1 | - | - | ghidra |
| SubgridProximityListChangedEventOneFrameComponent | 96 | - | - | ghidra |
| DoorAnimationFinishedOneFrameComponent | 24 | - | - | ghidra |
| GameplayEventsOneFrameComponent | 64 | 64 | - | ghidra |
| PlayAnimationComponent | 64 | - | - | ghidra |
| RecoveryAnimationComponent | 4 | - | - | ghidra |
| TextKeyEventsOneFrameComponent | 64 | 64 | - | ghidra |
| TriggeredEventsOneFrameComponent | 64 | 64 | - | ghidra |
| StateComponent | 1 | 8 | - | ghidra |
| ChangedEventOneFrameComponent | 16 | - | - | ghidra |
| ConversationCameraComponent | 8 | - | - | ghidra |
| SelectedCameraComponent | 8 | - | - | ghidra |
| SilenceFadeComponent | 16 | - | - | ghidra |
| AppearanceComponent | 112 | - | - | ghidra |
| CharacterDefinitionComponent | 656 | - | - | ghidra |
| DefinitionCommonComponent | 192 | - | - | ghidra |
| MoveComponent | 16 | - | - | ghidra |
| SessionCommonComponent | 12 | - | - | ghidra |
| AppearanceComponent | 112 | 112 | - | ghidra |
| ChangeAppearanceDefinitionComponent | 736 | 32 | - | ghidra |
| CharacterChangedAppearanceComponent | 304 | - | - | ghidra |
| CharacterCreatedComponent | 992 | - | - | ghidra |
| CharacterDefinitionComponent | 656 | 16 | - | ghidra |
| CompanionDefinitionComponent | 320 | 104 | - | ghidra |
| DefinitionCommonComponent | 192 | 16 | - | ghidra |
| FullRespecDefinitionComponent | 616 | 80 | - | ghidra |
| LevelUpComponent | 16 | 16 | - | ghidra |
| LevelUpDefinitionComponent | 816 | 32 | - | ghidra |
| RespecDefinitionComponent | 664 | 32 | - | ghidra |
| SessionCommonComponent | 12 | 12 | - | ghidra |
| StateComponent | 3 | 3 | - | ghidra |
| CreationComponent | - | 24 | - | windows |
| FullRespecComponent | - | - | - | windows |
| LevelUpComponent | - | 24 | - | windows |
| RespecComponent | - | - | - | windows |
| FleeingCombatComponent | 8 | - | - | ghidra |
| DiedEventOneFrameComponent | 1 | - | - | ghidra |
| ModifyDelayDeathRequestOneFrameComponent | 16 | - | - | ghidra |
| ActiveDialogActorComponent | 40 | - | - | ghidra |
| InitiatorComponent | 16 | - | - | ghidra |
| ISDoorClosedAnimationFinishedOneFrameComponent | 1 | - | - | ghidra |
| ISDoorClosedAnimationRequestOneFrameComponent | 1 | - | - | ghidra |
| ISDoorClosedComponent | 8 | - | - | ghidra |
| ISDoorOpenedAnimationFinishedOneFrameComponent | 1 | - | - | ghidra |
| ISDoorOpenedAnimationRequestOneFrameComponent | 1 | - | - | ghidra |
| ISDoorOpenedComponent | 8 | - | - | ghidra |
| JoinInCurrentRoundOneFrameComponent | 1 | - | - | ghidra |
| ScreenFadeComponent | 48 | - | - | ghidra |
| ServerTargetsNotificationComponent | 48 | - | - | ghidra |
| TeleportRequestComponent | 56 | - | - | ghidra |
| GroupRequestCompletedComponent | 1 | - | - | ghidra |
| HasStragglersComponent | 1 | - | - | ghidra |
| EnteredListenerRangeEventOneFrameComponent | 8 | - | - | ghidra |
| LeftListenerRangeEventOneFrameComponent | 8 | - | - | ghidra |
| CancelRequestOneFrameComponent | 1 | - | - | ghidra |
| ConditionalRollAdjustmentOneFrameComponent | 136 | - | - | ghidra |
| HitNotificationEventOneFrameComponent | 80 | - | - | ghidra |
| HitNotificationRequestOneFrameComponent | 72 | - | - | ghidra |
| HitResultEventOneFrameComponent | 488 | - | - | ghidra |
| ContainerKeyCreatedOneFrameComponent | 4 | - | - | ghidra |
| CanBeWieldedComponent (tag) | 1 | 1 | - | ghidra |
| WieldedComponent | 16 | 16 | - | ghidra |
| WieldingComponent | 8 | 8 | - | ghidra |
| CanBeWieldedComponent | 1 | - | - | ghidra |
| ISDoorClosedAnimationFinishedOneFrameComponent | 1 | - | - | ghidra |
| ISDoorClosedAnimationRequestOneFrameComponent | 1 | - | - | ghidra |
| ISDoorOpenedAnimationFinishedOneFrameComponent | 1 | - | - | ghidra |
| ISDoorOpenedAnimationRequestOneFrameComponent | 1 | - | - | ghidra |
| IdentityComponent | 1 | - | - | ghidra |
| MemberTransformComponent | 40 | - | - | ghidra |
| NewItemsInsideComponent | 1 | - | - | ghidra |
| NonTradableComponent | 1 | - | - | ghidra |
| OriginalIdentityComponent | 1 | - | - | ghidra |
| OwnedAsLootComponent | 1 | - | - | ghidra |
| StackComponent | 32 | - | - | ghidra |
| StackMemberComponent | 8 | - | - | ghidra |
| StateComponent | 1 | - | - | ghidra |
| WieldedComponent | 16 | - | - | ghidra |
| WieldingComponent | 8 | - | - | ghidra |
| ActionTypeComponent | 48 | 48 | - | ghidra |
| CanMoveComponent (tag) | 1 | 1 | - | ghidra |
| ClimbOnComponent (tag) | 1 | 1 | - | ghidra |
| DestroyedComponent (tag) | 1 | 1 | - | ghidra |
| InteractionDisabledComponent (tag) | 1 | 1 | - | ghidra |
| IsStoryItemComponent (tag) | 1 | 1 | - | ghidra |
| LadderComponent (tag) | 1 | 1 | - | ghidra |
| ScriptControlledDoorComponent | 1 | - | - | ghidra |
| UseActionComponent | 16 | 16 | - | ghidra |
| WalkOnComponent (tag) | 1 | 1 | - | ghidra |
| ActivationEventOneFrameComponent | 1 | - | - | ghidra |
| AnimationRequestOneFrameComponent | 12 | - | - | ghidra |
| TakeoffComponent | 48 | - | - | ghidra |
| ContainerComponent | 24 | - | - | ghidra |
| SpellLearningResultComponent | 24 | - | - | ghidra |
| MovementContinueComponent | 1 | - | - | ghidra |
| MovementRequestComponent | 56 | - | - | ghidra |
| EnemySightedComponent | 24 | - | - | ghidra |
| ScreenFadeFromServerComponent | 64 | - | - | ghidra |
| ShortRestStatusDurationIncreasedComponent | 16 | - | - | ghidra |
| ShowHudNotificationComponent | 48 | - | - | ghidra |
| SpellPrepareStartEventComponent | 64 | - | - | ghidra |
| StatsAppliedComponent | 24 | - | - | ghidra |
| StopMovementComponent | 1 | - | - | ghidra |
| SurfaceEnteredComponent | 24 | - | - | ghidra |
| SurfaceLeftComponent | 24 | - | - | ghidra |
| TadpoleSuperPowerRequestComponent | 1 | - | - | ghidra |
| TradeEventComponent | 16 | - | - | ghidra |
| UpdatePortraitMaterialRequestComponent | 16 | - | - | ghidra |
| VariableManagerDirtyComponent | 1 | - | - | ghidra |
| WorldAligningComponent | 56 | - | - | ghidra |
| InstanceComponent | 136 | - | - | ghidra |
| RequestComponent | 64 | - | - | ghidra |
| AppearanceOverrideComponent | 216 | 8 | - | ghidra |
| CharacterCreationTemplateOverrideComponent | 4 | 4 | - | ghidra |
| OwneeCurrentComponent | 8 | - | - | ghidra |
| RestorePartyEventOneFrameComponent | 16 | - | - | ghidra |
| CameraTransformComponent | 40 | 8 | - | ghidra |
| DummyAnimationStateComponent | 24 | 24 | - | ghidra |
| DummyComponent | 16 | 16 | - | ghidra |
| DummyEquipmentVisualComponent | 4 | 4 | - | ghidra |
| DummyShowSplatterComponent | 1 | 1 | - | ghidra |
| DummyTransformComponent | 40 | 8 | - | ghidra |
| SessionComponent | 1 | 1 | - | ghidra |
| DataComponent | 88 | - | - | ghidra |
| BlockedComponent | 1 | - | - | ghidra |
| ResultEventOneFrameComponent | 40 | - | - | ghidra |
| StateComponent | 168 | - | - | ghidra |
| UserComponent | 56 | - | - | ghidra |
| ChangesComponent | 168 | - | - | ghidra |
| LongRestInScriptPhase (tag) | 1 | 1 | - | ghidra |
| LongRestState | 24 | 40 | - | ghidra |
| LongRestTimeline | 16 | 16 | - | ghidra |
| LongRestTimers | 4 | 4 | - | ghidra |
| LongRestUsers | 120 | 120 | - | ghidra |
| RestingEntities | 200 | 200 | - | ghidra |
| FillRewardInventoriesRequestComponent | 128 | - | - | ghidra |
| GiveRewardRequestComponent | 16 | - | - | ghidra |
| TransferRewardsRequestComponent | 64 | - | - | ghidra |
| PortalComponent | 24 | - | - | ghidra |
| RoomStateComponent | 24 | - | - | ghidra |
| ModifiersComponent | 64 | - | - | ghidra |
| LoadComponent | 32 | - | - | ghidra |
| MainMenuPostInstantiateComponent | 1 | - | - | ghidra |
| PausedComponent | 1 | - | - | ghidra |
| RunningComponent | 1 | - | - | ghidra |
| UnloadLevelComponent | 1 | - | - | ghidra |
| UnloadModuleComponent | 1 | - | - | ghidra |
| ScreenFadeFromServerComponent | 64 | - | - | ghidra |
| AnimationStateRequestOneFrameComponent | 1 | - | - | ghidra |
| PlayAnimationRequestOneFrameComponent | 1 | - | - | ghidra |
| CharacterComponent | 1 | - | - | ghidra |
| DataComponent | 152 | 16 | - | ghidra |
| ItemComponent | 1 | - | - | ghidra |
| AnimationInfoComponent | 48 | 40 | - | ghidra |
| AnimationRequestOneFrameComponent | 48 | - | - | ghidra |
| CacheComponent | 8 | 8 | - | ghidra |
| CanBeTargetedComponent (tag) | 1 | 1 | - | ghidra |
| CastEventOneFrameComponent | 448 | - | - | ghidra |
| CastHitEventOneFrameComponent | 16 | - | - | ghidra |
| CastTextKeyEventOneFrameComponent | 16 | - | - | ghidra |
| CounteredEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| DataCacheSingletonComponent | 64 | 64 | - | ghidra |
| DestroyEventOneFrameComponent | 16 | - | - | ghidra |
| ExecutionTimeComponent | 8 | 8 | - | ghidra |
| FinishedEventOneFrameComponent | 2 | - | - | ghidra |
| InterruptResultsComponent | 56 | 56 | - | ghidra |
| IsCastingComponent | 8 | 8 | - | ghidra |
| JumpStartEventOneFrameComponent (tag) | - | 1 | - | windows |
| LogicExecutionEndEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| LogicExecutionStartEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| MovementComponent | 28 | 24 | - | ghidra |
| OutcomeComponent | 1 | 8 | - | ghidra |
| PrepareEndEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| PrepareStartEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| PreviewEndEventOneFrameComponent (tag) | - | 1 | - | windows |
| RollsComponent | 16 | 16 | - | ghidra |
| SpellCastConfirmComponent | 48 | - | - | ghidra |
| SpellCastFailedComponent | 24 | - | - | ghidra |
| SpellCastMovementAndPrecalculationEndComponent | 24 | - | - | ghidra |
| SpellCastRollAbortComponent | 16 | - | - | ghidra |
| SpellCastZoneRangeComputedComponent | 16 | - | - | ghidra |
| SpellRollAbortEventOneFrameComponent | 448 | - | - | ghidra |
| SpellRollCastEventOneFrameComponent | 448 | - | - | ghidra |
| StateComponent | 192 | 72 | - | ghidra |
| SurfaceCreationRequestOneFrameComponent | 48 | - | - | ghidra |
| SyncTargetingComponent | 152 | 64 | - | ghidra |
| TargetHitEventOneFrameComponent | 504 | - | - | ghidra |
| TargetPickedOneFrameComponent | 144 | - | - | ghidra |
| TargetsChangedEventOneFrameComponent | 16 | - | - | ghidra |
| ThrowPickupPositionChangedEventOneFrameComponent (tag) | - | 1 | - | windows |
| UpdateAttachmetsRequestOneFrameComponent | 1 | - | - | ghidra |
| ValueChangedOneFrameComponent | 4 | - | - | ghidra |
| AnimationRequestComponent | 24 | - | - | ghidra |
| FullIllithidComponent (tag) | 1 | 1 | - | ghidra |
| HalfIllithidComponent (tag) | 1 | 1 | - | ghidra |
| PowerContainerComponent | 16 | 16 | - | ghidra |
| TadpoledComponent (tag) | 1 | 1 | - | ghidra |
| TreeStateComponent | 1 | 1 | - | ghidra |
| SpellPrepareAnimationRequest | 4 | - | - | ghidra |
| ThrownAnimationRequestOneFrameComponent | 8 | - | - | ghidra |
| RequestTargetTrackingOneFrameComponent | 64 | - | - | ghidra |
| TradeBuybackDataComponent | 24 | - | - | ghidra |

---

## esv:: Components

| Component | Ghidra | Windows | TypeId | Source |
|-----------|--------|---------|--------|--------|
| AIHintAreaTrigger | 8 | - | - | ghidra |
| ActionResourceCooldowntrackingcomponent | - | - | 0x1088ec5c0 | typeid |
| ActionResourceResourcechangeresultssingletoncomponent | - | - | 0x1088ec5b0 | typeid |
| ActionResourceResourcesonlastcombatturncomponent | - | - | 0x1088ec6d0 | typeid |
| Activationgroupcontainercomponent | 16 | 16 | 0x1088f87a0 | ghidra |
| ActiveCharacterLightComponent | 4 | - | - | ghidra |
| ActiveRollInprogresscomponent | - | - | 0x108901798 | typeid |
| ActiveRollStartrequestoneframecomponent | - | - | 0x1089018a8 | typeid |
| ActiveRollWaitingcomponent | - | - | 0x1088eca10 | typeid |
| Activemusicvolumecomponent | 8 | - | 0x1088f4008 | ghidra |
| AiCombatAimodifierscomponent | - | 72 | 0x1088ecad0 | windows |
| AiCombatArchetypecomponent | 16 | 16 | 0x1088fae08 | ghidra |
| AiCombatInterestedinitemscomponent | 48 | 48 | 0x1088f0cc8 | ghidra |
| AiCombatInterestingitemcomponent | 48 | 48 | 0x1088ebb90 | ghidra |
| AiCombatLoadedaimodifierscomponent | - | - | 0x1088ecb00 | typeid |
| AiGridAreaTrigger | 8 | - | - | ghidra |
| AiSwarmActionattemptscomponent | - | - | 0x1088ebea0 | typeid |
| AiSwarmAttackordercomponent | - | - | 0x1088ebec0 | typeid |
| AiSwarmCalculatingcomponent | - | - | 0x1088ebee0 | typeid |
| AiSwarmGroupscomponent | 64 | - | 0x1088f1550 | ghidra |
| AiSwarmIscalculatingcomponent | - | - | 0x1088ebf20 | typeid |
| AiSwarmIspausedcomponent | - | - | 0x1088ebf40 | typeid |
| AiSwarmMemberschangedcomponent | - | - | 0x1088f1520 | typeid |
| AiSwarmNextactioncomponent | 32 | - | 0x1088ebf80 | ghidra |
| AiSwarmRequestactionpausedcomponent | - | - | 0x1088ec000 | typeid |
| AiSwarmSpellscomponent | - | - | 0x1088ec020 | typeid |
| AiSwarmTargetscomponent | - | - | 0x1088ec040 | typeid |
| AiSwarmTurnactionscalculationcomponent | - | - | 0x1088ec060 | typeid |
| AiSwarmTurnactionscomponent | 400 | - | 0x1088ec080 | ghidra |
| Anubisexecutorcomponent | 8 | 32 | 0x1088f58f8 | ghidra |
| ApprovalRatingschangedoneframecomponent | 48 | - | 0x10890a350 | ghidra |
| ArmorClassComponent | 32 | - | - | ghidra |
| AtmosphereTrigger | 8 | - | - | ghidra |
| AvailableLevelComponent | 8 | - | - | ghidra |
| AvatarContainerTrigger | 120 | - | - | ghidra |
| BackgroundGoalfailedoneframecomponent | 24 | - | 0x1089098c0 | ghidra |
| BackgroundGoalrecordedeventoneframecomponent | 40 | - | 0x1089098b0 | ghidra |
| BaseHpComponent | 16 | - | - | ghidra |
| Basedatacomponent | 24 | 12 | 0x1089079a8 | ghidra |
| Basesizecomponent | 2 | 2 | 0x1088fa1e0 | ghidra |
| Basestatscomponent | 4 | 4 | 0x108907978 | ghidra |
| Baseweaponcomponent | 16 | 16 | 0x108907b68 | ghidra |
| BlockBronzeTimelinePlacementTrigger | 8 | - | - | ghidra |
| BoostAttachmentrequestoneframecomponent | - | - | 0x1088fe9a0 | typeid |
| BoostBasecomponent | - | 16 | 0x1088ee2a0 | windows |
| BoostChangedeventssingletoncomponent | - | 64 | 0x1088ee270 | windows |
| BoostConditionalstatecomponent | - | 16 | 0x1088ee310 | windows |
| BoostDebugrequestscomponent | 16 | - | 0x1088ee2e0 | ghidra |
| BoostDebugrequestsupdatedeventoneframecomponent | - | - | 0x1088ee2d0 | typeid |
| BoostDelayeddestroyrequestoneframecomponent | - | - | 0x1088ee2c0 | typeid |
| BoostProvidercomponent | 32 | 32 | 0x1088ee260 | ghidra |
| BoostStatusboostsprocessedcomponent (tag) | - | 1 | 0x108903e48 | windows |
| BoostStoryrequestscomponent | 16 | - | 0x1088ee300 | ghidra |
| BoostStoryrequestsupdatedeventoneframecomponent | - | - | 0x1088ee2f0 | typeid |
| Breadcrumbcomponent | 268 | 24 | 0x1088e28c8 | ghidra |
| CameraArrivedplayerscomponent | - | - | 0x1088dfcc8 | typeid |
| CampAvatarcontainerrequestscomponent | 96 | - | 0x1088f8e58 | ghidra |
| CampAvatarcontainertriggercomponent | 8 | - | 0x1088f8e48 | ghidra |
| CampCharacterintriggerchangedcomponent | - | - | 0x1088dfe18 | typeid |
| CampChestTrigger | 8 | - | - | ghidra |
| CampEndthedayresulteventoneframecomponent | - | - | 0x10890a330 | typeid |
| CampInitializequalitycomponent | 1 | - | 0x1088dfec0 | ghidra |
| CampRegionTrigger | 8 | - | - | ghidra |
| CampTriggercomponent | 8 | - | 0x1088f3fe8 | ghidra |
| Character | 1 | - | - | ghidra |
| CharacterCanopendoorsoverridecomponent | 1 | - | 0x1088ef1f8 | ghidra |
| CharacterComponent | 24 | - | - | ghidra |
| CharacterCreationAppearancevisualtagcomponent | - | - | 0x1088fa4b0 | typeid |
| CharacterCreationAutolevelrequestoneframecomponent | - | - | 0x1088f9f08 | typeid |
| CharacterCreationBackupdefinitioncomponent | - | - | 0x108900570 | typeid |
| CharacterCreationCharacterselectedforuseroneframecomponent | - | - | 0x108909930 | typeid |
| CharacterCreationCompanionselectedforuseroneframecomponent | - | - | 0x108909940 | typeid |
| CharacterCreationCreationfinishedoneframecomponent | - | - | 0x10890a2d0 | typeid |
| CharacterCreationDebugbasedefinitionrequestoneframecomponent | - | - | 0x1088f1f08 | typeid |
| CharacterCreationDebugfulldefinitionrequestoneframecomponent | - | - | 0x1089005d0 | typeid |
| CharacterCreationEquipmentsetrequestcomponent | - | - | 0x1088f6650 | typeid |
| CharacterCreationGodcomponent | - | - | 0x108900560 | typeid |
| CharacterCreationInitiallevelcomponent | - | - | 0x1088f9f18 | typeid |
| CharacterCreationIscustomcomponent | - | - | 0x1088f69e8 | typeid |
| CharacterCreationOriginintroassignmentssingletoncomponent | - | - | 0x1088efa58 | typeid |
| CharacterCreationSessionownercomponent | - | - | 0x1089005a0 | typeid |
| CharacterCreationUpdatescomponent | - | - | 0x1088fced8 | typeid |
| CharacterCreationUseravatarcreatedoneframecomponent | - | - | 0x10890a2e0 | typeid |
| CharacterDeathactionsqueuesingletoncomponent | - | - | 0x1088f04d0 | typeid |
| CharacterEntitymovingcomponent | 1 | - | 0x1088f04a0 | ghidra |
| CharacterExecuteteleportrequestcomponent | 24 | - | 0x1088fc7a8 | ghidra |
| CharacterReconnectedplayersoneframecomponent | - | - | 0x1088f0330 | typeid |
| CharacterReevaluatepartyrequestoneframecomponent | - | - | 0x1088f0320 | typeid |
| Charactercreationcustomiconcomponent | 88 | 8 | 0x108900550 | ghidra |
| ChasmRegionTrigger | 136 | - | - | ghidra |
| ChasmSeederTrigger | 8 | - | - | ghidra |
| Chasmdatacomponent | 48 | - | 0x108903ae8 | ghidra |
| CombatCanstartcombatcomponent (tag) | 1 | 1 | 0x1088f1670 | ghidra |
| CombatCombatgroupmappingcomponent | - | 72 | 0x1088f1700 | windows |
| CombatCombatswitchedcomponent | 48 | 48 | 0x10890ebb8 | ghidra |
| CombatComponent | 8 | - | - | ghidra |
| CombatEnterrequestcomponent | 48 | 48 | 0x1088f1640 | ghidra |
| CombatFleeblockedcomponent (tag) | 1 | 1 | 0x1088f0e80 | ghidra |
| CombatFleerequestcomponent | - | 24 | 0x1088f47f8 | windows |
| CombatFleesuccessoneframecomponent (tag) | - | 1 | 0x10890a2f0 | windows |
| CombatGroupMappingComponent | 8 | - | - | ghidra |
| CombatImmediatejoincomponent (tag) | 1 | 1 | 0x1088f15c0 | ghidra |
| CombatJoineventoneframecomponent | 16 | - | 0x108912560 | ghidra |
| CombatJoiningcomponent | 4 | 4 | 0x1088f0f10 | ghidra |
| CombatLatejoinpenaltycomponent | 4 | 4 | 0x1088f15b0 | ghidra |
| CombatLeaverequestcomponent (tag) | 1 | 1 | 0x1088f4858 | ghidra |
| CombatLogCombatlogstatecomponent | - | - | 0x1088e0348 | typeid |
| CombatLogEquipstatusrequestoneframecomponent | - | - | 0x1088e0358 | typeid |
| CombatMergecomponent | 16 | 16 | 0x1088f1630 | ghidra |
| CombatParticipantComponent | 48 | - | - | ghidra |
| CombatSurfaceteamsingletoncomponent | 112 | 112 | 0x10890aa00 | ghidra |
| CombineAnalyticscombineresultssingletoncomponent | - | - | 0x1088f4d88 | typeid |
| Constellationchildcomponent | 8 | - | 0x1088e0428 | ghidra |
| Constellationcomponent | 64 | - | 0x1088f3e88 | ghidra |
| Constellationhelpercomponent | 24 | - | 0x1088f3e98 | ghidra |
| CoverIslightblockercomponent (tag) | - | 1 | 0x1088e0498 | windows |
| CoverIsvisionblockercomponent (tag) | - | 1 | 0x1088eb9b0 | windows |
| CrimeAreaTrigger | 8 | - | - | ghidra |
| CrimeRegionTrigger | 128 | - | - | ghidra |
| CrowdCharacterTrigger | 288 | - | - | ghidra |
| CrowdsAnimationcomponent | 12 | - | 0x1088f21f8 | ghidra |
| CrowdsAnimationpauserequestssingletoncomponent | - | - | 0x1088f2920 | typeid |
| CrowdsAnimationplayrequestssingletoncomponent | - | - | 0x1088f2950 | typeid |
| CrowdsDeactivatecharactercomponent | 1 | - | 0x1088f2c50 | ghidra |
| CrowdsDespawnwithoutcharactercomponent | 1 | - | 0x1088f2c20 | ghidra |
| CrowdsDetourcachecomponent | - | - | 0x1088f21e8 | typeid |
| CrowdsDetourcomponent | 32 | - | 0x1088f2ab8 | ghidra |
| CrowdsDetouridlingcomponent | 8 | - | 0x1088f2ac8 | ghidra |
| CrowdsDetourmovetorequestssingletoncomponent | - | - | 0x1088f2258 | typeid |
| CrowdsDetourpatrolrequestssingletoncomponent | - | - | 0x1088f24a0 | typeid |
| CrowdsDetourstopmovetorequestssingletoncomponent | - | - | 0x1088f2530 | typeid |
| CrowdsDisablecharacterspawningcomponent | 1 | - | 0x1088f2c10 | ghidra |
| CrowdsDynamicanimationsetcomponent | 16 | - | 0x1088f2f48 | ghidra |
| CrowdsFadecomponent | 8 | - | 0x1088f2bf0 | ghidra |
| CrowdsFleeingcombatcomponent | 8 | - | 0x1088f2bd0 | ghidra |
| CrowdsMovetocomponent | 36 | - | 0x1088f22b8 | ghidra |
| CrowdsMovetorequestssingletoncomponent | - | - | 0x1088f2288 | typeid |
| CrowdsPatrolcomponent | 48 | - | 0x1088f2aa8 | ghidra |
| CrowdsPatrolmovetorequestssingletoncomponent | - | - | 0x1088f23e0 | typeid |
| CrowdsPatrolrequestssingletoncomponent | - | - | 0x1088f24d0 | typeid |
| CrowdsPatrolstopmovetorequestssingletoncomponent | - | - | 0x1088f2410 | typeid |
| CrowdsSpawncomponent | 48 | - | 0x1088f2bc0 | ghidra |
| CrowdsSpawneventssingletoncomponent | - | - | 0x1088f2b90 | typeid |
| CrowdsStopmovetorequestssingletoncomponent | - | - | 0x1088f2500 | typeid |
| CrowdsTriggerspawnstatecomponent | 12 | - | 0x1088f2b50 | ghidra |
| CustomStatsComponent | 40 | - | - | ghidra |
| DarknessComponent | 104 | - | - | ghidra |
| DarknessDarknessactivecomponent (tag) | 1 | 1 | 0x1088e05e8 | ghidra |
| DeathAnimfallbacktimerfinishedeventoneframecomponent | - | - | 0x1088e00a8 | typeid |
| DeathAnimfinishedeventoneframecomponent | - | - | 0x1088f04e0 | typeid |
| DeathCharacterdeathinitiatedeventoneframecomponent | - | - | 0x1088f7a50 | typeid |
| DeathDeadentitiessingletoncomponent | - | - | 0x1088e0808 | typeid |
| DeathDeathanimationblockcomponent | - | - | 0x1088e00b8 | typeid |
| DeathDeathanimationfallbacktimercomponent | - | - | 0x1088f4a18 | typeid |
| DeathDeathanimationrequestoneframecomponent | - | - | 0x1088ed070 | typeid |
| DeathDeathcontinuecomponent (tag) | 1 | 1 | 0x1088f04c0 | ghidra |
| DeathDeathrequestoneframecomponent | 136 | - | 0x1088e0878 | ghidra |
| DeathDelaydeathcausecomponent | 24 | 24 | 0x1088e87f0 | ghidra |
| DeathDelayedanimationtriggercomponent | - | - | 0x1088e0098 | typeid |
| DeathDelayeddeathcomponent | 152 | 32 | 0x108907b08 | ghidra |
| DeathDownedeventoneframecomponent (tag) | 1 | 1 | 0x108907d18 | ghidra |
| DeathDyingwaitingfordeactivationcomponent | 1 | - | 0x1088e0058 | ghidra |
| DeathExecutedielogiceventoneframecomponent | - | - | 0x108909890 | typeid |
| DeathExecutedielogicrequestoneframecomponent | - | - | 0x1088e0048 | typeid |
| DeathKillercomponent | 48 | 48 | 0x1088e0838 | ghidra |
| DeathModifydelaydeathrequestoneframecomponent | 16 | - | 0x1088e0848 | ghidra |
| DeathResurrectedeventoneframecomponent | 12 | - | 0x108907d28 | ghidra |
| DeathResurrectionrequestoneframecomponent | 24 | - | 0x1088e0858 | ghidra |
| DeathStatecomponent | - | 4 | 0x1088e0038 | windows |
| DialogAdratelimitingdatacomponent | 32 | - | 0x1088dfa28 | ghidra |
| DialogAdratelimitinghistorycomponent | 64 | - | 0x1088fc0b0 | ghidra |
| DialogAutolistenrequestssingletoncomponent | - | - | 0x1088e0bc0 | typeid |
| DialogDialogstartedeventssingletoncomponent | - | - | 0x1088e0b18 | typeid |
| DialogFailedprivatedialogjoinattemptoneframecomponent | - | - | 0x1088e3460 | typeid |
| DialogStateComponent | 56 | - | - | ghidra |
| DisarmForceunequiprequestcomponent | - | - | 0x1088f66a0 | typeid |
| DisarmWeapondisarmedeventoneframecomponent | - | - | 0x1089098a0 | typeid |
| Displaynamelistcomponent | 40 | 16 | 0x1088f3ec8 | ghidra |
| DropDropentitieslistcomponent | 16 | - | 0x108906868 | ghidra |
| DropDropentitiestoprocesscomponent | 4 | - | 0x1088e0e08 | ghidra |
| DropDropentityexecutioncomponent | 32 | - | 0x1088e8d80 | ghidra |
| DropDropentitystatecomponent | 64 | - | 0x108906858 | ghidra |
| DropDropentitytargetcomponent | 48 | - | 0x1088f8da8 | ghidra |
| DropDropfinishedeventcomponent | 1 | - | 0x1088e0e98 | ghidra |
| DropSplitrequestsingletoncomponent | - | - | 0x1088f7170 | typeid |
| DualwieldingUnequiprequestcomponent | - | - | 0x1088f66d0 | typeid |
| Effect | 8 | - | - | ghidra |
| EffectPlayeffectrequestssingletoncomponent | - | - | 0x1088e5708 | typeid |
| EffectStopeffectrequestssingletoncomponent | - | - | 0x1088e8eb0 | typeid |
| EocAreaTrigger | 120 | - | - | ghidra |
| EocLevelComponent | 4 | - | - | ghidra |
| EocPointTrigger | 120 | - | - | ghidra |
| EscortFollowercomponent | 8 | 8 | 0x1088e13b8 | ghidra |
| EscortGrouprequestcompletedcomponent | 1 | - | 0x1088e6640 | ghidra |
| EscortGroupssingletoncomponent | 64 | - | 0x1088e1460 | ghidra |
| EscortHasstragglerscomponent (tag) | 1 | 1 | 0x1088e14b0 | ghidra |
| EscortIsfollowingcomponent | - | - | 0x1088e1040 | typeid |
| EscortLeaderchangessingletoncomponent | - | - | 0x108902530 | typeid |
| EscortLeadercomponent | 4 | 4 | 0x1088e1490 | ghidra |
| EscortLeaderprioritycomponent | 64 | 64 | 0x1088e13f0 | ghidra |
| EscortLeaderpriorityrequestcompletedcomponent | 1 | - | 0x1088e6630 | ghidra |
| EscortLeaderrequestcompletedcomponent | 1 | - | 0x1088e6620 | ghidra |
| EscortMembercomponent | 4 | 4 | 0x1088e10c0 | ghidra |
| EscortRequestfollowcomponent | - | - | 0x1088e1380 | typeid |
| EscortStragglerstrackercomponent | - | 32 | 0x1088e14a0 | windows |
| EventTrigger | 128 | - | - | ghidra |
| ExpExperiencegaveoutcomponent | 4 | 4 | 0x108908ee8 | ghidra |
| ExperienceComponent | 8 | - | - | ghidra |
| ExplorationTrigger | 144 | - | - | ghidra |
| Explorationawardstatecomponent | 16 | - | 0x1088e15d0 | ghidra |
| FallingDatacomponent | 192 | - | 0x1088ef9f8 | ghidra |
| FloorCharacterintriggerchangedcomponent | - | - | 0x1088e1738 | typeid |
| FloorIntriggercomponent | - | - | 0x1088e1748 | typeid |
| FloorTrigger | 128 | - | - | ghidra |
| FollowersComponent | 4 | - | - | ghidra |
| FtbSurfaceteamsingletoncomponent | 112 | 112 | 0x10890a9d0 | ghidra |
| FtbTimefactorrequestssingletoncomponent | - | 64 | 0x1088f49b8 | windows |
| FtbTimefactorresetrequestssingletoncomponent | - | 48 | 0x1088f49c8 | windows |
| FtbTurnbasedchangesrequestsingletoncomponent | - | 64 | 0x10890eb28 | windows |
| FtbTurnbasedcomponent | 8 | - | 0x1088f49d8 | ghidra |
| FtbZonecomponent | 72 | 72 | 0x10890e670 | ghidra |
| FtbZoneinstigatorcomponent | 16 | 16 | 0x1088f49a8 | ghidra |
| GameMasterComponent | 64 | - | - | ghidra |
| Gameplaylightequipmentcomponent | 48 | 48 | 0x1088e19f8 | ghidra |
| Gamestateloadlevelcomponent | - | - | 0x1088ea188 | typeid |
| Gamestateloadsessioncomponent | - | - | 0x1089053f0 | typeid |
| Gamestatereloadstorycomponent | - | - | 0x10890cf58 | typeid |
| Gamestatesavecomponent | - | - | 0x1088edcc8 | typeid |
| Gamestateunloadlevelcomponent | - | - | 0x10890d598 | typeid |
| Gamestateunloadsessioncomponent | - | - | 0x1089053c0 | typeid |
| Gametimercomponent | 40 | 40 | 0x1088fabf8 | ghidra |
| Gravityactivetimeoutcomponent | 4 | - | 0x1088e1ba8 | ghidra |
| Gravityinstigatorcomponent | 1 | - | 0x1088e1bb8 | ghidra |
| HealthComponent | 16 | - | - | ghidra |
| HistoryTargetcontainersingletoncomponent | - | - | 0x1088e96b8 | typeid |
| HistoryTargetpendingrequesterssingletoncomponent | - | - | 0x1088e96c8 | typeid |
| HistoryTargetstartrequestssingletoncomponent | - | - | 0x1088e9718 | typeid |
| HistoryTargetupdaterequestssingletoncomponent | - | - | 0x1088e98b0 | typeid |
| HistoryTargetuuidcomponent | 16 | 16 | 0x108904358 | ghidra |
| HitAttachproxyafterinitrequestcomponent | - | - | 0x1088e1d20 | typeid |
| HitHitnotificationeventoneframecomponent | 80 | - | 0x108902450 | ghidra |
| HitHitnotificationrequestoneframecomponent | 72 | - | 0x1088e1d78 | ghidra |
| HitRedirectiontrackingcomponent | - | - | 0x1088e5dc0 | typeid |
| HitUnresolvedhitnotificationcomponent | 16 | - | 0x1088e1ce8 | ghidra |
| HotbarOrdercomponent (tag) | 1 | 1 | 0x1088e4528 | ghidra |
| Iconlistcomponent | 16 | 16 | 0x1088f3ee8 | ghidra |
| IdentifiedComponent | 24 | - | - | ghidra |
| ImprovisedWeaponPickupdatacomponent | - | - | 0x10890a340 | typeid |
| InterruptActionrequestscomponent | - | 48 | 0x1088f6058 | windows |
| InterruptAddremoverequestscomponent | - | 64 | 0x1088f5f78 | windows |
| InterruptDataComponent | 16 | - | - | ghidra |
| InterruptDatasingletoncomponent | - | 32 | 0x1088f5bf8 | windows |
| InterruptInitialparticipantscomponent | - | 64 | 0x1088feb50 | windows |
| InterruptPreferencesComponent | 8 | - | - | ghidra |
| InterruptPreferencesrequestsingletoncomponent | - | - | 0x1088f5db8 | typeid |
| InterruptRequestsingletoncomponent | - | - | 0x1088f6088 | typeid |
| InterruptTimefactorrequestscomponent | - | - | 0x1088f6250 | typeid |
| InterruptTurnorderinzonecomponent | 48 | 48 | 0x10890ea58 | ghidra |
| InterruptZoneParticipantComponent | 8 | - | - | ghidra |
| InterruptZonerequestscomponent | - | 32 | 0x1088f61a8 | windows |
| InventoryCharacterhasgeneratedtradetreasurecomponent (tag) | 1 | 1 | 0x1088f7a80 | ghidra |
| InventoryContainerdatacomponent | 8 | 8 | 0x1088f7160 | ghidra |
| InventoryDataComponent | 32 | - | - | ghidra |
| InventoryDeferredcharacterdropanimationcomponent | - | - | 0x1088ed080 | typeid |
| InventoryDeferredequipmentrequestsoneframecomponent | - | - | 0x1088f6720 | typeid |
| InventoryEntityhasgeneratedtreasurecomponent (tag) | 1 | 1 | 0x1088f7a70 | ghidra |
| InventoryEquipmentinteractionrequestscomponent | - | - | 0x1088f6b20 | typeid |
| InventoryFailedaddsunloadrequestcomponent | - | - | 0x1088f6ff0 | typeid |
| InventoryGroupcheckcomponent | 4 | 4 | 0x1088f6a90 | ghidra |
| InventoryInteractionrequestscomponent | - | - | 0x108900f28 | typeid |
| InventoryInteractionrequestswithgroupcomponent | - | - | 0x1088f71a0 | typeid |
| InventoryInteractionrequestswithstackcomponent | - | - | 0x1088f7120 | typeid |
| InventoryInventoriescreatedsingletoncomponent | - | - | 0x1088f7c90 | typeid |
| InventoryInventoriesdestroyedsingletoncomponent | - | - | 0x1088f6e00 | typeid |
| InventoryIsloadedfromequipmentsetcomponent | - | - | 0x1088f6700 | typeid |
| InventoryIsreplicatedcomponent | 1 | - | 0x1088f6e40 | ghidra |
| InventoryIsreplicatedwithcomponent (tag) | 1 | 1 | 0x1088f6e30 | ghidra |
| InventoryLootablereactionqueuesingletoncomponent | 96 | - | 0x1088f7a40 | ghidra |
| InventoryMemberComponent | 16 | - | - | ghidra |
| InventoryMemberchangessingletoncomponent | - | - | 0x1088fa030 | typeid |
| InventoryMemberisreplicatedwithcomponent | 1 | - | 0x1088f6ca0 | ghidra |
| InventoryMemberscreatedsingletoncomponent | - | - | 0x1088fec10 | typeid |
| InventoryMemberunloadrequestcomponent | - | - | 0x1088f6fc0 | typeid |
| InventoryOriginalownerupdaterequestssingletoncomponent | - | - | 0x1088f7110 | typeid |
| InventoryOwnerComponent | 16 | - | - | ghidra |
| InventoryReadytobeaddedtoinventorycomponent (tag) | - | 1 | 0x1088f6b10 | windows |
| InventoryReequipstackcomponent | 64 | - | 0x1088f7588 | ghidra |
| InventoryReplicateinventoriesrequestcomponent | - | - | 0x1088fea80 | typeid |
| InventoryReplicatemembersrequestcomponent | - | - | 0x1088feab0 | typeid |
| InventoryReturntoownercomponent | 1 | - | 0x108900c50 | ghidra |
| InventoryReturntoownerequiprequestcomponent | - | - | 0x108900c20 | typeid |
| InventoryShapeshiftaddedequipmentcomponent | 16 | - | 0x1089079e8 | ghidra |
| InventoryShapeshiftequipmenthistorycomponent | 16 | 16 | 0x1088f6630 | ghidra |
| InventoryShapeshiftunequippedequipmentcomponent | 16 | - | 0x1088f8bf8 | ghidra |
| InventoryStackblockedduringtradecomponent | 1 | - | 0x1088f7150 | ghidra |
| InventorySummonrequestsingletoncomponent | - | - | 0x1088f7538 | typeid |
| InventoryTransferTransferlistssingletoncomponent | - | - | 0x108906848 | typeid |
| Inventorypropertycanbepickpocketedcomponent | 24 | 8 | 0x1088dff40 | ghidra |
| Inventorypropertyisdroppedondeathcomponent | 24 | 8 | 0x1088e2430 | ghidra |
| Inventorypropertyistradablecomponent | 24 | 8 | 0x1088e2500 | ghidra |
| IsGlobalComponent | 4 | - | - | ghidra |
| Ismarkedfordeletioncomponent (tag) | 1 | 1 | 0x1088fd0d8 | ghidra |
| Item | 2 | - | - | ghidra |
| ItemAnimationFallbacktimercomponent | 4 | - | 0x1088f8198 | ghidra |
| ItemAnimationPendingrequestcomponent | 2 | - | 0x1088f8028 | ghidra |
| ItemAnimationRequestsingletoncomponent | - | - | 0x1088f81a8 | typeid |
| ItemAnimationStatecomponent | 6 | - | 0x108902790 | ghidra |
| ItemComponent | 24 | - | - | ghidra |
| ItemConsumedsingletoncomponent | - | - | 0x1088fd108 | typeid |
| ItemDestroyingwaitingforanimationcomponent | - | - | 0x1088f8558 | typeid |
| ItemDestroyingwaitingforblueprintcomponent | - | - | 0x1088f8548 | typeid |
| ItemDestroyingwaitingfordeactivationcomponent | 2 | - | 0x1088fe920 | ghidra |
| ItemDestroyingwaitingforeffectcomponent | 4 | - | 0x1088f8538 | ghidra |
| ItemDestroyrequestcomponent | 128 | - | 0x1088e26c0 | ghidra |
| ItemDynamiclayerownercomponent | 4 | 4 | 0x1088fab08 | ghidra |
| ItemEntitymovingcomponent | 1 | - | 0x1088f8d88 | ghidra |
| ItemEquippedeventoneframecomponent | - | - | 0x108912e10 | typeid |
| ItemInusecomponent | 48 | - | 0x108914cc0 | ghidra |
| ItemMarkedfordestructionsingletoncomponent | - | - | 0x1088f98a0 | typeid |
| ItemMarkentityfordestructioncomponent | 1 | - | 0x108902640 | ghidra |
| ItemObjectinteractionsingletoncomponent | - | - | 0x108914cd0 | typeid |
| ItemUnequippedeventoneframecomponent | - | - | 0x108912e50 | typeid |
| ItemwallAnimationcomponent | 72 | - | 0x1088f9a90 | ghidra |
| ItemwallCreatecomponent | 200 | - | 0x1088f9a80 | ghidra |
| ItemwallCreatesurfacecapsuleoneframecomponent | 128 | - | 0x1088f9a20 | ghidra |
| ItemwallRequestsummononeframecomponent | 136 | - | 0x1088f9a50 | ghidra |
| Jumpfollowcomponent | 336 | 272 | 0x1088f0450 | ghidra |
| Leadercomponent | 48 | 48 | 0x1088e28b8 | ghidra |
| LevelComponent | 4 | - | - | ghidra |
| LevelInstancesloadedcomponent | - | - | 0x1088e9000 | typeid |
| LevelInventoryitemdatapopulatedcomponent (tag) | 1 | 1 | 0x1088e2ae8 | ghidra |
| LightGameplaylightchangescomponent | - | 12 | 0x1088e19e8 | windows |
| LightGameplaylightrefreshrequestcomponent | - | - | 0x1088e1a08 | typeid |
| LightGameplayobscuritycomponent | - | - | 0x1088e1b28 | typeid |
| LightUpdatedarknessrequestscomponent | - | - | 0x1088e05f8 | typeid |
| LightingTrigger | 144 | - | - | ghidra |
| LockComponent | 40 | - | - | ghidra |
| LockLockpickingstatecomponent | 112 | - | 0x108901808 | ghidra |
| LockNeedsvalidationcomponent | - | - | 0x1088e2d18 | typeid |
| LockNotificationeventoneframecomponent | 24 | - | 0x10890a2b0 | ghidra |
| LockStatechangecomponent | 1 | - | 0x108902330 | ghidra |
| LookatLifetimecomponent | - | - | 0x1088e62b0 | typeid |
| Moduleloadcomponent | - | - | 0x1088e7158 | typeid |
| Moduleunloadcomponent | - | - | 0x1088e2f48 | typeid |
| MoveEnterattackrangeeventoneframecomponent | 32 | - | 0x1088fcf38 | ghidra |
| MoveLeaveattackrangeeventoneframecomponent | 32 | - | 0x1088fcf68 | ghidra |
| MultiplayerDropinapprovalcanceledrequestssingletoncomponent | 48 | - | 0x1088e3520 | ghidra |
| MultiplayerDropinapprovalnewrequestssingletoncomponent | 48 | - | 0x1088e3500 | ghidra |
| MultiplayerDropinapprovalpendingrequestssingletoncomponent | 48 | - | 0x1088e2708 | ghidra |
| MultiplayerDropinapprovalprocessedrequestssingletoncomponent | 48 | - | 0x1088e3510 | ghidra |
| MultiplayerDropinccinprogresssingletoncomponent | - | - | 0x1088fc7b8 | typeid |
| MultiplayerDropindelayedplayerconnectrequestssingletoncomponent | 64 | - | 0x1088e0f20 | ghidra |
| MultiplayerNewplayerjoinblockedsingletoncomponent | 4 | - | 0x1088f7fb8 | ghidra |
| MultiplayerScriptoverridessingletoncomponent | 4 | - | 0x1088e3108 | ghidra |
| MultiplayerUserloadedlevelcomponent | 1 | - | 0x1088eb790 | ghidra |
| MultiplayerUsersettingscomponent | 1 | - | 0x1088eb688 | ghidra |
| MusicVolumeTrigger | 136 | - | - | ghidra |
| Musicvolumetriggerstatecomponent | 16 | 16 | 0x1088ea198 | ghidra |
| Netcomponent (tag) | 1 | 1 | 0x1088f6c90 | ghidra |
| OneTimeRewardRewardlistcomponent | - | - | 0x1088fa300 | typeid |
| OriginalTemplateComponent | 4 | - | - | ghidra |
| Osirispingrequestsingletoncomponent | 16 | 16 | 0x1088f9ce0 | ghidra |
| Osirissetdisplaytitlehiddenrequestssingletoncomponent | - | - | 0x1088f9cf0 | typeid |
| OwnershipIscurrentownercomponent | 48 | 48 | 0x1088e4560 | ghidra |
| OwnershipIslatestownercomponent | 48 | 48 | 0x1088e4580 | ghidra |
| OwnershipIsoriginalownercomponent | 48 | 48 | 0x1088e4570 | ghidra |
| OwnershipIspreviousownercomponent | 48 | 48 | 0x1088e4590 | ghidra |
| OwnershipOwneehistorycomponent | 24 | 24 | 0x108900c70 | ghidra |
| OwnershipOwneerequestcomponent | 48 | 24 | 0x108908da0 | ghidra |
| PartyAttachedtogroupeventoneframecomponent | - | - | 0x1089098d0 | typeid |
| PartyBlockdismisscomponent | 1 | - | 0x1088f56e8 | ghidra |
| PartyBlockdismissremovedoneframecomponent | - | - | 0x1088f56f8 | typeid |
| PartyDetachedfromgroupeventoneframecomponent | - | - | 0x1089098e0 | typeid |
| PartyEntitychangedpartyeventoneframecomponent | - | - | 0x1089098f0 | typeid |
| PartyExperiencerequestoneframecomponent | - | - | 0x1088f0350 | typeid |
| PartyMemberComponent | 4 | - | - | ghidra |
| PartyMemberparticipationrequestoneframecomponent | - | - | 0x1088e48b0 | typeid |
| PartyPartymergedeventoneframecomponent | - | - | 0x1088e75d8 | typeid |
| PartyPartyspliteventoneframecomponent | - | - | 0x1088e75e8 | typeid |
| PartyPostreloadstoryupdateeventoneframecomponent | - | - | 0x1088f03d0 | typeid |
| PartyPresetLevelupstatecomponent | - | - | 0x1088e4828 | typeid |
| PartyPresetLoadsessioncomponent | - | - | 0x1088e5c58 | typeid |
| PartyPresetLoadstatecomponent | - | - | 0x1088f6b00 | typeid |
| PartyRecipesunlockedeventoneframecomponent | - | - | 0x108909900 | typeid |
| PartyUpdatepartyfollowersrequestoneframecomponent | - | - | 0x1088f0390 | typeid |
| PartyUsersnapshotcomponent | 64 | - | 0x1088f0340 | ghidra |
| PartyViewupdatedeventoneframecomponent | - | - | 0x1088f56d8 | typeid |
| PassiveActiverollpassivescomponent | 24 | - | 0x1088fcc40 | ghidra |
| PassiveBasecomponent | - | - | 0x1088fd048 | windows |
| PassiveBoostscomponent | 832 | 8 | 0x1088fd068 | ghidra |
| PassiveBoostsupdatedeventoneframecomponent | - | - | 0x1088fd078 | typeid |
| PassivePersistentdatacomponent | 8 | 8 | 0x1088fcf98 | ghidra |
| PassivePostponedfunctorscomponent | 64 | - | 0x1088fcff8 | ghidra |
| PassiveScriptpassivescomponent | 16 | 48 | 0x1088fcf28 | ghidra |
| PassiveToggledpassivescomponent | 40 | 64 | 0x1088fce88 | ghidra |
| PatrolCaretcomponent | 84 | - | 0x1088e4a70 | ghidra |
| PatrolSplinescomponent | - | - | 0x1088f2470 | typeid |
| Peritempassivecooldowncomponent | - | - | 0x1088fda68 | typeid |
| Peritempassiverestoredcooldowncomponent | - | - | 0x1088fd968 | typeid |
| Peritemspellcooldowncomponent | - | - | 0x108905000 | typeid |
| Peritemspellsourcecomponent | 16 | - | 0x108904ff0 | ghidra |
| PhotoModeCapabilitycomponent | - | - | 0x1088e4fc8 | typeid |
| PhotoModeSessionfailedeventsingletoncomponent | - | - | 0x1088e4f78 | typeid |
| PickpocketPickpocketcomponent | 16 | - | 0x1088e50c8 | ghidra |
| PickupBeingpickedupcomponent | - | - | 0x1088fde90 | typeid |
| PickupLegacypickuprequestssingletoncomponent | - | - | 0x1088fe100 | typeid |
| PickupOriginalpickuptargetcomponent | 1 | - | 0x1088fe0f0 | ghidra |
| PickupPickupexecutionfailedsingletoncomponent | - | - | 0x1088fde60 | typeid |
| PickupPickupexecutioninflightcomponent | 8 | - | 0x1088fdd90 | ghidra |
| PickupPickupfailedtospendresourcesingletoncomponent | - | - | 0x1088fe258 | typeid |
| PickupPickupfinishedcomponent | 1 | - | 0x1088fdff8 | ghidra |
| PickupPickuppermissioncomponent | 48 | - | 0x1089027f0 | ghidra |
| PickupPickuppermissiongrantedcomponent | 1 | - | 0x1088fdfe8 | ghidra |
| PickupPickuprequestcomponent | 64 | - | 0x108906878 | ghidra |
| PickupPickupresultssingletoncomponent | - | - | 0x1088fdfb8 | typeid |
| PickupPickupsplitlistcomponent | 16 | - | 0x1088fe1d0 | ghidra |
| PickupPickupsplitrequestssingletoncomponent | - | - | 0x1088fe268 | typeid |
| PickupScriptpermissionresponsessingletoncomponent | - | - | 0x1088fdf78 | typeid |
| PickupSuccessfullypickedupsingletoncomponent | - | - | 0x1088fdd80 | typeid |
| PickupValidatedpickuprequestssingletoncomponent | - | - | 0x1088fe0d0 | typeid |
| Pingcooldownsingletoncomponent | 64 | 64 | 0x1088e5100 | ghidra |
| Pingrequestsingletoncomponent | 16 | 16 | 0x108902590 | ghidra |
| PlacementPlacementcomponent | - | - | 0x1088e51a8 | typeid |
| PlacementStatecomponent | - | - | 0x10890beb8 | typeid |
| PlacementValidationcomponent | 3 | - | 0x10890bf08 | ghidra |
| PlatformDestructioncomponent | - | - | 0x1088f8b28 | typeid |
| PlatformMovementcomponent | - | - | 0x1088e5478 | typeid |
| PlatformMovementcontinuecomponent | 1 | - | 0x1088e54d8 | ghidra |
| PlatformMovementpausedreasonscomponent | 8 | - | 0x1088e5488 | ghidra |
| PlatformMovementrequestcomponent | 56 | - | 0x1088e5468 | ghidra |
| PlatformOntopofdestroyedplatformcomponent | - | - | 0x1088e5628 | typeid |
| PlayerComponent | 16 | - | - | ghidra |
| PortalTrigger | 120 | - | - | ghidra |
| ProfileUpdaterequestoneframecomponent | - | - | 0x1088e5858 | typeid |
| ProfileUpdateshowntutorialsrequestoneframecomponent | - | - | 0x1088e5868 | typeid |
| ProgressionChangedcontainerscomponent | - | 64 | 0x1088fce58 | windows |
| ProgressionFeatmutingchangedeventoneframecomponent | - | - | 0x108905fc8 | typeid |
| Projectile | 4 | 432 | - | ghidra |
| ProjectileAttachmentcomponent | 8 | 8 | 0x108900c60 | ghidra |
| ProjectileInitializationcomponent | - | 24 | 0x1088f8c98 | windows |
| ProjectileSpellcomponent | 184 | 24 | 0x108905a20 | ghidra |
| RecruitRecruitedbycomponent | 8 | 8 | 0x1088fe8e0 | ghidra |
| RegionTrigger | 128 | - | - | ghidra |
| RelationBasefactionchangedeventoneframecomponent | - | - | 0x10890b748 | typeid |
| RelationRelationchangedeventoneframecomponent | - | - | 0x10890b6f8 | typeid |
| ReplicationDependencyComponent | 1 | - | - | ghidra |
| ReplicationPeersinrangecomponent | 16 | 16 | 0x1088fe940 | ghidra |
| ReplicationReplicationdependencycomponent | 8 | 8 | 0x1088fe880 | ghidra |
| ReplicationReplicationdependencyownercomponent | 16 | 16 | 0x1088fe890 | ghidra |
| ReposeEndreposerequestoneframecomponent | - | - | 0x1088f02e0 | typeid |
| ReposeReposeresulteventoneframecomponent | - | - | 0x1088e5df8 | typeid |
| ReposeUsedentitiestocleansingletoncomponent | 48 | - | 0x1088e5e48 | ghidra |
| RestPendingtypecomponent | 72 | 72 | 0x108907c08 | ghidra |
| RestResttyperequestcontentloadedcomponent | - | - | 0x10890c048 | typeid |
| RestShortrestconsumeresourcescomponent (tag) | - | 1 | 0x1088ec6c0 | windows |
| RestShortrestresulteventoneframecomponent | - | - | 0x1088fdb38 | typeid |
| RewardFillrewardinventoriesrequestcomponent | 128 | - | 0x108900e48 | ghidra |
| RewardGiverewardrequestcomponent | 16 | - | 0x108900e58 | ghidra |
| RewardTransferrewardsrequestcomponent | 64 | - | 0x108900e68 | ghidra |
| RollDeathsavingthrowfinishedeventoneframecomponent | - | - | 0x108908ff0 | typeid |
| RollStreamStreamscomponent | 40 | 48 | 0x108901550 | ghidra |
| RoomTrigger | 128 | - | - | ghidra |
| SafePositionUpdatedEventOneFrameComponent | 24 | - | - | ghidra |
| Safepositioncomponent | 16 | 16 | 0x108903e80 | ghidra |
| SaveCompletedOneFrameComponent | 1 | - | - | ghidra |
| SaveWorldPrepareEventComponent | 1 | - | - | ghidra |
| SavegameComponent | 80 | - | - | ghidra |
| Saveworldpreparebusycomponent | - | - | 0x1088e63a0 | typeid |
| Saveworldrequestcomponent | 264 | - | 0x1088e6390 | ghidra |
| Scalechangecomponent | - | - | 0x1088e7128 | typeid |
| ScreenFadeScreenfadeidtofadenamecomponent | - | - | 0x1088e65a0 | typeid |
| ScreenFadeScreenfadetimercomponent | - | - | 0x1088e65b0 | typeid |
| ScriptCompletedrequestssingletoncomponent | - | - | 0x1088e69f0 | typeid |
| ScriptEntercombatrequestsingletoncomponent | - | - | 0x1088f15d0 | typeid |
| ScriptEscortremoveallrequestsingletoncomponent | - | - | 0x1088e6990 | typeid |
| ScriptEscortsetcharactergrouprequestsingletoncomponent | - | - | 0x1088e69a0 | typeid |
| ScriptEscortsetleaderpriorityrequestsingletoncomponent | - | - | 0x1088e69b0 | typeid |
| ScriptEscortsetleaderrequestsingletoncomponent | - | - | 0x1088e69c0 | typeid |
| ScriptExecutingrequestcomponent | - | - | 0x1088e6a30 | typeid |
| ScriptIsmovingtotargetcomponent | - | - | 0x1088e66f0 | typeid |
| ScriptLevelloadstartedcomponent | - | - | 0x108903a90 | typeid |
| ScriptLightActivecomponent | - | - | 0x1088e6ea8 | typeid |
| ScriptLightEffectcomponent | - | - | 0x1088e6eb8 | typeid |
| ScriptLightEffectparameterscomponent | - | - | 0x1088e6f40 | typeid |
| ScriptLightLitcomponent | 1 | - | 0x1088e6f50 | ghidra |
| ScriptLightPlayeffectrequestssingletoncomponent | - | - | 0x1088e6e98 | typeid |
| ScriptLightStopeffectrequestssingletoncomponent | - | - | 0x1088e8ec0 | typeid |
| ScriptQueuedrequestssingletoncomponent | - | - | 0x1088e6a20 | typeid |
| ScriptResettutorialsmessagerequestsingletoncomponent | - | - | 0x1088e69d0 | typeid |
| ScriptSetcombatgrouprequestsingletoncomponent | - | - | 0x1088f1600 | typeid |
| ScriptSetrelationrequestsingletoncomponent | - | - | 0x1088e69e0 | typeid |
| Scriptpropertycanbepickpocketedcomponent (tag) | 1 | 1 | 0x1088dff30 | ghidra |
| Scriptpropertyisdroppedondeathcomponent (tag) | 1 | 1 | 0x1088e2420 | ghidra |
| Scriptpropertyistradablecomponent (tag) | 1 | 1 | 0x1088e24f0 | ghidra |
| ServerDisplayNameListComponent | 4 | - | - | ghidra |
| ServerReplicationDependencyOwnerComponent | 1 | - | - | ghidra |
| Servertimelineactordatacomponent | - | - | 0x10890bf38 | typeid |
| Servertimelinecreationconfirmationcomponent | 88 | - | 0x10890be58 | ghidra |
| Servertimelinedatacomponent | 24 | - | 0x10890bf98 | ghidra |
| Servertimelinedestructionconfirmationcomponent | - | - | 0x10890bf78 | typeid |
| Servertimelineworldcinematiccomponent | 16 | - | 0x10890bf48 | ghidra |
| SetGravityActiveRequestOneFrameComponent | 16 | - | - | ghidra |
| ShapeshiftAnubisstatecomponent | 32 | - | 0x1088c4758 | ghidra |
| ShapeshiftHealthreservationcomponent | 64 | 64 | 0x108907b18 | ghidra |
| ShapeshiftStatescomponent | 24 | 24 | 0x1089091a0 | ghidra |
| Shapeshiftcustomiconcomponent | 88 | - | 0x1088e2168 | ghidra |
| SightAggregateddatacomponent | - | 360 | 0x1088eb990 | windows |
| SightAggregatedgameplaylightdatacomponent | - | 160 | 0x1088dfb40 | windows |
| SightAigridviewshedcomponent | - | 72 | 0x1088e05d8 | windows |
| SightComponent | 96 | - | - | ghidra |
| SightEntityloscheckqueuecomponent | 112 | 112 | 0x1088eb980 | ghidra |
| SightEventsenabledcomponent (tag) | - | 1 | 0x1088eb960 | windows |
| SightLightloscheckqueuecomponent | 32 | 32 | 0x1088e2b20 | ghidra |
| SightSighteventsoneframecomponent | - | - | 0x108909910 | typeid |
| SightViewshedparticipantcomponent | - | - | 0x1088eb970 | typeid |
| SoundDistantsoundinfoproxycomponent | - | - | 0x1088e7020 | typeid |
| SoundDistantsoundstateproxycomponent | - | - | 0x1088fea00 | typeid |
| SoundDistantsoundstateusermapcomponent | - | - | 0x1088e0cf0 | typeid |
| SoundPlayserversoundrequestoneframecomponent | 24 | - | 0x1088e7080 | ghidra |
| SoundVolumeTrigger | 176 | - | - | ghidra |
| SpellCastCachecomponent | - | - | 0x108906698 | typeid |
| SpellCastCasthitdelaycomponent | - | - | 0x108905a40 | typeid |
| SpellCastCastrequestscomponent | - | - | 0x108904188 | typeid |
| SpellCastCastresponsiblecomponent | - | - | 0x1089041b8 | typeid |
| SpellCastClientinitiatedcomponent | - | - | 0x108905a90 | typeid |
| SpellCastExternalscomponent | - | - | 0x108906688 | typeid |
| SpellCastHitregistercomponent | - | - | 0x1089041d8 | typeid |
| SpellCastInterruptdatacomponent | - | - | 0x108906678 | typeid |
| SpellCastInterruptrequestscomponent | - | - | 0x108904158 | typeid |
| SpellCastInterruptresultscomponent | - | - | 0x108906e98 | typeid |
| SpellCastMovementcomponent | - | - | 0x108905cc8 | typeid |
| SpellCastMovementinfocomponent | - | - | 0x108904bd0 | typeid |
| SpellCastPendingrequestscomponent | - | - | 0x108904018 | typeid |
| SpellCastProjectilecachecomponent | - | - | 0x108906cd0 | typeid |
| SpellCastProjectilepathfindcachecomponent | - | - | 0x1089066d8 | typeid |
| SpellCastRandomIsservercontrolledcomponent | - | - | 0x1088f5918 | typeid |
| SpellCastRandomRequestcomponent | - | - | 0x1088ed210 | typeid |
| SpellCastStatecomponent | - | - | 0x10890a3a0 | typeid |
| SpellCastUnsheathfallbacktimercomponent | - | - | 0x108906668 | typeid |
| SpellCastZonerangecomponent | - | - | 0x1089043a8 | typeid |
| SpellModificationschangedeventoneframecomponent | - | - | 0x10890aec8 | typeid |
| SpellNewspellsaddedfromcharactercreationcomponent | - | - | 0x108905fa8 | typeid |
| SpellOndamagespellscomponent | 16 | 16 | 0x1088fa2c8 | ghidra |
| SpellSpellpreparedeventoneframecomponent | - | - | 0x10890aef8 | typeid |
| SpellSpellunpreparedeventoneframecomponent | - | - | 0x10890af28 | typeid |
| SplatterBasestatecomponent | - | - | 0x1088e78e8 | typeid |
| StartTrigger | 8 | - | - | ghidra |
| StatesComponent | 24 | - | - | ghidra |
| StatsChangeunequiplockrequestoneframecomponent | - | - | 0x1089079f8 | typeid |
| StatsLevelchangedoneframecomponent | 16 | - | 0x1083f2050 | ghidra |
| StatsProficiencyBaseproficiencycomponent | - | 16 | 0x1088e5820 | windows |
| StatsProficiencyIntrinsicwielderchangescomponent | - | - | 0x10890afc8 | typeid |
| StatsProficiencyProficiencygroupstatscomponent | 4 | 4 | 0x1088e57e8 | ghidra |
| StatusActivationeventoneframecomponent | - | - | 0x108913050 | typeid |
| StatusActivecomponent (tag) | - | 1 | 0x1088fd058 | windows |
| StatusAddedfromsaveloadcomponent (tag) | - | 1 | 0x108902400 | windows |
| StatusAuraContainercomponent | - | 16 | 0x1088e7c98 | windows |
| StatusAuracomponent (tag) | - | 1 | 0x1088e8000 | windows |
| StatusCausecomponent | 88 | 24 | 0x1089023f0 | ghidra |
| StatusContainerComponent | 4 | - | - | ghidra |
| StatusDangerousauracomponent | - | - | 0x1088e8030 | typeid |
| StatusDeactivationeventoneframecomponent | - | - | 0x108913080 | typeid |
| StatusDestroyrollcheckcomponent | - | - | 0x108901888 | typeid |
| StatusDifficultychangesingletoncomponent | - | - | 0x1088e87a0 | typeid |
| StatusDifficultymodifierscomponent | - | 64 | 0x1088e7a78 | windows |
| StatusOwnershipcomponent | 8 | 8 | 0x1089023e0 | ghidra |
| StatusPerformingcomponent | 4 | 4 | 0x1088e80b0 | ghidra |
| StatusRecoveryRecoverablestatuscomponent | - | - | 0x1088e7cd0 | typeid |
| StatusRecoveryRecoveryrequestscomponent | - | - | 0x1088e7ce0 | typeid |
| StatusRemoveonlongrestcomponent | - | - | 0x1088e8850 | typeid |
| StatusSoundstatecantvocalstatecomponent | - | - | 0x1088ef258 | typeid |
| StatusStatuscomponent | 40 | 40 | 0x1089023d0 | ghidra |
| StatusStatusrequestscomponent | - | 432 | 0x1088e8750 | windows |
| StatusUniquecomponent | 64 | 64 | 0x108907398 | ghidra |
| StatusUnsheathmusicalinstrumentcomponent | - | - | 0x1088e8180 | typeid |
| StealthComponent | 40 | - | - | ghidra |
| SteeringLifetimecomponent | - | - | 0x1088ea000 | typeid |
| SteeringStatecomponent | - | - | 0x1088e8db0 | typeid |
| SummonAnimationrequestcomponent | - | - | 0x1088f8b98 | typeid |
| SummonCombatlogentryrequestoneframecomponent | - | - | 0x1088e7730 | typeid |
| SummonContainerComponent | 24 | - | - | ghidra |
| SummonDespawndelaysingletoncomponent | - | - | 0x1088e09c8 | typeid |
| SummonIsunsummoningcomponent (tag) | 1 | 1 | 0x1088f8ae8 | ghidra |
| SummonRemoveconcentrationrequestoneframecomponent | 1 | - | 0x1088e09d8 | ghidra |
| SummonUsecasterpassivescomponent | - | - | 0x108906c18 | typeid |
| SurfaceLevelloadedcomponent | - | - | 0x1088e9010 | typeid |
| SurfacePathInfluencesComponent | 24 | - | - | ghidra |
| SurfaceSurfacecomponent | - | 24 | 0x10890aa40 | windows |
| SurfaceTrailcomponent | - | - | 0x1088e9020 | typeid |
| SwapPlacesLifetimecomponent | - | - | 0x1088e90d0 | typeid |
| TadpoleTreeCurrentresourcerequestssingletoncomponent | - | - | 0x1088ec650 | typeid |
| TagsAnubistagcomponent | 16 | 16 | 0x1088f3f18 | ghidra |
| TagsApplytagsrequestoneframecomponent | - | - | 0x1088e9318 | typeid |
| TagsBoosttagcomponent | 16 | 16 | 0x1088f3f28 | ghidra |
| TagsDebugtagcomponent | 16 | - | 0x1088e92e8 | ghidra |
| TagsDialogtagcomponent | 16 | 16 | 0x1088f3f08 | ghidra |
| TagsOsiristagcomponent | 16 | 16 | 0x1088fad48 | ghidra |
| TagsRacetagcomponent | 16 | 16 | 0x1088fe370 | ghidra |
| TagsTemplatetagcomponent | 16 | 16 | 0x1088f4028 | ghidra |
| TeleportHastargetoverridecomponent | 8 | - | 0x108903c98 | ghidra |
| TeleportIstargetoverridecomponent | - | - | 0x1088e9a10 | typeid |
| TeleportKeepalivecomponent | - | - | 0x10890aca0 | typeid |
| TeleportSpellcomponent | - | - | 0x10890acb0 | typeid |
| TeleportStatecomponent | - | - | 0x10890ac90 | typeid |
| TeleportTargetoverriderefcountssingletoncomponent | - | - | 0x1088e9a00 | typeid |
| ThrownThrownparameterscomponent | - | - | 0x1088e9c18 | typeid |
| TimelineDeferredendingstatecomponent | - | - | 0x10890bf58 | typeid |
| TimelineFadedinuserscomponent | - | - | 0x10890bf68 | typeid |
| TimelineFadeintimeoutsingletoncomponent | - | - | 0x1088e9d80 | typeid |
| TimelinePlayerfadeineventoneframecomponent | - | - | 0x108902720 | typeid |
| TimelineScripteventoneframecomponent | 32 | - | 0x1088e3590 | ghidra |
| TimelineTimelinebehaviorflagmodificationcomponent | 1 | - | 0x10890bfb8 | ghidra |
| TradeCantradesetcomponent | 1 | - | 0x1088ef118 | ghidra |
| TradeLegacycantradeprocessedcomponent | 1 | - | 0x1088ef108 | ghidra |
| TradeLegacycantraderequestssingletoncomponent | - | - | 0x1088f9d00 | typeid |
| TradePresenttradercomponent | 1 | - | 0x10890d538 | ghidra |
| TradeTraderhostiletoallplayerscomponent | 1 | - | 0x10890d568 | ghidra |
| TradeTraderhostiletoindivplayerscomponent | 48 | - | 0x10890cf78 | ghidra |
| TradeTradermapchangessingletoncomponent | - | - | 0x10890d4b8 | typeid |
| TradeTradermapmarkerlinkedwithcomponent | 8 | - | 0x10890d508 | ghidra |
| TrapDelayedrollfinishedeventssingletoncomponent | - | - | 0x1088ea070 | typeid |
| TrapDisarmattemptcomponent | 16 | 16 | 0x1089018d8 | ghidra |
| TrapDisarmingstatecomponent | 88 | - | 0x1088fab98 | ghidra |
| TrapNotificationeventoneframecomponent | 24 | - | 0x10890a2c0 | ghidra |
| TriggerCachedleaveeventscomponent | 16 | 16 | 0x1088f3f98 | ghidra |
| TriggerEventconfigcomponent | 1 | 1 | 0x1088f3120 | ghidra |
| TriggerLoadedhandledcomponent (tag) | 1 | 1 | 0x1088ea2a8 | ghidra |
| TriggerRegisteredforcomponent | 48 | 48 | 0x1088f3ff8 | ghidra |
| TriggerRegistrationsettingscomponent | 1 | 1 | 0x1088f3130 | ghidra |
| TriggerTriggerworldautotriggeredcomponent (tag) | 1 | 1 | 0x10890bea8 | ghidra |
| TriggerUpdatedregisteredforcomponent | 16 | 16 | 0x1088ea2b8 | ghidra |
| TriggerUpdatedregisteredforitemscomponent | 16 | 16 | 0x1088ea2e8 | ghidra |
| TurnBasedComponent | 72 | - | - | ghidra |
| TurnOrderComponent | 128 | - | - | ghidra |
| TurnOrderTimedOutOneFrameComponent (tag) | - | 1 | - | windows |
| TurnEndedEventOneFrameComponent | 16 | - | 0x1083f1810 | ghidra |
| TurnStartedEventOneFrameComponent | 16 | - | 0x1083f1848 | ghidra |
| TurnSurfaceteamsingletoncomponent | 112 | 112 | 0x10890e9c8 | ghidra |
| TurnSurfacetrackingcomponent | 48 | 48 | 0x10890aa30 | ghidra |
| Turnorderskippedcomponent (tag) | 1 | 1 | 0x10890ead8 | ghidra |
| TutorialActionresourceeventrequestssingletoncomponent | - | - | 0x108911988 | typeid |
| TutorialAttackhiteventrequestssingletoncomponent | - | - | 0x1089119b8 | typeid |
| TutorialDualwieldingeventrequestssingletoncomponent | - | - | 0x1089119e8 | typeid |
| TutorialFunctoreventrequestssingletoncomponent | - | - | 0x108911a18 | typeid |
| TutorialHotbardelayedremovesingletoncomponent | - | - | 0x108911220 | typeid |
| TutorialHotbareventrequestssingletoncomponent | - | - | 0x108911a48 | typeid |
| TutorialMagicpocketseventrequestssingletoncomponent | - | - | 0x108911a78 | typeid |
| TutorialMetamagiceventrequestssingletoncomponent | - | - | 0x108911aa8 | typeid |
| TutorialProfileeventdatacomponent | 56 | - | 0x108911b98 | ghidra |
| TutorialRolleventrequestssingletoncomponent | - | - | 0x108911ad8 | typeid |
| TutorialSaveeventrequestssingletoncomponent | - | - | 0x108911b08 | typeid |
| TutorialShowingsingletoncomponent | - | - | 0x1089121e0 | typeid |
| TutorialUieventrequestssingletoncomponent | - | - | 0x108911b38 | typeid |
| TutorialUseractioneventrequestssingletoncomponent | - | - | 0x108911b68 | typeid |
| TutorialValidatedeventrequestssingletoncomponent | - | - | 0x108911958 | typeid |
| UnsheathClimbingcomponent | - | - | 0x108912f30 | typeid |
| UnsheathCoatingcomponent | - | - | 0x108912f20 | typeid |
| UnsheathCombatjoiningcomponent | - | - | 0x108912f10 | typeid |
| UnsheathCombatleavingcomponent | - | - | 0x108912f00 | typeid |
| UnsheathCombiningcomponent | - | - | 0x108912ef0 | typeid |
| UnsheathConsumingcomponent | - | - | 0x108912ee0 | typeid |
| UnsheathDefaultcomponent | 8 | 8 | 0x108912ed0 | ghidra |
| UnsheathLockpickingcomponent | - | - | 0x108912ec0 | typeid |
| UnsheathResurrectcomponent | - | - | 0x108912eb0 | typeid |
| UnsheathScriptoverridecomponent | 16 | 16 | 0x108912ea0 | ghidra |
| UnsheathSpellanimationconcludedcomponent | - | - | 0x108912e90 | typeid |
| UnsheathSpellanimationlifetimecomponent | - | - | 0x108912e80 | typeid |
| UnsheathSummonedcomponent | - | - | 0x1089146f8 | typeid |
| UnsheathUserrequestcomponent | - | - | 0x108914890 | typeid |
| UseComponent | 40 | - | - | ghidra |
| UseSocketComponent | 16 | - | - | ghidra |
| UserReservedComponent | 24 | - | - | ghidra |
| UuidHistorymappingcomponent | 64 | - | 0x10890a370 | ghidra |
| UuidHistorytrackedcomponent | 1 | - | 0x1088f3fa8 | ghidra |
| Variablemanagercomponent (tag) | 1 | 1 | 0x1088eb928 | ghidra |
| ZoneSpellcomponent | 128 | - | 0x108915e60 | ghidra |
| ZoneStatecomponent | 1 | - | 0x108915e50 | ghidra |
|  | 1 | - | - | ghidra |
| CooldownTrackingComponent | 16 | - | - | ghidra |
| ResourceChangeResultsSingletonComponent | - | 16 | - | windows |
| ResourcesOnLastCombatTurnComponent | 64 | - | - | ghidra |
|  | 1 | - | - | ghidra |
| InProgressComponent | 24 | 24 | - | ghidra |
| StartRequestOneFrameComponent | - | 24 | - | windows |
| AiComponent | 1 | - | - | ghidra |
|  | 4 | - | - | ghidra |
| InterestingItemsAddedOneFrameComponent | 1 | - | - | ghidra |
| MemberChangedEventOneFrameComponent | 8 | - | - | ghidra |
|  | 3 | - | - | ghidra |
| ApplyRequestOneFrameComponent | 104 | - | - | ghidra |
| ApplyViaModRequestOneFrameComponent | 80 | - | - | ghidra |
| BaseUpdatedOneFrameComponent (tag) | - | 1 | - | windows |
| ChangedEventOneFrameComponent | 16 | - | - | ghidra |
| RemoveRequestOneFrameComponent | 48 | - | - | ghidra |
| StatusBoostsRefreshedOneFrameComponent | 16 | - | - | ghidra |
|  | 1 | - | - | ghidra |
| DataComponent | 152 | - | - | ghidra |
| EndLongRestOneFrameComponent | 16 | - | - | ghidra |
| PresenceComponent | 16 | - | - | ghidra |
| QualityComponent | 4 | - | - | ghidra |
| ReturnPointComponent | 16 | - | - | ghidra |
| SettingsComponent | 64 | - | - | ghidra |
| SuppliesSelectionStateChangedEventOneFrameComponent | 16 | - | - | ghidra |
| SuppliesToConsumeCacheSingletonComponent | 64 | - | - | ghidra |
| AutomatedDialogActorComponent | 40 | - | - | ghidra |
| DefinitionComponent | 168 | - | - | ghidra |
| ExternalResourcesComponent | 40 | - | - | ghidra |
| GameplayVisualComponent | 16 | - | - | ghidra |
| InheritedFactionRequestOneFrameComponent | 8 | - | - | ghidra |
| LoadingAnimationSetComponent | 16 | - | - | ghidra |
| SessionCommonComponent | 1 | - | - | ghidra |
| TurnActionsComponent | 336 | - | - | ghidra |
|  | 8 | - | - | ghidra |
| AppearanceComponent | 4 | - | - | ghidra |
| AppearanceVisualTagComponent | 16 | 16 | - | ghidra |
| BackupDefinitionComponent | 168 | - | - | ghidra |
| DebugFullDefinitionRequestOneFrameComponent | 440 | - | - | ghidra |
| DefinitionCommonComponent | 8 | - | - | ghidra |
| EquipmentSetRequestComponent | - | 64 | - | windows |
| FullDefinitionComponent | 136 | - | - | ghidra |
| GodComponent | 16 | 16 | - | ghidra |
| IsCustomComponent (tag) | 1 | 1 | - | ghidra |
| SessionOwnerComponent | 16 | - | - | ghidra |
| UpdatesComponent | - | 64 | - | windows |
|  | 1 | - | - | ghidra |
| CombatScheduledForDeleteOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| CombatStartedEventOneFrameComponent (tag) | - | 1 | - | windows |
| CombatStateComponent | 24 | - | - | ghidra |
| DelayedFanfareRemovedDuringCombatEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| GlobalCombatRequests | - | 16 | - | windows |
| IsInCombatComponent | 24 | - | - | ghidra |
| JoinInCurrentRoundFailedEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| JoinInCurrentRoundOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| LeftEventOneFrameComponent | 24 | - | - | ghidra |
| RequestCompletedEventOneFrameComponent (tag) | - | 1 | - | windows |
| SurprisedJoinRequestOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| SurprisedStealthRequestOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| ThreatRangeChangedEventOneFrameComponent (tag) | - | 1 | - | windows |
| AddToInventoryRequestOneFrameComponent | 56 | - | - | ghidra |
| ResultOneFrameComponent | 48 | - | - | ghidra |
| TransformedEntitiesOneFrameComponent | 48 | - | - | ghidra |
| UnlockRecipeOneFrameComponent | 48 | - | - | ghidra |
| OnConcentrationClearedEventOneFrameComponent | 24 | - | - | ghidra |
|  | 8 | - | - | ghidra |
| BehaviourRequestOneFrameComponent | 1 | - | - | ghidra |
|  | 4 | - | - | ghidra |
| ApplyKnockedOutOneFrameComponent | 24 | - | - | ghidra |
| DiedEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| OnDeathCompleteOneFrameComponent | 1 | - | - | ghidra |
| TickOneFrameComponent | 1 | - | - | ghidra |
|  | 1 | - | - | ghidra |
|  | 3 | - | - | ghidra |
| MemberChangedOneFrameComponent | 8 | - | - | ghidra |
|  | 3 | - | - | ghidra |
| FallToProneOneFrameComponent (tag) | - | 1 | - | windows |
|  | 2 | - | - | ghidra |
| ModeChangedEventOneFrameComponent | 16 | - | - | ghidra |
| PlayersTurnEndedEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| PlayersTurnStartedEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| RoundEndedEventOneFrameComponent (tag) | - | 1 | - | windows |
|  | 2 | - | - | ghidra |
| AnimationEventOneFrameComponent | 8 | - | - | ghidra |
| HitComponent | 344 | - | - | ghidra |
| HitResultEventOneFrameComponent | 488 | - | - | ghidra |
| OnRollsResolvedEventOneFrameComponent | 24 | - | - | ghidra |
| RequestOneFrameComponent | 1 | - | - | ghidra |
| CancelRequestOneFrameComponent | 1 | - | - | ghidra |
| SetPositionOneFrameComponent | 24 | - | - | ghidra |
| SetVisibilityOneFrameComponent | 1 | - | - | ghidra |
|  | 1 | - | - | ghidra |
| ConditionalRollAdjustmentOneFrameComponent | 136 | - | - | ghidra |
|  | 5 | - | - | ghidra |
| MemberRemovedEventOneFrameComponent | 16 | - | - | ghidra |
| DestroyingEventOneFrameComponent | 1 | - | - | ghidra |
| DestroyingWaitingForFadeOut | 16 | - | - | ghidra |
| TransformedOnDestroyEventOneFrameComponent | 1 | - | - | ghidra |
| ForcePushRequestOneFrameComponent | 96 | - | - | ghidra |
|  | 1 | - | - | ghidra |
| ActiveRollRequestOneFrameComponent | 1 | - | - | ghidra |
|  | 5 | - | - | ghidra |
| RewardListComponent | 16 | - | - | ghidra |
|  | 9 | - | - | ghidra |
|  | 1 | - | - | ghidra |
|  | 4 | - | - | ghidra |
| MigratableBoostsComponent | 144 | - | - | ghidra |
| PassiveBaseComponent | 8 | - | - | ghidra |
| PassivesUpdatedEventOneFrameComponent (tag) | - | 1 | - | windows |
| RequestTargetTrackingOneFrameComponent | 64 | - | - | ghidra |
| UsageCountIncrementedEventOneFrameComponent (tag) | - | 1 | - | windows |
|  | 2 | - | - | ghidra |
|  | 1 | - | - | ghidra |
| CapabilityComponent | - | 1 | - | windows |
| SessionFailedEventSingletonComponent | 1 | - | - | ghidra |
|  | 1 | - | - | ghidra |
|  | 1 | - | - | ghidra |
|  | 1 | - | - | ghidra |
|  | 1 | - | - | ghidra |
| LevelUpChangedOneFrameComponent (tag) | - | 1 | - | windows |
| SplitThrowableObjectRequestOneFrameComponent (tag) | - | 1 | - | windows |
|  | 1 | - | - | ghidra |
|  | 4 | - | - | ghidra |
| IsReplicatedComponent | 1 | - | - | ghidra |
| IsReplicatedWithComponent | 1 | - | - | ghidra |
| MemberIsReplicatedWithComponent | 1 | - | - | ghidra |
| PrototypeModificationComponent | 16 | - | - | ghidra |
|  | 1 | - | - | ghidra |
| RestCancelledEventOneFrameComponent | 1 | - | - | ghidra |
| RestFinishedEventOneFrameComponent | 1 | - | - | ghidra |
| RestTypeChosenEventOneFrameComponent | 80 | - | - | ghidra |
| RestTypeRequestOneFrameComponent | 1 | - | - | ghidra |
| ScriptPhaseStartedEventOneFrameComponent | 1 | - | - | ghidra |
| ScriptRestConfirmedEventOneFrameComponent | 1 | - | - | ghidra |
| StartRequestFailedEventOneFrameComponent | 1 | - | - | ghidra |
| UserCharacterRestedEventOneFrameComponent | 1 | - | - | ghidra |
| RestorePartyEventOneFrameComponent | 16 | - | - | ghidra |
| RollFinishedEventOneFrameComponent | - | 16 | - | windows |
| LoadComponent | 1 | - | - | ghidra |
|  | 3 | - | - | ghidra |
| EntityLosCheckResultComponent | 48 | - | - | ghidra |
| IgnoreSurfacesChangedEventOneFrameComponent (tag) | - | 1 | - | windows |
| StealthRollCancelOneFrameComponent (tag) | - | 1 | - | windows |
|  | 3 | - | - | ghidra |
| BookChangedOneFrameComponent (tag) | - | 1 | - | windows |
|  | 12 | - | - | ghidra |
| CacheComponent | - | 240 | - | windows |
| CastHitDelayComponent | 24 | 24 | - | ghidra |
| CastRequestsComponent | - | 64 | - | windows |
| CastResponsibleComponent | - | 8 | - | windows |
| ClientInitiatedComponent (tag) | - | 1 | - | windows |
| ExternalsComponent | 16 | 16 | - | ghidra |
| HitRegisterComponent | - | 16 | - | windows |
| InterruptDataComponent | - | 72 | - | windows |
| InterruptRequestsComponent | - | 64 | - | windows |
| InterruptResultsComponent | - | 64 | - | windows |
| MovementComponent | - | 24 | - | windows |
| MovementInfoComponent | - | 16 | - | windows |
| PendingRequestsComponent | 48 | 48 | - | ghidra |
| ProjectileCacheComponent | 984 | 152 | - | ghidra |
| ProjectilePathfindCacheComponent | 32 | 32 | - | ghidra |
| StateComponent | - | 64 | - | windows |
| UnsheathFallbackTimerComponent | - | 8 | - | windows |
| ZoneRangeComponent | - | 16 | - | windows |
| ResultEventOneFrameComponent | 104 | - | - | ghidra |
| AttributeFlagsChangedEventOneFrameComponent (tag) | - | 1 | - | windows |
| ClassesChangedEventOneFrameComponent (tag) | - | 1 | - | windows |
| StatsAppliedEventOneFrameComponent (tag) | - | 1 | - | windows |
|  | 4 | - | - | ghidra |
| DispelDestroyOneFrameComponent | 16 | - | - | ghidra |
| DownedChangedEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| LifeTimeComponent | 16 | - | - | ghidra |
| StatusIDComponent | 16 | - | - | ghidra |
| RemovedStatusAuraEffectEventOneFrameComponent | - | 24 | - | windows |
|  | 2 | - | - | ghidra |
|  | 1 | - | - | ghidra |
| AddConcentrationRequestOneFrameComponent | 72 | - | - | ghidra |
| AddToExistingConcentrationRequestOneFrameComponent | 16 | - | - | ghidra |
| AttachToProjectileRequestOneFrameComponent | 8 | - | - | ghidra |
| CreateBaseRequestOneFrameComponent | 24 | - | - | ghidra |
| DespawnRequestOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| ExpiredRequestOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| HandleSummonerEventRequestOneFrameComponent | 1 | - | - | ghidra |
| LateJoinPenaltyOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| OwnerSetEventOneFrameComponent | 8 | - | - | ghidra |
| PlaceInInventoryRequestOneFrameComponent | 16 | - | - | ghidra |
| ReservePartySlotRequestOneFrameComponent | 16 | - | - | ghidra |
| SetLifetimeRequestOneFrameComponent | 8 | - | - | ghidra |
| SpawnCreatedEventOneFrameComponent | 8 | - | - | ghidra |
| AddedPowerOneFrameComponent | 16 | - | - | ghidra |
| RemovedPowerOneFrameComponent | 16 | - | - | ghidra |
|  | 12 | - | - | ghidra |
|  | 3 | - | - | ghidra |
| FinishedEventOneFrameComponent | 32 | - | - | ghidra |
| TemplateChangedOneFrameComponent (tag) | - | 1 | - | windows |
| TemplateTransformedOneFrameComponent (tag) | - | 1 | - | windows |
| ActorControlComponent | 184 | - | - | ghidra |
| BackgroundActorRequestOneFrameComponent | 40 | - | - | ghidra |
| InterruptActorComponent | 16 | - | - | ghidra |
| RemovedOneShotActorOneFrameComponent | 16 | - | - | ghidra |
| TimelineActorVisibilityOneFrameComponent | 1 | - | - | ghidra |
| TimelineFadeClearRequestOneFrameComponent | 8 | - | - | ghidra |
|  | 1 | - | - | ghidra |
|  | 3 | - | - | ghidra |
| DisarmResultEventOneFrameComponent | 24 | - | - | ghidra |
|  | 6 | - | - | ghidra |
| RegionOnEventRequestOneFrameComponent | 64 | - | - | ghidra |
| TriggerInteractionsOneFrameComponent | 64 | - | - | ghidra |
| RoundEndedEventOneFrameComponent (tag) | - | 1 | - | windows |
|  | 2 | - | - | ghidra |
|  | 2 | - | - | ghidra |
|  | 2 | - | - | ghidra |
|  | 1 | - | - | ghidra |

---

## gui:: Components

| Component | Ghidra | Windows | TypeId | Source |
|-----------|--------|---------|--------|--------|
| InputTrackingsingletoncomponent | - | - | 0x108894088 | typeid |
| LariannetNotificationsingletoncomponent | - | - | 0x108892fc8 | typeid |
| LariannetPendingloggedincomponent | - | - | 0x108892ca0 | typeid |
| LariannetPendingplatformcomponent | - | - | 0x1088917b0 | typeid |
| ModCanceledmodsubscriptionordownloadsingletoncomponent | - | - | 0x108892e40 | typeid |
| ModRequestedmodssingletoncomponent | - | - | 0x108892e50 | typeid |
| RegistrationVmcharacterdatasingletoncomponent | - | - | 0x108896248 | typeid |
| RegistrationVmcombatdatasingletoncomponent | - | - | 0x108893770 | typeid |
| RegistrationVmdialoguedatasingletoncomponent | - | - | 0x108895060 | typeid |
| RegistrationVmglobaldatasingletoncomponent | - | - | 0x1088961e8 | typeid |
| RegistrationVminventorydatasingletoncomponent | - | - | 0x108895010 | typeid |
| RegistrationVminventoryregisteredsingletoncomponent | - | - | 0x108893b30 | typeid |
| RegistrationVmitemdatasingletoncomponent | - | - | 0x108896218 | typeid |
| RegistrationVmitemregisteredsingletoncomponent | - | - | 0x108894ef0 | typeid |
| RegistrationVmlocalplayerdatasingletoncomponent | - | - | 0x1088961a8 | typeid |
| RegistrationVmlocalplayerregisteredsingletoncomponent | - | - | 0x108894180 | typeid |
| RegistrationVmpassivedatasingletoncomponent | - | - | 0x108894f60 | typeid |
| RegistrationVmpassivefromtadpolecomponent | - | - | 0x108893e98 | typeid |
| RegistrationVmpassiveregisteredsingletoncomponent | - | - | 0x108894f30 | typeid |
| RegistrationVmremoteplayerdatasingletoncomponent | - | - | 0x108894190 | typeid |
| RegistrationVmremoteplayerregisteredsingletoncomponent | - | - | 0x1088941a0 | typeid |
| TooltipsWorldtooltipscomponent | - | - | 0x1088961d8 | typeid |
| Uireadycomponent | - | - | 0x1088941b0 | typeid |
| VmcharacterCharactermodechangedsingletoncomponent | - | - | 0x108894d80 | typeid |
| VmcharacterVmcharacteractivatedsingletoncomponent | - | - | 0x108894e90 | typeid |
| VmcharacterVmcharacterdeferredactivationsingletoncomponent | - | - | 0x1088917c0 | typeid |

---

## ls:: Components

| Component | Ghidra | Windows | TypeId | Source |
|-----------|--------|---------|--------|--------|
| Activeskeletonslotscomponent | 16 | 16 | 0x108935df8 | ghidra |
| Activevfxtextkeyscomponent | - | - | 0x1089360e8 | typeid |
| Alwaysupdateeffectcomponent (tag) | 1 | 1 | 0x1089363d8 | ghidra |
| AnimationAnimationwaterfallcomponent | 32 | 32 | 0x108936108 | ghidra |
| AnimationBlueprintoverridecomponent | 4 | - | 0x108940140 | ghidra |
| AnimationDynamicanimationtagscomponent | 16 | 16 | 0x10893a4e8 | ghidra |
| AnimationGameplayeventssingletoncomponent | - | 16 | 0x108936148 | windows |
| AnimationInstancechangedeventssingletoncomponent | - | - | 0x108936168 | typeid |
| AnimationStoredposecomponent | 144 | - | 0x108935e48 | ghidra |
| AnimationTemplateanimationsetoverridecomponent | 16 | 16 | 0x10893a4d8 | ghidra |
| AnimationTextkeyeventssingletoncomponent | - | 16 | 0x1089361d8 | windows |
| Animationblueprintcomponent | 8 | 48 | 0x108940130 | ghidra |
| Animationsetcomponent | 8 | 24 | 0x108940ab8 | ghidra |
| Animationupdatecomponent (tag) | 1 | 1 | 0x108935e68 | ghidra |
| AnubisActivecomponent | - | - | 0x108916ae8 | typeid |
| AnubisAnubistreecomponent | - | - | 0x1089169f8 | typeid |
| AnubisConfigcomponent | - | - | 0x1089169d8 | typeid |
| AnubisDebugDebugeventcomponent | - | - | 0x1089161a0 | typeid |
| AnubisDebugHistorycomponent | - | - | 0x108916ad8 | typeid |
| AnubisEnabledcomponent | 1 | - | 0x108916ac8 | ghidra |
| AnubisErrorcomponent | - | - | 0x108917dc0 | typeid |
| AnubisEventsforwardingcomponent | 16 | - | 0x1089171c8 | ghidra |
| AnubisGameintermediatesingletoncomponent | - | - | 0x1089169a8 | typeid |
| AnubisNonpersistentcomponent | - | - | 0x1089169e8 | typeid |
| AnubisPausedcomponent | - | - | 0x108916af8 | typeid |
| AnubisPendingstatecomponent | - | - | 0x108916968 | typeid |
| AnubisReinitializingcomponent | - | - | 0x1089169b8 | typeid |
| AnubisRuntimecomponent | 144 | - | 0x108916a08 | ghidra |
| AnubisSavegameLoadingcomponent | - | - | 0x108916a38 | typeid |
| AnubisSavegameLoadingstatecomponent | - | - | 0x108916a28 | typeid |
| AnubisSavegameReloadingcomponent | - | - | 0x1089169c8 | typeid |
| AnubisSavegameRestoringstatecomponent | - | - | 0x108916aa8 | typeid |
| AnubisSavegameStatecomponent | 136 | - | 0x108916a78 | ghidra |
| AnubisSavegameWaitingforconfigchangecomponent | - | - | 0x108916ab8 | typeid |
| AnubisSystemhelpersingletoncomponent | - | - | 0x108916998 | typeid |
| AnubisTointerruptstatecomponent | - | - | 0x108916978 | typeid |
| AnubisTreecomponent | 4 | - | 0x108917db0 | ghidra |
| AnubisUnselectedstatecomponent | - | - | 0x108916988 | typeid |
| ArcBallCameraBehavior | 36 | - | - | ghidra |
| Cameracomponent | 176 | 32 | 0x10893ff18 | ghidra |
| Cinematiclevelinstancecomponent | - | - | 0x10893b240 | typeid |
| Clothloadedcomponent | - | - | 0x108934ec0 | typeid |
| Clothteleportdatacomponent | 8 | - | 0x10889fa68 | ghidra |
| ClusterChildChangedOneFrameComponent | 16 | - | - | ghidra |
| Clusterattachrequestcomponent | 1 | - | 0x10893ad38 | ghidra |
| Clusterboundcomponent | 24 | - | 0x108936278 | ghidra |
| Clusterboundmaxcomponent | 4 | - | 0x108936288 | ghidra |
| Clusterchildcomponent | 8 | - | 0x10893d0f8 | ghidra |
| Clusterchildindexedcomponent | - | - | 0x108936228 | typeid |
| Clustercomponent | 1 | - | 0x108936238 | ghidra |
| Clustercontainercomponent | - | - | 0x108936248 | typeid |
| Clustercontentcomponent | 48 | - | 0x108936268 | ghidra |
| Clusterculldatacomponent | 8 | - | 0x10893d138 | ghidra |
| Clusterdistmaxcomponent | 4 | - | 0x10893cfd0 | ghidra |
| Clusterdistmincomponent | 4 | - | 0x108936298 | ghidra |
| Clusterindexcomponent | - | - | 0x108936258 | typeid |
| Clusterphysicsalwaysloadedcomponent | - | - | 0x10891af58 | typeid |
| Clusterphysicscontentcomponent | - | - | 0x108936308 | typeid |
| Clusterphysicsloadedcomponent | - | - | 0x108936318 | typeid |
| Clusterphysicsloadingcomponent | - | - | 0x108936328 | typeid |
| Clusterphysicspartialloadingcomponent | - | - | 0x108936338 | typeid |
| Clusterphysicsregisterysingletoncomponent | - | - | 0x108936348 | typeid |
| Clusterphysicsvisibilitycomponent | - | - | 0x1089362b8 | typeid |
| Clusterpositionxcomponent | 4 | - | 0x10893d010 | ghidra |
| Clusterpositionycomponent | 4 | - | 0x10893d000 | ghidra |
| Clusterpositionzcomponent | 4 | - | 0x10893cff0 | ghidra |
| Clusterradiuscomponent | 4 | - | 0x10893cfe0 | ghidra |
| Clustervisibilitycomponent | - | - | 0x1089362a8 | typeid |
| Clustervisibilityregisterysingletoncomponent | - | - | 0x1089362f8 | typeid |
| Clustervisualcontentcomponent | - | - | 0x1089362c8 | typeid |
| Clustervisualloadedcomponent | - | - | 0x10893d458 | typeid |
| Clustervisualloadingcomponent | - | - | 0x1089362d8 | typeid |
| Clustervisualpartialloadingcomponent | - | - | 0x1089362e8 | typeid |
| ConstellationComponent | - | - | 0x108917540 | typeid |
| Construction | 8 | - | - | ghidra |
| ConstructionFilling | 8 | - | - | ghidra |
| ConstructionTile | 8 | - | - | ghidra |
| Constructiontilebonetransformsetcomponent | 16 | - | 0x1089352e8 | ghidra |
| Copyparentvisibilitycomponent | 8 | - | 0x1089364f8 | ghidra |
| Cullcomponent | 2 | 2 | 0x10893bb80 | ghidra |
| Culltriggerplanescomponent | 112 | - | 0x10893f180 | ghidra |
| Debugcomponent | 16 | - | 0x10893f190 | ghidra |
| Decalcomponent | 8 | 16 | 0x108936428 | ghidra |
| DefaultCameraBehavior | 28 | 28 | - | ghidra |
| EditorCameraBehavior | 64 | - | - | ghidra |
| EffectCameraBehavior | 12 | 16 | - | ghidra |
| EffectCreateOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| Effectcomponent | 8 | 120 | 0x10893cdc0 | ghidra |
| Effectsoundentityattachedcomponent | - | - | 0x1089363b8 | typeid |
| Fadeableobstructioncomponent | 72 | - | 0x108935ab0 | ghidra |
| Fadeableobstructionhierarchysingletoncomponent | - | - | 0x108935ad0 | typeid |
| Fadeableobstructionmappingsingletoncomponent | - | - | 0x108935ac0 | typeid |
| Fadegroupcomponent | - | - | 0x108935968 | typeid |
| Fadegroupmappingsingletoncomponent | - | - | 0x108935938 | typeid |
| Fadingentitiesforrenderingsingletoncomponent | - | - | 0x10893d388 | typeid |
| Fadingview0Component | - | - | 0x10893c218 | typeid |
| Fadingview1Component | - | - | 0x10893c208 | typeid |
| Fogvolumecomponent | 296 | - | 0x10893f878 | ghidra |
| GamePausecomponent (tag) | 1 | 1 | 0x10893e8f0 | ghidra |
| GamePauseexcludedcomponent (tag) | - | 1 | 0x10893e930 | windows |
| GameplaySoundSetupRequestOneFrameComponent | 64 | - | - | ghidra |
| Gameplayeffectsettimefactorrequestssingletoncomponent | - | 64 | 0x1089363e8 | windows |
| Gameplayglobalsoundrequestssingletoncomponent | - | - | 0x10893a728 | typeid |
| Gameplayloadedsoundscomponent | - | - | 0x10893a5b8 | typeid |
| Gameplaysoundeventrequestbuscomponent | - | - | 0x10893a668 | typeid |
| Gameplaysoundrtpcglobalresetrequestbuscomponent | - | - | 0x10893a6f8 | typeid |
| Gameplaysoundrtpcrequestbuscomponent | - | - | 0x10893a6c8 | typeid |
| Gameplaysoundswitchrequestbuscomponent | - | - | 0x10893a698 | typeid |
| Gameplaysoundtransferrequestbuscomponent | - | - | 0x10893a638 | typeid |
| Gameplayvfxsetplaytimerequestssingletoncomponent | - | 64 | 0x1089363f8 | windows |
| Gameplayvfxsingletoncomponent | - | 16 | 0x108936408 | windows |
| Hizcomponent | 16 | - | 0x10893c268 | ghidra |
| Hlodchildcomponent | 8 | - | 0x10893ad28 | ghidra |
| Hlodcomponent | - | - | 0x10893d128 | typeid |
| Incinematiclevelinstancecomponent | - | - | 0x10893ae10 | typeid |
| Instancingbatchcomponent | 48 | - | 0x10893aec0 | ghidra |
| Instancingbatchinitializedcomponent | - | - | 0x10893aee0 | typeid |
| Instancingbatchloadcomponent | 8 | - | 0x10893aef0 | ghidra |
| Instancingbatchloadedcomponent | - | - | 0x10893af20 | typeid |
| Instancingbatchregisteredcomponent | - | - | 0x10893ae70 | typeid |
| Instancingbatchvisualcomponent | - | - | 0x10893ae90 | typeid |
| Instancingfolderloaderbusycomponent | - | - | 0x10893aed0 | typeid |
| Instancingfolderloadercomponent | - | - | 0x10893ae80 | typeid |
| Instancinggroupcomponent | 104 | - | 0x10893aeb0 | ghidra |
| Instancinggroupvisualcomponent | - | - | 0x10893aea0 | typeid |
| InvisibleClimbingHelper | 8 | - | - | ghidra |
| Isglobalcomponent (tag) | 1 | 1 | 0x10893f0c0 | ghidra |
| Isseethroughcomponent (tag) | - | 1 | 0x10893d628 | windows |
| LevelCacheloadcomponent | - | - | 0x10893b310 | typeid |
| LevelCacherequiredcomponent | - | - | 0x10893b138 | typeid |
| LevelInstanceLoadedOneFrameComponent (tag) | - | 1 | - | windows |
| LevelInstanceUnloadedOneFrameComponent (tag) | - | 1 | - | windows |
| LevelLevelinstancebackgroundloadingcomponent | - | - | 0x10893b2f0 | typeid |
| LevelLevelinstanceloadingcomponent | - | - | 0x10893b4a8 | typeid |
| LevelLevelinstanceloadstatecomponent | 1 | - | 0x10893b498 | ghidra |
| LevelLevelinstancetempdestroyedcomponent | 8 | 8 | 0x10893b230 | ghidra |
| LevelLevelinstanceunloadingcomponent (tag) | - | 1 | 0x10893b468 | windows |
| LevelUnloadedOneFrameComponent | 4 | - | - | ghidra |
| Levelcomponent | 16 | 16 | 0x10893e780 | ghidra |
| Levelinstancecomponent | 64 | 64 | 0x10893d258 | ghidra |
| Levelinstanceloadcomponent | 1 | - | 0x10893d288 | ghidra |
| Levelinstancestatecomponent | 208 | 184 | 0x10893d268 | ghidra |
| Levelisownercomponent (tag) | 1 | 1 | 0x10893b1a8 | ghidra |
| Levelprepareunloadbusycomponent (tag) | - | 1 | 0x108935ed8 | windows |
| Levelrootcomponent | 4 | 4 | 0x10893b438 | ghidra |
| Levelunloadbusycomponent (tag) | - | 1 | 0x10893b448 | windows |
| Lightcomponent | 272 | - | 0x10893f868 | ghidra |
| Lightflickercomponent | 12 | - | 0x10893bb60 | ghidra |
| Lightmovementcomponent | 12 | - | 0x10893bb70 | ghidra |
| Lightprobecomponent | 232 | - | 0x10893d0e8 | ghidra |
| Lightprobehierarchysingletoncomponent | - | - | 0x10893b938 | typeid |
| Lightprobeloadcomponent | 8 | - | 0x10893ba38 | ghidra |
| Lightprobeloadedcomponent | - | - | 0x10893ba18 | typeid |
| Lightprobeloaderregisteredcomponent | - | - | 0x10893ba28 | typeid |
| Lightprobertreesingletoncomponent | - | - | 0x10893b948 | typeid |
| Localboundcomponent | 24 | - | 0x108940298 | ghidra |
| Occlusioncomponent | 8 | - | 0x10893c1e8 | ghidra |
| OrthoCameraBehavior | 40 | - | - | ghidra |
| Outlinecomponent | - | - | 0x108936358 | typeid |
| Outlineentitiesforrenderingsingletoncomponent | - | - | 0x108936378 | typeid |
| Ownedbyeffectcomponent | - | - | 0x108936418 | typeid |
| Parententitycomponent | 8 | - | 0x10893d8a0 | ghidra |
| PhotoModeActivatedcomponent | - | - | 0x10893c3f0 | typeid |
| PhotoModeBrightnesscomponent | - | - | 0x10893c440 | typeid |
| PhotoModeColorgradingcomponent | - | - | 0x10893c450 | typeid |
| PhotoModeDofcomponent | - | - | 0x10893c400 | typeid |
| PhotoModeExposurecomponent | - | - | 0x10893c460 | typeid |
| PhotoModeFovcomponent | - | - | 0x10893c430 | typeid |
| PhotoModeSessionsingletoncomponent | - | - | 0x10893c3e0 | typeid |
| PhotoModeVignettecomponent | - | - | 0x10893c470 | typeid |
| Physicscomponent | 24 | 24 | 0x10893c8e8 | ghidra |
| Physicscreateoneframecomponent | - | - | 0x10893c658 | typeid |
| Physicsloadcomponent | 24 | - | 0x10893c648 | ghidra |
| Physicsloadedcomponent | 1 | - | 0x10893c678 | ghidra |
| Physicsloaderregisteredcomponent | - | - | 0x10893c668 | typeid |
| Physicsmodificationoneframecomponent | - | - | 0x10893c808 | typeid |
| Physicspathloaddesciptioncomponent | 24 | - | 0x10893c698 | ghidra |
| Physicsreloadoneframecomponent | - | - | 0x10893c6a8 | typeid |
| Physicsresourceloaddesciptioncomponent | 8 | - | 0x10893c688 | ghidra |
| Physicsskinnedconnectedtocomponent | 48 | - | 0x1088faf18 | ghidra |
| Physicsskinnedconnectioncomponent | 48 | - | 0x10893c860 | ghidra |
| Physicsstreamloadcomponent | 1 | - | 0x10893c6b8 | ghidra |
| Roomtriggertagcomponent | 1 | - | 0x1089361f8 | ghidra |
| SavegameLoadedcomponent | - | - | 0x108940cc8 | typeid |
| Savegamecomponent (tag) | 1 | 1 | 0x108935ff8 | ghidra |
| Savewithcomponent | 8 | - | 0x108936018 | ghidra |
| Scene | 8 | - | - | ghidra |
| Sceneattachcomponent | 8 | 8 | 0x108940150 | ghidra |
| Scenedestroywithlastdetachedobjectcomponent | - | - | 0x10893d108 | typeid |
| Scenerootcomponent | - | - | 0x108936598 | typeid |
| Scrollingobjectcomponent | 48 | - | 0x10893d278 | ghidra |
| Seethroughstatecomponent | 64 | - | 0x1089360c8 | ghidra |
| Setcharacterlightcullflagsrequestssingletoncomponent | - | - | 0x1089365b8 | typeid |
| Setlightcullflagsrequestssingletoncomponent | - | - | 0x1089365a8 | typeid |
| Skeletonsoundobjectscomponent | 256 | - | 0x10893d860 | ghidra |
| Skeletonsoundobjecttransformcomponent | 44 | - | 0x10893d7e0 | ghidra |
| Soundactivatedcomponent | 1 | - | 0x10893d810 | ghidra |
| Soundactivationchangessingletoncomponent | - | - | 0x10893d870 | typeid |
| Soundcameracomponent | 64 | - | 0x10893d5f8 | ghidra |
| Soundcomponent | 32 | 32 | 0x10893db58 | ghidra |
| Soundlistenercomponent | - | - | 0x10893d608 | typeid |
| Soundmaterialcomponent | - | - | 0x10893d570 | typeid |
| Soundmultipositioncomponent | - | - | 0x10893d800 | typeid |
| Soundocclusiondatacomponent | - | - | 0x10893d840 | typeid |
| Soundocclusionfiltercomponent | - | - | 0x10893d618 | typeid |
| Soundocclusionsettingscomponent | - | - | 0x10893d5a8 | typeid |
| Soundroomcurrentstatecomponent | 1 | - | 0x108936498 | ghidra |
| Soundroomlistenercomponent | - | - | 0x108936478 | typeid |
| Soundroomneighborstatecomponent | 32 | - | 0x10893d850 | ghidra |
| Soundroomstatecomponent | - | - | 0x10893d7a0 | typeid |
| Soundusestransformcomponent | - | - | 0x10893d7d0 | typeid |
| Soundvirtualpositioncomponent | - | - | 0x10893d7f0 | typeid |
| Splinecomponent | 8 | - | 0x108936038 | ghidra |
| Staticlevelphysicscomponent | 8 | - | 0x10893b900 | ghidra |
| Staticphysicscomponent | 8 | 8 | 0x1088f3ea8 | ghidra |
| Staticphysicsparentcomponent | - | - | 0x1088f3eb8 | typeid |
| TerrainObject | 8 | - | - | ghidra |
| Terraincreatecomponent | - | - | 0x10893e740 | typeid |
| Terrainloadcomponent | 16 | - | 0x10893e730 | ghidra |
| Terrainloadedcomponent | - | - | 0x10893e770 | typeid |
| Terrainloaderregisteredcomponent | - | - | 0x10893e750 | typeid |
| Timefactorcomponent | 4 | 4 | 0x10893e920 | ghidra |
| TransformGameplaysettransformrequestscomponent | 128 | - | 0x10893edc8 | ghidra |
| TransformInventorymembersettransformrequestcomponent | 64 | - | 0x10893edf8 | ghidra |
| TransformInventorymembersettranslaterequestcomponent | - | - | 0x10893ee28 | typeid |
| TransformLevelinstancemovesettransformrequestscomponent | - | - | 0x10893ee58 | typeid |
| TransformScrollingobjectsettranslaterequestscomponent | - | - | 0x10893ee68 | typeid |
| Transformcomponent | 40 | 8 | 0x108940550 | ghidra |
| TriggerAreacomponent | 136 | 32 | 0x10893f578 | ghidra |
| TriggerContainercomponent | 64 | 64 | 0x108934fe0 | ghidra |
| TriggerIsinsideofcomponent | 16 | 16 | 0x1088f3f88 | ghidra |
| TriggerUpdatedcontainercomponent | 16 | 16 | 0x1088ea258 | ghidra |
| TriggerUpdatedinsideofcomponent | - | - | 0x1088a0530 | typeid |
| TriggerUpdatedphysicscomponent | 16 | 16 | 0x10893f280 | ghidra |
| UgcGametagscomponent | - | - | 0x10893cab0 | typeid |
| UgcUserdatacomponent | - | - | 0x10893ca80 | typeid |
| UuidComponent | 16 | 16 | 0x10893f6f8 | ghidra |
| UuidTohandlemappingcomponent | 64 | 64 | 0x10893f6c8 | ghidra |
| VisualAttachRequestOneFrameComponent | - | 16 | - | windows |
| VisualChangeRequestOneFrameComponent | - | 8 | - | windows |
| VisualChangedEventOneFrameComponent (tag) | 1 | 1 | - | ghidra |
| Visualcomponent | 16 | 16 | 0x108940110 | ghidra |
| Visualloadcomponent | - | - | 0x10893f978 | typeid |
| Visualloaddesciptioncomponent | 8 | 8 | 0x1089402c8 | ghidra |
| Visualloadedcomponent (tag) | 1 | 1 | 0x1089402a8 | ghidra |
| Visualloaderregisteredcomponent | - | - | 0x10893f948 | typeid |
| Visualloadrequestssingletoncomponent | - | 64 | 0x10893f910 | windows |
| Visualstreamcomponent | 16 | - | 0x10893fea8 | ghidra |
| Visualstreamervisiblecomponent | - | - | 0x10893fee8 | typeid |
| Visualstreamhintcomponent | 4 | - | 0x10893ff28 | ghidra |
| Visualstreaminitializedcomponent | - | - | 0x10893fec8 | typeid |
| Visualstreamloadcomponent | 8 | - | 0x10893f958 | ghidra |
| Visualstreamsystemdatacomponent | - | - | 0x10893feb8 | typeid |
| WorldMapCameraBehavior | 32 | - | - | ghidra |
| AnimationSetUpdateRequestComponent (tag) | 1 | 1 | - | ghidra |
| LoadAnimationSetGameplayRequestOneFrameComponent | 16 | - | - | ghidra |
| RemoveAnimationSetsGameplayRequestOneFrameComponent | 48 | - | - | ghidra |
| FrameworkReloadedOneFrameComponent | 1 | - | - | ghidra |
| LoadCompleteOneFrameComponent | 1 | - | - | ghidra |
| LoadRequestOneFrameComponent | 8 | - | - | ghidra |
| SaveStateComponent | 56 | - | - | ghidra |
| NextSceneStageOneFrameComponent | 1 | - | - | ghidra |
| SceneStageComponent | 4 | - | - | ghidra |

---

## navcloud:: Components

| Component | Ghidra | Windows | TypeId | Source |
|-----------|--------|---------|--------|--------|
| AgentChangedOneFrameComponent | 1 | - | - | ghidra |
| Agentcomponent | 4 | - | 0x10891ab50 | ghidra |
| GenerateGeneratedatacomponent | - | - | 0x10891a858 | typeid |
| GenerateIswaitingforgeneratecomponent | 1 | - | 0x10891aa20 | ghidra |
| GenerateZonecomponent | 16 | - | 0x10891a878 | ghidra |
| Inrangecomponent | 1 | - | 0x1088e32c8 | ghidra |
| LevelLoadedOneFrameComponent | 1 | - | - | ghidra |
| ObstacleChangedOneFrameComponent | 1 | - | - | ghidra |
| Obstaclecomponent | 28 | - | 0x10891aa00 | ghidra |
| Obstaclemetadatacomponent | 96 | - | 0x10891a9f0 | ghidra |
| OffMeshLinkComponent | 32 | - | - | ghidra |
| Pathdebugcomponent | 224 | - | 0x10891a930 | ghidra |
| Pathinternalcomponent | 176 | - | 0x10891a910 | ghidra |
| Pathrequestcomponent | 104 | - | 0x10891a920 | ghidra |
| Pathresultcomponent | - | - | 0x10891a900 | typeid |
| RegionUnloadingComponent | 1 | - | - | ghidra |
| Regiondatacomponent | 64 | - | 0x10891aa10 | ghidra |
| Regionloadingcomponent | 40 | - | 0x10891aab0 | ghidra |

---
