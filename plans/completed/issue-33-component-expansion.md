# Plan: Issue #33 - Component Property Layouts Expansion

## Goal
Expand component coverage from 36 to 50+ components to increase Ext.Entity parity from 62% to 70%+.

## Current State
- **36 components** implemented in `src/entity/component_offsets.h`
- **1,999 TypeIds** available (701 in eoc:: namespace)
- Tools ready: `extract_typeids.py`, `generate_component_stubs.py`

---

## CURRENT FOCUS: Batch 1 - Simple Components (2-3 hours)

Quick wins - single-field or simple struct components.

| # | Component | Namespace | Fields | Verification |
|---|-----------|-----------|--------|--------------|
| 1 | DeathState | `eoc::death::StateComponent` | State (uint32) | Kill entity, check State |
| 2 | DeathType | `eoc::death::DeathTypeComponent` | DeathType (uint8) | Kill entity, check type |
| 3 | InventoryWeight | `eoc::inventory::WeightComponent` | Weight (int32) | Check item weight matches UI |
| 4 | ThreatRange | `eoc::combat::ThreatRangeComponent` | Range, TargetCeiling, TargetFloor (floats) | Character stats |
| 5 | IsInCombat | `eoc::combat::IsInCombatComponent` | Tag (no fields) | Presence check |

### Implementation Steps for Each Component

1. **Find TypeId address:**
   ```bash
   nm -gU "/Applications/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3" 2>/dev/null | c++filt | grep "TypeId.*ComponentName"
   ```

2. **Add TypeId entry** to `src/entity/component_typeid.c`

3. **Add property definition** to `src/entity/component_offsets.h`

4. **Verify offsets** via runtime probing

5. **Test** in console: `entity.ComponentName.Property`

---

## Future Batches (for reference)

### Batch 2: Combat Components (3-4 hours)
| Component | Fields | Verification |
|-----------|--------|--------------|
| CombatParticipant | CombatHandle, CombatGroupId, InitiativeRoll, Flags, AiHint | In-combat character |
| CombatState | MyGuid, Level, IsInNarrativeCombat (skip HashMaps) | Combat entity |

### Batch 3: Progression Components (3-4 hours)
| Component | Fields | Verification |
|-----------|--------|--------------|
| LevelUp | LevelUpCount | Character with pending levels |
| ProgressionFeat | Feat GUID, counts | Feated character |
| ProgressionPassives | AddCount, RemoveCount | Character with class passives |
| ProgressionSpells | AddCount, RemoveCount | Spellcaster |

### Batch 4: Inventory Components (2-3 hours)
| Component | Fields | Verification |
|-----------|--------|--------------|
| InventoryStack | ElementCount, EntryCount | Stacked items |
| InventoryData | Type, SlotLimit | Character inventory |

### Batch 5: Advanced Components (2-3 hours)
| Component | Fields | Verification |
|-----------|--------|--------------|
| IsSummon | SummonTopOwner, Owner, InstanceIndex | Summoned creature |
| TurnOrder | TurnOrderCount, GroupCount | Combat turn order |

---

## Per-Component Workflow

```bash
# 1. Get TypeId address
nm -gU "/Applications/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3" 2>/dev/null | c++filt | grep "TypeId.*ComponentName"

# 2. Generate stub (optional - reference Windows headers)
python3 tools/generate_component_stubs.py --namespace eoc --list | grep ComponentName

# 3. Verify offsets at runtime
echo 'Debug.ProbeStruct(entity_ptr, 0, 0x100, 8)' | nc -U /tmp/bg3se.sock

# 4. Add to codebase and test
```

---

## Files to Modify

### Primary
- `src/entity/component_offsets.h` - Add property definitions + layouts
- `src/entity/component_typeid.c` - Add TypeId entries

### Documentation
- `ROADMAP.md` - Update component count, version history
- `CLAUDE.md` - Update component count, parity %
- `README.md` - Update status table
- `docs/CHANGELOG.md` - Add version entry

---

## Success Criteria
- [ ] 50+ total components (36 + 14 new)
- [ ] All combat-critical components accessible
- [ ] All progression components accessible
- [ ] `entity.ComponentName.Property` works for each
- [ ] Documentation updated

## Time Estimate
**Total: 12-17 hours** (can be done incrementally by batch)

---

## Risk Mitigation

1. **Complex nested types (HashMaps)** → Expose simple counts first, skip complex fields
2. **ARM64 alignment differs** → Verify every offset via runtime probing
3. **Session-scoped components** → Test in correct game state, add null checks
