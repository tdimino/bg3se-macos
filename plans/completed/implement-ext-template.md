# Plan: Implement Ext.Template API (Issue #41)

## Overview

Implement the Ext.Template API for accessing game object templates (CharacterTemplate, ItemTemplate, etc.).

## Background

**Windows BG3SE Pattern** (from ServerTemplate.inl):
- 4-level template hierarchy: GlobalTemplateBank → LocalTemplateManager → CacheTemplateManager → LocalCacheTemplates
- Templates accessed via FixedString ID lookup in LegacyMap/HashMap
- GameObjectTemplate base struct with specialized types (CharacterTemplate, ItemTemplate, etc.)

**macOS Challenge:**
- Template manager symbols NOT exported via dlsym
- Same pattern as StaticData (Issue #40) which we solved via Frida capture

## Target API Surface

```lua
-- From Issue #41 requirements
Ext.Template.GetAllRootTemplates()           -- GlobalTemplateBank
Ext.Template.GetRootTemplate(templateId)     -- Single root template
Ext.Template.GetAllLocalTemplates()          -- LocalTemplateManager
Ext.Template.GetLocalTemplate(templateId)    -- Single local template
Ext.Template.GetAllCacheTemplates()          -- CacheTemplateManager
Ext.Template.GetCacheTemplate(templateId)    -- Single cache template
Ext.Template.GetAllLocalCacheTemplates()     -- Level cache
Ext.Template.GetLocalCacheTemplate(templateId)
Ext.Template.Get(templateId)                 -- Cascading search
```

## Implementation Strategy

### Phase 1: Frida Discovery

Since template symbols are stripped, use Frida to:
1. Hook functions that access templates at runtime
2. Capture GlobalTemplateBank and CacheTemplateManager pointers
3. Write to capture files similar to StaticData

**Potential Hook Targets (from MULTI_ISSUE.md):**
- ActionData::Visit functions at 0x1011233b0+ (take GameObjectTemplate* param)
- RegisterType<CampChestTemplateManager> at 0x100c676f4
- RegisterType<AvatarContainerTemplateManager> at 0x100c67bd4

**Alternative: Pattern Scan for Template Strings:**
- "RootTemplate" string at 0x107b6af72
- "Templates/" string at 0x107b45f61
- Find xrefs to these strings to locate template loading functions

### Phase 2: C Implementation

Files to create:
- `src/template/template_manager.c` - Template manager singleton capture/access
- `src/template/template_manager.h` - Header
- `src/lua/lua_template.c` - Lua bindings
- `src/lua/lua_template.h` - Header

**Structure (based on Windows BG3SE):**
```c
// GameObjectTemplate base (simplified)
typedef struct {
    void* VMT;                    // +0x00
    void* Tags;                   // +0x08 (TemplateTagContainer*)
    uint32_t Id_fs;               // +0x10 (FixedString index)
    uint32_t TemplateName_fs;     // +0x14
    uint32_t ParentTemplateId_fs; // +0x18
    uint32_t TemplateHandle;      // +0x1C
    char* Name;                   // +0x20 (STDString)
    // ... more fields
} GameObjectTemplate;

// GlobalTemplateBank (conceptual)
typedef struct {
    void* VMT;
    // LegacyMap<FixedString, GameObjectTemplate*> Templates
    void* templates_map;
} GlobalTemplateBank;
```

### Phase 3: Lua API

Register in `lua_ext_register_functions()`:
- `Ext.Template.Get(templateId)` - Cascading lookup
- `Ext.Template.GetRootTemplate(templateId)` - Direct GlobalTemplateBank lookup
- `Ext.Template.GetType(template)` - Return template type string

## Implementation Steps

1. [ ] Create Frida script to discover GlobalTemplateBank access
   - Hook ActionData::Visit or similar function
   - Look for GameObjectTemplate* parameter patterns
   - Capture manager pointer when triggered

2. [ ] Analyze captured manager structure
   - Determine Templates map offset
   - Verify LegacyMap layout (same as StaticData?)

3. [ ] Implement template_manager.c
   - Load captured pointers from file
   - Implement map traversal
   - Add template lookup by FixedString

4. [ ] Implement lua_template.c
   - GetRootTemplate, GetAllRootTemplates
   - GetCacheTemplate, GetAllCacheTemplates
   - Get (cascading search)

5. [ ] Test with common templates
   - Character templates
   - Item templates
   - Scenery templates

## Files Modified

- `src/injector/main.c` - Register Ext.Template namespace
- `CMakeLists.txt` - Add new source files
- `CLAUDE.md`, `README.md`, `ROADMAP.md` - Update docs

## Risk Mitigation

**If Frida capture fails:**
- Use pattern scanning for template string xrefs
- Probe from known EntityWorld → Level → LocalTemplateManager chain
- Fall back to TypeContext registration pattern (like StaticData)

## Estimated Complexity

- Frida script: ~2 hours (reuse StaticData pattern)
- C implementation: ~4 hours
- Lua bindings: ~2 hours
- Testing: ~2 hours

Total: ~10 hours (spread across sessions)

## Dependencies

- Working Frida installation
- BG3 running with game loaded (for runtime capture)
- StaticData implementation as reference pattern
