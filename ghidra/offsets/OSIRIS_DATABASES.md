# Osiris Database Access (macOS) — Osi.DB_* fix

**Problem:** `Osi.DB_*:Get()` (DB_PartyMembers, DB_Players, DB_Avatars, DB_Is_InCombat…)
always returns empty on macOS, breaking every mod that reads an Osiris database
(e.g. **Sit This One Out** — its cantrip-grant loop iterates `DB_PartyMembers`).

## Root cause (VERIFIED live 2026-07-12)

Osiris keeps functions in **two** indexes inside `COsiFunctionMan`:
1. A numeric **runtime id-index** (`pFunctionData(uint)`) — what the macOS port
   brute-force probes in `osi_func_enumerate()`. **Databases are NOT in it.**
2. A **name index** (`CSearchIndex<COsiFunctionData*, COsiString, 1023>`) — where
   databases live. The port never walked this → DBs unresolvable.

Confirmed: re-enumeration after story load still finds exactly 1303 functions,
zero databases. Databases have **`OsiFunctionId == 0`** (no dispatch id), so
`InternalQuery`-by-id cannot serve them. Windows reads their `Facts` list directly.

## Name index layout — VERIFIED (libOsiris `COsiFunctionMan::pFunctionData(CKey)` @ 0x29b88; live-probed)

- `_OsiFunctionMan` global = libOsiris base + **0x9f348**; deref → `manager`.
- Name buckets at **manager + 0** (before the id runtime-index at manager+0x5ff0).
- `bucket[i] = manager + i*0x18` (1023 buckets). Tree root = `*(bucket + 0x8)`.
- Tree node: left = `*(node+0x00)`, right = `*(node+0x08)`,
  key COsiString at `node+0x20`, **value `COsiFunctionData*` = `*(node+0x38)`**.
- Walk is implemented in `osi_func_enumerate_by_name()` (osiris_functions.c) — a
  read-only, bounded traversal. **Traversal VERIFIED correct** (live-probed:
  reaches `DB_SHA_NightsongPrison_FadeEvents`, `DB_UND_ChestOfMundane`, … type=4).

## COsiFunctionData (def) layout — VERIFIED offsets (live)

| Offset | Field | Notes |
|--------|-------|-------|
| +0x18 | `FunctionSignature*` | → +0x08 `const char* Name` (extraction works) |
| +0x20 | `NodeRef.Id` (u32) | node id → resolve Node → Database |
| **+0x24** | `Type` (u32) | **=4 for Database** (NOTE: id-path wrongly reads type at +0x28=Key[0]) |
| +0x28 | `Key[4]` (u32×4) | handle source for normal funcs |
| +0x38 | `OsiFunctionId` (u32) | **=0 for databases** ← why the id-walk skipped them |

## The fix (Windows-parity) — read Facts directly

Windows (`Lua/Osiris/Function.inl` `LuaGet`):
```cpp
db = function_->Node.Get()->Database.Get();
head = db->Facts.Head; current = head->Next;
while (current != head) { /* current->Item = TupleVec row */ current = current->Next; }
```
Windows `Database` (`GameDefinitions/Osiris.h`):
```cpp
struct Database { uint32_t DatabaseId; void* FactsVMT; List<TupleVec> Facts; Vector<uint32_t> ParamTypes; uint8_t NumParams; };
```
`List` is circular: `Facts.Head` sentinel; nodes have `Next` + `Item` (TupleVec = vector of TypedValue).

## FULL RESOLUTION CHAIN — VERIFIED via libOsiris arm64 disassembly (2026-07-12)

macOS Osiris uses `CReteDBase` (the database, holds a `std::list<CTuple>`),
`CTuple` = `COsiSOOList<COsiTypedValue,8>`, `COsiTypedValue` (16 bytes).
All offsets below are from disassembly of the named functions.

**Globals** (libOsiris file offsets; runtime = libOsirisBase + off;
libOsirisBase = &`_OsiFunctionMan` − 0x9f348, or dlsym `_ReteNodeFactory`):
- `_ReteNodeFactory` @ **0x9f338** — holds a **pointer** to the node factory.
- Databases manager pointer @ **0x9f5b0** (alias also at 0x9a4d8).
- Both factory & dbmgr: `+0x00` = id counter (u32), `+0x08`..`+0x10` = `std::vector<T*>`
  (`__begin_`=+0x08, `__end_`=+0x10). **Element by id: `*( *(mgr+0x08) + (id-1)*8 )`.**
  (VERIFIED: db serialize loop `sub w9,id,#1; ldr x0,[begin, w9, lsl#3]`.)

**Chain** (`CreateReteFact` @ 0x6ba5c; `CReteDBase::Select` @ 0x5da40):
1. Name-index walk → `def` (COsiFunctionData*) for the DB name (VERIFIED live).
   `nodeId = u32 @ def+0x20`, `type(=4) @ def+0x24`.
2. `factory = *(base+0x9f338)`; `node = *( *(factory+0x08) + (nodeId-1)*8 )`.
   Validate `u32 @ node+0x08 == nodeId`. (fact node = `CReteNode`)
3. `dbId = u32 @ node+0x18`.
4. `dbmgr = *(base+0x9f5b0)`; `db = *( *(dbmgr+0x08) + (dbId-1)*8 )` = **CReteDBase**.
   Validate `u32 @ db+0x00 == dbId`.
5. **Facts** (std::list<CTuple> embedded at `db+0x10` sentinel):
   - `count = u32 @ db+0x20`; `first = ptr @ db+0x18`; end sentinel = `db+0x10`.
   - list node: `__next_ = ptr @ n+0x08`; **CTuple value @ n+0x10**.
   - iterate: `n = first; while (n != db+0x10) { tuple = n+0x10; n = *(n+0x08); }`.
6. **CTuple** = `COsiSOOList<COsiTypedValue,8>`:
   - `size = u32 @ tuple+0x80`; `cap = u32 @ tuple+0x84`;
   - `data = (cap < 9) ? (tuple+0x00) : *(tuple+0x00)`; column i at `data + i*0x10`.
7. **COsiTypedValue** (16 bytes): `typeId = u16 @ tv+0x08`; `value = 8 bytes @ tv+0x00`
   (char* for STRING/GUIDSTRING & custom GUID subtypes; int64 for INTEGER; float for REAL).
   Read *(tv+0x00) as ptr → C string for string types; else numeric.

**Note:** databases have `OsiFunctionId==0` (def+0x38) → do NOT dispatch via
InternalQuery; read Facts as above (Windows parity).

## Implementation plan

1. In `osi_func_enumerate_by_name()`: for `Type==4` (Database) at def+0x24, store the
   **def pointer** in a name→def registry (DBs have no id to cache under).
2. New `osi_db_read_facts(def, L, filterArgs)` — resolve Node→Database→Facts, walk
   the circular list, push each matching tuple as a Lua row (mirror Windows `LuaGet`).
3. `lua_osi_db_get`: if the DB name is in the registry, call `osi_db_read_facts`
   instead of the (unusable) InternalQuery-by-id path.

## Code state (branch pr-91, this session)

- `osiris_functions.c`: `osi_func_enumerate_by_name()` (walk WORKS) + `osi_func_cache_def()`.
  Widened `osi_func_enumerate()` ranges/caps + idempotent (harmless improvement).
- `main.c` fake_Event: one-shot call to `osi_func_enumerate_by_name()` on
  SavegameLoaded/LevelGameplayStarted (`g_dbNamesEnumerated`).
- **Bug to fix:** walk requires `osiId!=0` so it caches 0 DBs. Change to register DB
  defs by name (see plan step 1) — id-caching is useless for DBs.

## Live probe cheat-sheet (Ext.Debug over /tmp/bg3se.sock)
```
base = Ext.Memory.GetModuleBase("Osiris")           -- e.g. 0x10f6a4000
man  = Ext.Debug.ReadPtr(base + 0x9f348)             -- COsiFunctionMan
root = Ext.Debug.ReadPtr(man + b*0x18 + 0x8)         -- bucket b tree root
val  = Ext.Debug.ReadPtr(node + 0x38)                -- COsiFunctionData*
name = Ext.Debug.ReadString(Ext.Debug.ReadPtr(val+0x18) + 0x08, 64)
```
⚠️ Keep probes BOUNDED (≤~50 buckets/call). A full recursive 1023-bucket walk from
Lua crashed the game.
