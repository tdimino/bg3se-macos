# Reverse Engineering Documentation

RE findings, struct layouts, and analysis tools for the BG3 macOS ARM64 binary.

## Documents

| File | Description | Status |
|------|-------------|--------|
| [global-singletons.md](global-singletons.md) | All discovered global singleton addresses with struct layouts | Verified |
| [../bugs/noesis-input-bypass-re.md](../bugs/noesis-input-bypass-re.md) | Noesis GUI input bypass — full pipeline RE, focus gate discovery, bypass approaches | In-progress |
| [../bugs/headless-boot-debug-log.md](../bugs/headless-boot-debug-log.md) | Headless boot attempts 1–7 — debug log with fixes applied | In-progress |

## Ghidra Offsets (per-subsystem)

Located in `ghidra/offsets/`:

| File | Description |
|------|-------------|
| `CLI_FLAGS.md` | 40 discovered game CLI flags |
| `STATS.md` | RPGStats system offsets |
| `COMPONENT_SIZES.md` | Master component size index |
| `COMPONENT_SIZES_EOC_*.md` | Per-namespace component sizes |
| `NETWORKING.md` | Network subsystem (GameServer, peers, protocols) |

## Scripts

Located in `scripts/re/`:

| Script | Purpose |
|--------|---------|
| `find_adrp_refs.py` | Scan __TEXT for ADRP+ADD/LDR pairs referencing target strings |
| `disasm_wide.py` | Disassemble ±4KB around a target address, find function prologues |
| `disasm_targets.py` | Multi-target variant of disasm_wide |
| `find_dispatch.py` | Locate Protocol::ProcessMsg dispatch via GetMessage callers |
| `find_processmsg.py` | Find ProtocolList (+0x2E0) access near virtual calls |
| `find_string_ptrs.py` | Scan DATA sections for 64-bit pointers to known strings |

See `scripts/re/README.md` for full usage and ARM64 instruction patterns.

## Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Fat binary ARM64 offset | `0xf534000` | Offset of ARM64 slice in universal binary |
| Virtual address base | `0x100000000` | ARM64 VA base |
| __TEXT segment size | `0x8398000` | Full code segment |
| File offset formula | `0xf534000 + (VA - 0x100000000)` | Convert VA to file offset |
