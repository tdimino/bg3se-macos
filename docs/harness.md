# BG3SE Test Harness

Autonomous test harness for bg3se-macos. Builds, injects, launches, tests, and reports—one command.

## Quick Start

```bash
cd /path/to/bg3se-macos

# Check status
PYTHONPATH=tools python3 -m bg3se_harness status

# Full launch: build + patch + launch + health check
PYTHONPATH=tools python3 -m bg3se_harness launch

# Run regression tests (game must be running)
PYTHONPATH=tools python3 -m bg3se_harness test

# Send arbitrary Lua
PYTHONPATH=tools python3 -m bg3se_harness run "Ext.GetVersion()"
```

## Commands

| Command | Description |
|---------|-------------|
| `status` | Check if BG3 is running, socket alive, binary patched |
| `build` | Build dylib via cmake, verify universal binary, deploy to Steam folder |
| `patch` | Inject libbg3se.dylib into BG3 binary via insert_dylib |
| `unpatch` | Restore original BG3 binary from backup |
| `launch` | Build + patch + launch + socket health check |
| `test [filter]` | Run regression tests, output structured JSON |
| `test --tier 2 [filter]` | Run in-game tests (requires loaded save) |
| `run "<lua>"` | Send Lua code to running game via socket |

## How Injection Works

Traditional `DYLD_INSERT_LIBRARIES` injection is fragile—SIP, Hardened Runtime, and Steam's process chain can silently strip the environment variable. The harness replaces this with **static Mach-O patching** via `insert_dylib`:

1. `insert_dylib` adds an `LC_LOAD_WEAK_DYLIB` load command to the BG3 binary
2. The binary is ad-hoc codesigned after patching
3. On launch, dyld automatically loads libbg3se.dylib—no environment variables needed
4. `--weak` linking means a missing dylib won't crash the game

### Idempotency

- `patch` checks `otool -L` before patching—skips if already done
- A SHA-256 hash of the patched binary is stored alongside it
- Game updates detected by hash mismatch → automatic re-patch from backup

### Reversibility

```bash
PYTHONPATH=tools python3 -m bg3se_harness unpatch
```

Restores the original binary from the `.bg3se-original` backup.

## Test Output

`test` returns structured JSON:

```json
{
  "tier": 1,
  "filter": null,
  "tests": [
    {"name": "Core.Print", "status": "pass", "ms": 2, "error": null, "index": 1, "total": 85},
    {"name": "Stats.Bad", "status": "fail", "ms": 5, "error": "Expected string, got nil", "index": 3, "total": 85}
  ],
  "summary": {"passed": 83, "failed": 2, "skipped": 0, "total": 85, "elapsed_ms": 142},
  "all_passed": false
}
```

Filter by category: `test Stats` runs only tests matching "Stats".

## Architecture

```
tools/bg3se_harness/
├── __init__.py
├── __main__.py      # entry point
├── cli.py           # argparse subcommands
├── config.py        # paths, timeouts, defaults
├── build.py         # cmake build + verify + deploy
├── patch.py         # insert_dylib + codesign
├── launch.py        # direct launch + socket health check
├── console.py       # Python socket IPC client
├── test_runner.py   # test execution + output parsing
└── menu.py          # vision-based save loading (Claude Computer Use)
```

## Dependencies

- **insert_dylib** (C, tyilo/insert_dylib): Built from `tools/vendor/insert_dylib/`
- **Python 3.10+**
- **BG3** installed via Steam
- **bg3se-macos** dylib (built by cmake)

## Troubleshooting

**Binary not patched after game update:** Run `patch` again—it detects the hash change and re-patches from the updated binary.

**Socket timeout:** The health check polls `/tmp/bg3se.sock` for 30s. If BG3 is slow to start, use `--timeout 60`.

**Codesign warnings:** Ad-hoc signing may warn about subcomponents (log files in MacOS/). These are harmless—the binary itself is signed correctly.

**Steam re-downloads binary:** If you run "Verify Integrity of Game Files" in Steam, it will replace the patched binary. Run `patch` again afterward.
