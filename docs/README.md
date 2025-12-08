# Documentation

## Quick Navigation

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Installation, building, and first launch |
| [API Reference](api-reference.md) | Complete Ext.* and Osi.* API documentation |
| [Architecture](architecture.md) | Technical deep-dive: injection, hooks, ARM64 ABI |
| [Development Guide](development.md) | Contributing, building features, debugging |
| [Troubleshooting](troubleshooting.md) | Common issues and solutions |
| [Reverse Engineering](reverse-engineering.md) | Ghidra workflows, offset discovery |

## For Different Audiences

### Mod Users
Start with [Getting Started](getting-started.md) to install and run SE mods on your Mac.

### Mod Developers
Check the [API Reference](api-reference.md) for available Lua APIs, then [Development Guide](development.md) for the live console.

### Contributors
Read [Architecture](architecture.md) to understand the codebase, then [Development Guide](development.md) and [Reverse Engineering](reverse-engineering.md) for workflows.

## Additional Resources

- **[ghidra/offsets/](../ghidra/offsets/)** - Reverse-engineered memory offsets
- **[agent_docs/](../agent_docs/)** - Claude Code development context
- **[tools/](../tools/)** - PAK extractor, Frida scripts, test mods
- **[ROADMAP.md](../ROADMAP.md)** - Feature parity tracking
- **[archive/](archive/)** - Historical investigation notes (crash analysis, debugging sessions)

## Reference Implementation

The Windows BG3SE source code is our architectural reference:
- **GitHub:** https://github.com/Norbyte/bg3se

Key directories for porting features:
- `BG3Extender/Lua/` - Lua API patterns
- `BG3Extender/GameDefinitions/` - Entity/component structures
- `BG3Extender/Osiris/` - Osiris binding patterns
