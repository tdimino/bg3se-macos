# Automation Tools

This folder contains configuration and documentation for automated BG3SE testing using Claude Code with MCP servers.

## Contents

```
automation/
├── README.md              # This file
├── MCP_SERVERS.md         # MCP server documentation
├── mcp-servers.json       # MCP server configuration template
└── skills/
    └── bg3-steam-launcher/
        └── SKILL.md       # Claude Code skill for BG3 testing
```

## Quick Setup

### 1. Install MCP Servers

```bash
claude mcp add macos-automator -- npx -y @steipete/macos-automator-mcp@latest
claude mcp add peekaboo -- npx -y @steipete/peekaboo-mcp@beta
```

Or merge `mcp-servers.json` into your Claude Code config at `~/.claude.json`.

### 2. Install the Skill

Copy the skill to your Claude Code skills directory:

```bash
cp -r skills/bg3-steam-launcher ~/.claude/skills/
```

### 3. Grant Permissions

System Preferences → Security & Privacy → Privacy → Accessibility → enable `osascript`

## Usage

With Claude Code, invoke the skill:

```
skill: "bg3-steam-launcher"
```

This provides Claude with the workflow for:
- Launching BG3 via Steam
- Clicking through the Larian launcher
- Loading saved games
- Checking SE injection logs
- Finding crash reports

## MCP Servers

| Server | Purpose |
|--------|---------|
| **macos-automator** | Execute AppleScript/JXA for UI automation |
| **peekaboo** | Capture screenshots and analyze with AI |

See `MCP_SERVERS.md` for detailed tool documentation.
