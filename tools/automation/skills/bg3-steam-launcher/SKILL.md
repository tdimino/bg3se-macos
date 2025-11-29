---
name: bg3-steam-launcher
description: |
  Launch Baldur's Gate 3 through Steam on macOS and load saved games using macos-automator and peekaboo MCP servers.
  Designed for testing bg3se-macos (Script Extender) development.
  Use when: (1) launching BG3 from Steam, (2) loading a BG3 saved game, (3) testing SE mod injection,
  (4) user asks to "start BG3", "load my BG3 save", "play Baldur's Gate", "test the script extender".
  Requires macos-automator and peekaboo MCP servers installed with accessibility permissions.
---

# BG3 Steam Launcher

Automate launching Baldur's Gate 3 via Steam and loading saved games.

**MCP Servers Used:**
- **macos-automator** - AppleScript execution for UI automation
- **peekaboo** - Fast screenshots and AI-powered visual analysis

## Prerequisites

```bash
claude mcp add macos-automator -- npx -y @steipete/macos-automator-mcp@latest
claude mcp add peekaboo -- npx -y @steipete/peekaboo-mcp@beta
```

Grant accessibility permissions to osascript in System Preferences → Security → Accessibility.

## MCP Tools Quick Reference

### Peekaboo (Vision)

| Tool | Use |
|------|-----|
| `mcp__peekaboo__image` | Capture screenshot of screen/app/window |
| `mcp__peekaboo__analyze` | Ask AI questions about screenshots |
| `mcp__peekaboo__list` | List running apps and windows |

### macos-automator (Actions)

| Tool | Use |
|------|-----|
| `mcp__macos-automator__execute_script` | Run AppleScript/JXA |
| `mcp__macos-automator__get_scripting_tips` | Search automation scripts |

## Core Workflow

### Step 1: Launch BG3 via Steam Protocol

```applescript
do shell script "open steam://run/1086940"
```

BG3 Steam App ID: **1086940**

### Step 2: Wait for Larian Launcher

Use Peekaboo to monitor for the PLAY button, then click it.

### Step 3: Wait for Main Menu (15-30s)

Poll with Peekaboo screenshots looking for Continue/Load Game/New Game buttons.

### Step 4: Load Save

Navigate menus using keyboard (Enter=36, Esc=53, arrows) or mouse coordinates.

## Mouse Clicks (JXA + CGEvent)

Standard AppleScript `click at` doesn't work for game UIs. Use JXA with CGEvent:

```javascript
// Execute with language: "javascript"
ObjC.import('Cocoa');

function clickAt(x, y) {
    const point = $.CGPointMake(x, y);
    const down = $.CGEventCreateMouseEvent($(), $.kCGEventLeftMouseDown, point, $.kCGMouseButtonLeft);
    const up = $.CGEventCreateMouseEvent($(), $.kCGEventLeftMouseUp, point, $.kCGMouseButtonLeft);
    $.CGEventPost($.kCGHIDEventTap, down);
    delay(0.05);
    $.CGEventPost($.kCGHIDEventTap, up);
}

// Get window-relative coordinates
function getWindowClickPos(processName, xPercent, yPercent) {
    const se = Application('System Events');
    const proc = se.processes.byName(processName);
    const win = proc.windows[0];
    const pos = win.position();
    const size = win.size();
    return {
        x: pos[0] + (size[0] * xPercent),
        y: pos[1] + (size[1] * yPercent)
    };
}

// Example: click PLAY button (22% across, 87% down)
const coords = getWindowClickPos('bg3', 0.22, 0.87);
clickAt(coords.x, coords.y);
```

## Process Names

| App | Process Name | Bundle ID |
|-----|--------------|-----------|
| Steam | `Steam` | com.valvesoftware.steam |
| BG3 (Launcher & Game) | `bg3` | com.larian.bg3 |

## Button Coordinates (1728x1117 fullscreen)

| Screen | Element | X | Y |
|--------|---------|---|---|
| Larian Launcher | PLAY button | 22% | 87% |
| Main Menu | Continue | 310 | 510 |
| Main Menu | Load Game | 310 | 610 |
| Load Screen | First save slot | 200 | 230 |
| Load Screen | Load Game button | 870 | 1050 |
| Mod Verification | Start Game button | 720 | 1000 |

## SE Testing Workflow

1. **Build:**
   ```bash
   cd /path/to/bg3se-macos && ./scripts/build.sh
   ```

2. **Verify SE wrapper** in Steam launch options:
   ```
   /tmp/bg3w.sh %command%
   ```

3. **Launch via this skill** and load a save

4. **Check SE logs:**
   ```bash
   tail -f /tmp/bg3se_macos.log
   ```

## Crash Reports

**SE Log:** `/tmp/bg3se_macos.log`

**macOS Crash Reports:** `~/Library/Logs/DiagnosticReports/`
- Files named `Baldur's Gate 3-YYYY-MM-DD-HHMMSS.ips`
- JSON format with full stack traces

```bash
# List recent BG3 crash reports
ls -la ~/Library/Logs/DiagnosticReports/ | grep -i "baldur"

# Find crash location in our dylib
grep -A5 "libbg3se.dylib" ~/Library/Logs/DiagnosticReports/'Baldur'\''s Gate 3-*.ips'
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Click doesn't work | Use JXA CGEvent (see above) |
| Permission denied | System Preferences → Accessibility → enable osascript |
| Can't see screen | Use `mcp__peekaboo__image` with `app_target: "screen"` |
