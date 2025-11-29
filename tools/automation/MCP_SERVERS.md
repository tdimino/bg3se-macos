# MCP Servers for BG3SE Testing

Model Context Protocol (MCP) servers enable Claude Code to automate macOS tasks for testing the Script Extender.

## Installation

```bash
claude mcp add macos-automator -- npx -y @steipete/macos-automator-mcp@latest
claude mcp add peekaboo -- npx -y @steipete/peekaboo-mcp@beta
```

Grant accessibility permissions: System Preferences → Security → Accessibility → enable `osascript`

## macos-automator

AppleScript and JXA (JavaScript for Automation) execution.

| Tool | Purpose |
|------|---------|
| `execute_script` | Run AppleScript or JXA code |
| `get_scripting_tips` | Search 493 automation scripts |

### Key Usage

```bash
# Run AppleScript
mcp__macos-automator__execute_script
  script_content: "do shell script \"open steam://run/1086940\""

# Run JXA (required for mouse clicks in games)
mcp__macos-automator__execute_script
  script_content: "ObjC.import('Cocoa'); ..."
  language: "javascript"

# Search for scripts
mcp__macos-automator__get_scripting_tips
  search_term: "click mouse"
```

### Mouse Clicks (JXA + CGEvent)

Standard AppleScript `click at` doesn't work for game UIs. Use JXA with CGEvent:

```javascript
ObjC.import('Cocoa');
const point = $.CGPointMake(x, y);
const down = $.CGEventCreateMouseEvent($(), $.kCGEventLeftMouseDown, point, $.kCGMouseButtonLeft);
const up = $.CGEventCreateMouseEvent($(), $.kCGEventLeftMouseUp, point, $.kCGMouseButtonLeft);
$.CGEventPost($.kCGHIDEventTap, down);
$.CGEventPost($.kCGHIDEventTap, up);
```

## peekaboo

Screenshot capture and AI-powered visual analysis.

| Tool | Purpose |
|------|---------|
| `image` | Capture screenshot of screen/app/window |
| `analyze` | Ask AI questions about an image |
| `list` | List running apps and their windows |

### Key Usage

```bash
# Capture specific app
mcp__peekaboo__image
  app_target: "bg3"
  path: "/tmp/bg3.png"
  format: "png"

# Capture all screens
mcp__peekaboo__image
  app_target: "screen"
  path: "/tmp/screen.png"
  format: "png"

# List running applications
mcp__peekaboo__list
  item_type: "running_applications"

# List windows for an app
mcp__peekaboo__list
  item_type: "application_windows"
  app: "bg3"

# AI analysis (requires PEEKABOO_AI_PROVIDERS configured)
mcp__peekaboo__analyze
  image_path: "/tmp/bg3.png"
  question: "Is the main menu visible?"
```

## References

- [macos-automator-mcp](https://github.com/steipete/macos-automator-mcp)
- [peekaboo-mcp](https://github.com/steipete/peekaboo-mcp)
