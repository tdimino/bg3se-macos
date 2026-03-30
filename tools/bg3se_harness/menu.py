"""Vision-based menu navigation for loading BG3 save games.

This module is intentionally thin. The actual vision-based navigation
is delegated to Claude Computer Use (or peekaboo/usecomputer fallback)
via the skill's SKILL.md instructions. This module provides utility
functions for the harness CLI when running outside of Claude Code.
"""

import subprocess
import sys
import time


def wait_for_main_menu(timeout=60):
    """Wait for BG3 to reach the main menu.

    When running from Claude Code, the skill handles this via Computer Use.
    When running standalone, this just waits and prompts the user.
    """
    print(f"Waiting for BG3 main menu (up to {timeout}s)...", file=sys.stderr)
    print("Navigate to Load Game and load your save.", file=sys.stderr)
    print("Press Enter when the save is loaded, or Ctrl+C to skip.", file=sys.stderr)

    try:
        import select
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if ready:
            sys.stdin.readline()
            return {"menu_reached": True, "method": "manual"}
        return {"menu_reached": False, "timeout": True}
    except KeyboardInterrupt:
        return {"menu_reached": False, "skipped": True}


def load_save_with_usecomputer(save_name=None):
    """Attempt save loading via usecomputer CLI (if installed).

    Requires: npm i -g usecomputer
    """
    try:
        result = subprocess.run(
            ["which", "usecomputer"], capture_output=True, text=True,
        )
        if result.returncode != 0:
            return {"success": False, "error": "usecomputer not installed"}

        # Take screenshot to analyze game state
        screenshot_path = "/tmp/bg3_menu.png"
        subprocess.run(
            ["usecomputer", "screenshot", "--path", screenshot_path],
            capture_output=True,
        )
        return {
            "success": False,
            "error": "usecomputer screenshot captured but vision analysis requires Claude",
            "screenshot": screenshot_path,
        }
    except FileNotFoundError:
        return {"success": False, "error": "usecomputer not found"}


# Instructions for Claude Computer Use (embedded in skill SKILL.md)
CLAUDE_MENU_INSTRUCTIONS = """
## Menu Navigation via Claude Computer Use

When BG3 reaches the main menu after launch:

1. **Take a screenshot** to verify the main menu is visible
2. **Click "Load Game"** — look for the button in the center of the screen
3. **Wait 2 seconds** for the save list to populate
4. **Click the most recent save** — it should be at the top of the list
5. **Click "Load"** — confirm button at the bottom
6. **Wait for the save to load** — watch for the loading screen to finish
7. **Verify via socket** — send `Ext.GetGameState()` and confirm it returns "Running"

If the main menu is not visible:
- Check if a "Continue" dialog or "Mod Verification" popup is blocking
- Click through any dialogs first, then retry
"""
