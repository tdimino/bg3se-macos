"""BG3 CLI flag registry.

All 38 flags discovered via binary string extraction from the macOS BG3 binary.
See ghidra/offsets/CLI_FLAGS.md for full documentation including addresses.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Flag:
    name: str
    takes_arg: bool
    group: str
    description: str


# fmt: off
GAME_FLAGS = {
    # Launch & Save Control (P0)
    "continueGame":     Flag("-continueGame", False, "launch", "Auto-continue most recent save"),
    "loadSaveGame":     Flag("-loadSaveGame", True, "launch", "Load specific save game by name"),
    "load":             Flag("-load", False, "launch", "Generic load"),
    "testLoadLevel":    Flag("-testLoadLevel", False, "launch", "Test level loading"),

    # Mod & Story (P1)
    "module":           Flag("-module", True, "mod", "Specify module to load"),
    "modded":           Flag("-modded", False, "mod", "Enable modded mode"),
    "modEnv":           Flag("-modEnv", True, "mod", "Mod environment"),
    "dynamicStory":     Flag("-dynamicStory", False, "mod", "Dynamic story mode"),
    "saveStoryState":   Flag("-saveStoryState", False, "mod", "Save story state on exit"),
    "storylog":         Flag("-storylog", False, "mod", "Enable story logging"),

    # Debug & Developer (P1-P2)
    "stats":            Flag("-stats", False, "debug", "Stats output"),
    "json":             Flag("-json", False, "debug", "JSON output mode"),
    "osi":              Flag("-osi", False, "debug", "Osiris debug"),
    "crash":            Flag("-crash", False, "debug", "Crash reporting mode"),
    "syslog":           Flag("-syslog", False, "debug", "System logging"),
    "combatTimelines":  Flag("-combatTimelines", False, "debug", "Combat timeline debug"),
    "toggleCrowds":     Flag("-toggleCrowds", False, "debug", "Toggle NPC crowds"),
    "testAIStart":      Flag("-testAIStart", False, "debug", "Test AI start"),
    "newexposure":      Flag("-newexposure", False, "debug", "New exposure settings"),
    "dummyValue":       Flag("-dummyValue", True, "debug", "Dummy test value"),

    # System & Graphics (P2)
    "detailLevel":      Flag("-detailLevel", True, "system", "Graphics detail level"),
    "startInControllerMode": Flag("-startInControllerMode", False, "system", "Start in controller mode"),
    "mediaPath":        Flag("-mediaPath", True, "system", "Media/assets path"),
    "photoModeScreenshotsPath": Flag("-photoModeScreenshotsPath", True, "system", "Screenshot save path"),
    "enableClientNewECSScheduler": Flag("-enableClientNewECSScheduler", False, "system", "New ECS scheduler"),

    # Network (P2)
    "lariannetEnv":     Flag("-lariannetEnv", True, "network", "Larian network environment"),

    # Localization (P2-P3)
    "locaLanguage":     Flag("-locaLanguage", True, "locale", "Language setting"),
    "locaCloseOnErrors": Flag("-locaCloseOnErrors", False, "locale", "Close on localization errors"),
    "locaupdater":      Flag("-locaupdater", False, "locale", "Localization updater"),

    # Save System Debug / ECB Checker (P2-P3)
    "useSaveSystemECBChecker": Flag("-useSaveSystemECBChecker", False, "ecb", "Enable ECB checker"),
    "saveSystemECBCheckerEnableLogging": Flag("-saveSystemECBCheckerEnableLogging", False, "ecb", "ECB logging"),
    "saveSystemECBCheckerEnableDetailedLogging": Flag("-saveSystemECBCheckerEnableDetailedLogging", False, "ecb", "Detailed ECB logging"),
    "saveSystemECBCheckerAllowSaveOnFailure": Flag("-saveSystemECBCheckerAllowSaveOnFailure", False, "ecb", "Allow save on ECB fail"),
    "saveSystemECBCheckerLogSuccessfulAttempts": Flag("-saveSystemECBCheckerLogSuccessfulAttempts", False, "ecb", "Log successful saves"),
    "saveSystemECBCheckNumberOfFramesToWait": Flag("-saveSystemECBCheckNumberOfFramesToWait", True, "ecb", "Frames to wait before check"),

    # Double-dash flags
    "logPath":          Flag("--logPath", True, "system", "Log file path"),
    "cpuLimit":         Flag("--cpuLimit", True, "system", "CPU usage limit"),
    "closeOnErrors":    Flag("--closeOnErrors", False, "system", "Close on errors"),
    "nodb":             Flag("--nodb", False, "system", "No database"),
    "noxml":            Flag("--noxml", False, "system", "No XML"),
}
# fmt: on

# GameStateInit enforces mutual exclusivity between these flag sets.
MUTUALLY_EXCLUSIVE = [
    {"continueGame", "loadSaveGame"},
]

# Named presets for common flag combinations.
PRESETS = {
    "debug": ["stats", "json", "storylog", "osi"],
    "modded": ["modded"],
    "ecb": ["useSaveSystemECBChecker", "saveSystemECBCheckerEnableLogging"],
}

ALL_GROUPS = sorted({f.group for f in GAME_FLAGS.values()})


class FlagError(Exception):
    pass


def validate_flags(flag_keys: set[str]) -> None:
    """Validate that no mutually exclusive flags are combined."""
    for exclusive_set in MUTUALLY_EXCLUSIVE:
        active = flag_keys & exclusive_set
        if len(active) > 1:
            names = ", ".join(sorted(active))
            raise FlagError(
                f"Mutually exclusive flags: {names} "
                f"(GameStateInit enforces this)"
            )


def build_flag_args(flag_dict: dict[str, str | bool]) -> list[str]:
    """Convert a {key: value} dict to command-line args.

    Boolean flags: {key: True} → ["-flagName"]
    Arg flags: {key: "value"} → ["-flagName", "value"]
    """
    validate_flags(set(flag_dict.keys()))

    args = []
    for key, value in flag_dict.items():
        flag = GAME_FLAGS.get(key)
        if flag is None:
            raise FlagError(f"Unknown flag: {key}")
        args.append(flag.name)
        if flag.takes_arg:
            if not isinstance(value, str) or not value:
                raise FlagError(f"Flag {key} requires a string argument")
            args.append(value)
    return args


def list_flags(group: str | None = None) -> list[tuple[str, Flag]]:
    """List flags, optionally filtered by group."""
    items = sorted(GAME_FLAGS.items(), key=lambda kv: (kv[1].group, kv[0]))
    if group:
        items = [(k, f) for k, f in items if f.group == group]
    return items
