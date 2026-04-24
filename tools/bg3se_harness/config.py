from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BG3_APP_BUNDLE = Path.home() / "Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app"
BG3_EXEC = BG3_APP_BUNDLE / "Contents/MacOS/Baldur's Gate 3"
DYLIB_OUTPUT = PROJECT_ROOT / "build/lib/libbg3se.dylib"
DEPLOYED_DYLIB = BG3_APP_BUNDLE / "Contents/MacOS/libbg3se.dylib"
SOCKET_PATH = "/tmp/bg3se.sock"
SENTINEL_PATH = "/tmp/bg3se_loaded.txt"
HEALTH_TIMEOUT = 30
HEALTH_TIMEOUT_CONTINUE = 90  # Save loading takes 10-30s on top of launch
BACKUP_SUFFIX = ".bg3se-original"
HASH_FILE = BG3_APP_BUNDLE / "Contents/MacOS/.bg3se-patch-hash"
INSERT_DYLIB = PROJECT_ROOT / "tools/vendor/insert_dylib/insert_dylib_bin"
DYLIB_INSTALL_NAME = "@loader_path/libbg3se.dylib"

# Mod management paths
LARIAN_LOCAL = Path.home() / "Documents/Larian Studios/Baldur's Gate 3"
MODS_DIR = LARIAN_LOCAL / "Mods"
MODSETTINGS_PATH = LARIAN_LOCAL / "PlayerProfiles/Public/modsettings.lsx"
GRAPHIC_SETTINGS_PATH = LARIAN_LOCAL / "graphicSettings.lsx"
SAVES_DIR = LARIAN_LOCAL / "PlayerProfiles/Public/Savegames/Story"

# Harness data paths
HARNESS_CONFIG_DIR = Path.home() / ".config/bg3se-harness"
MOD_REGISTRY_PATH = HARNESS_CONFIG_DIR / "mod_registry.json"
SAVE_FIXTURES_DIR = HARNESS_CONFIG_DIR / "save_fixtures"
REPORTS_DIR = PROJECT_ROOT / ".reports"

# Catalog paths (shipped with repo)
CATALOG_DIR = Path(__file__).resolve().parent / "catalog"
SCENARIOS_DIR = Path(__file__).resolve().parent / "scenarios"

# GustavX invariant — must always be at position 0 in modsettings.lsx
GUSTAVX_UUID = "28ac9ce2-2aba-8cda-b3b5-6e922f71b6b8"
