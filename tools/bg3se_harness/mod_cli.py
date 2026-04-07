"""CLI handler for mod management commands.

Delegates to mod_manager package for actual operations.

Usage:
    bg3se-harness mod list
    bg3se-harness mod install <source>
    bg3se-harness mod enable <name>
    bg3se-harness mod disable <name>
    bg3se-harness mod remove <name>
    bg3se-harness mod info <source>
    bg3se-harness mod order --move X --before Y
    bg3se-harness mod search <query>
    bg3se-harness mod backup
"""

from __future__ import annotations

import json
import sys


def cmd_mod(args):
    """CLI handler for mod subcommands."""
    subcmd = args.mod_command

    if subcmd == "list":
        from .mod_manager.registry import list_mods
        result = list_mods()
        print(json.dumps(result, indent=2))
        return 0

    elif subcmd == "install":
        source = args.source
        if source.startswith("nexus:"):
            mod_id = source.replace("nexus:", "")
            from .mod_manager.nexus import get_mod_info, get_download_links
            info = get_mod_info(int(mod_id))
            if "error" in info:
                print(json.dumps(info, indent=2))
                return 1
            links = get_download_links(int(mod_id))
            print(json.dumps(links, indent=2))
            return 0 if links.get("success") else 1
        else:
            from .mod_manager.installer import install_local
            enable = not getattr(args, "no_enable", False)
            result = install_local(source, enable=enable)
            print(json.dumps(result, indent=2))
            return 0 if "error" not in result else 1

    elif subcmd == "enable":
        from .mod_manager.modsettings import enable_mod
        result = enable_mod(args.name)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "disable":
        from .mod_manager.modsettings import disable_mod
        result = disable_mod(args.name)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "remove":
        from .mod_manager.installer import uninstall
        result = uninstall(args.name)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "info":
        from .mod_manager.installer import get_mod_info
        result = get_mod_info(args.source)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "order":
        from .mod_manager.modsettings import reorder_mod
        result = reorder_mod(args.move, args.before)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "search":
        from .mod_manager.nexus import search_mods
        result = search_mods(args.query)
        print(json.dumps(result, indent=2))
        return 0

    elif subcmd == "changelog":
        from .mod_manager.nexus import get_changelogs
        result = get_changelogs(args.mod_id)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success", True) else 1

    elif subcmd == "versions":
        from .mod_manager.nexus import get_mod_files
        result = get_mod_files(args.mod_id)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success", True) else 1

    elif subcmd == "updated":
        from .mod_manager.nexus import get_updated
        result = get_updated(period=args.period)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success", True) else 1

    elif subcmd == "backup":
        from .mod_manager.modsettings import backup_modsettings
        result = backup_modsettings()
        print(json.dumps(result, indent=2))
        return 0

    return 1
