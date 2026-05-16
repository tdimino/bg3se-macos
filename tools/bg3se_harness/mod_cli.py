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


def _resolve_uuid(uuid_or_name: str) -> str | dict:
    """Resolve a UUID or mod name to a UUID via the mod registry.

    Returns the UUID string on success, or an error dict on failure.
    """
    from .mod_manager.registry import load_registry
    registry = load_registry()

    if uuid_or_name in registry:
        return uuid_or_name

    lower = uuid_or_name.lower()
    matches = [
        u for u, e in sorted(registry.items(), key=lambda x: (x[1].get("name") or "").lower())
        if lower in (e.get("name") or "").lower()
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        names = [registry[u].get("name", u) for u in matches]
        return {"error": f"Ambiguous name {uuid_or_name!r}: matched {names}. Use UUID."}
    return {"error": f"Mod not found in registry: {uuid_or_name!r}"}


def _registry_entry(uuid: str) -> dict | None:
    from .mod_manager.registry import load_registry
    return load_registry().get(uuid)


def cmd_mod(args):
    """CLI handler for mod subcommands."""
    subcmd = args.mod_command

    if subcmd == "list":
        from .mod_manager.registry import list_mods
        if getattr(args, "scan_installed", False):
            from .mod_manager.inventory import reconcile_registry
            result = reconcile_registry(write=False)
        else:
            result = list_mods()
        print(json.dumps(result, indent=2))
        return 0

    elif subcmd == "scan":
        from .mod_manager.inventory import scan_installed_paks
        if not getattr(args, "installed", False):
            result = {"error": "Only --installed scanning is currently supported"}
            print(json.dumps(result, indent=2))
            return 1
        result = scan_installed_paks()
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "reconcile":
        from .mod_manager.inventory import reconcile_registry
        if not getattr(args, "installed", False):
            result = {"error": "Only --installed reconciliation is currently supported"}
            print(json.dumps(result, indent=2))
            return 1
        result = reconcile_registry(write=getattr(args, "write", False))
        print(json.dumps(result, indent=2))
        return 0 if not result.get("scan", {}).get("error") else 1

    elif subcmd == "preflight":
        from .mod_manager.inventory import preflight_mod_state
        result = preflight_mod_state(
            accept_mod_verification=getattr(args, "accept_mod_verification", False),
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    elif subcmd == "verify":
        from .mod_manager.inventory import verify_modsettings
        if not getattr(args, "modsettings", False):
            result = {"error": "Only --modsettings verification is currently supported"}
            print(json.dumps(result, indent=2))
            return 1
        result = verify_modsettings(
            save_name=getattr(args, "save", None),
            continue_latest=getattr(args, "continue_latest", False),
            expected_order_path=getattr(args, "expected_order", None),
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

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
        from .mod_manager.modsettings import add_mod
        from .mod_manager.registry import set_mod_enabled
        uuid = _resolve_uuid(args.name)
        if isinstance(uuid, dict):
            print(json.dumps(uuid, indent=2))
            return 1
        entry = _registry_entry(uuid)
        if not entry:
            result = {"error": f"Mod not found in registry: {uuid!r}"}
            print(json.dumps(result, indent=2))
            return 1
        name = entry.get("name") or uuid
        folder = entry.get("folder") or name
        version = entry.get("version") or "36028797018963968"
        result = add_mod(
            uuid=uuid,
            name=name,
            folder=folder,
            version=version,
            md5=entry.get("md5", ""),
        )
        if "error" not in result:
            set_mod_enabled(uuid, True)
            result["enabled"] = True
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "disable":
        from .mod_manager.modsettings import disable_mod
        from .mod_manager.registry import set_mod_enabled
        uuid = _resolve_uuid(args.name)
        if isinstance(uuid, dict):
            print(json.dumps(uuid, indent=2))
            return 1
        result = disable_mod(uuid)
        if "error" not in result:
            set_mod_enabled(uuid, False)
            result["enabled"] = False
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
        return 0 if result.get("success", True) else 1

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
        return 0 if result.get("success", True) else 1

    return 1
