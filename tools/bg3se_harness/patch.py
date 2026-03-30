import hashlib
import shutil
import subprocess
import sys

from .config import (
    BACKUP_SUFFIX, BG3_EXEC, DYLIB_INSTALL_NAME, HASH_FILE, INSERT_DYLIB,
)


def _hash_binary():
    h = hashlib.sha256()
    with open(str(BG3_EXEC), "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _backup_path():
    return BG3_EXEC.parent / (BG3_EXEC.name + BACKUP_SUFFIX)


def _sign_binary(path):
    """Ad-hoc sign a Mach-O binary. Ignores bundle subcomponent issues."""
    result = subprocess.run(
        ["codesign", "-f", "-s", "-", str(path)],
        capture_output=True, text=True,
    )
    # codesign may warn about subcomponents (log files in MacOS/) but still
    # signs the binary successfully. Check if the binary is actually signed.
    verify = subprocess.run(
        ["codesign", "-d", str(path)],
        capture_output=True, text=True,
    )
    return verify.returncode == 0


def is_patched():
    result = subprocess.run(
        ["otool", "-L", str(BG3_EXEC)], capture_output=True, text=True,
    )
    return "libbg3se" in result.stdout


def needs_repatch():
    if not HASH_FILE.exists():
        return True
    stored = HASH_FILE.read_text().strip()
    current_hash = _hash_binary()
    return stored != current_hash


def backup():
    dest = _backup_path()
    if dest.exists():
        return {"backed_up": True, "path": str(dest), "already_existed": True}
    shutil.copy2(str(BG3_EXEC), str(dest))
    return {"backed_up": True, "path": str(dest), "already_existed": False}


def patch():
    exe = str(BG3_EXEC)

    if not BG3_EXEC.exists():
        return {"success": False, "error": f"BG3 not found at {BG3_EXEC}"}

    if is_patched() and not needs_repatch():
        return {"already_patched": True, "action": "none"}

    if is_patched() and needs_repatch():
        print("Game binary changed since last patch. Re-patching...", file=sys.stderr)
        unpatch()

    if not INSERT_DYLIB.exists():
        return {"success": False, "error": f"insert_dylib not found at {INSERT_DYLIB}"}

    # If backup exists but binary isn't patched, the game was updated.
    # Refresh the backup to match the new clean binary.
    if _backup_path().exists() and not is_patched():
        _backup_path().unlink()

    bk = backup()

    # Don't use --strip-codesig: let insert_dylib handle the signature
    # internally. We'll re-sign after.
    result = subprocess.run(
        [
            str(INSERT_DYLIB),
            "--weak", "--inplace", "--all-yes",
            DYLIB_INSTALL_NAME, exe,
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        # Retry with --strip-codesig if needed
        result = subprocess.run(
            [
                str(INSERT_DYLIB),
                "--weak", "--inplace", "--strip-codesig", "--all-yes",
                DYLIB_INSTALL_NAME, exe,
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            return {"success": False, "error": result.stderr[-500:], "backup_path": bk["path"]}

    # Ad-hoc sign the binary
    signed = _sign_binary(exe)

    # Verify dylib is linked
    verify_otool = subprocess.run(
        ["otool", "-L", exe], capture_output=True, text=True,
    )
    has_dylib = "libbg3se" in verify_otool.stdout

    # Store hash of patched binary
    HASH_FILE.write_text(_hash_binary())

    return {
        "success": has_dylib,
        "already_patched": False,
        "backup_path": bk["path"],
        "signed": signed,
        "dylib_linked": has_dylib,
    }


def unpatch():
    bk = _backup_path()
    exe = str(BG3_EXEC)

    if not bk.exists():
        return {"success": False, "error": "No backup found to restore"}

    shutil.copy2(str(bk), exe)

    if HASH_FILE.exists():
        HASH_FILE.unlink()

    return {"success": True, "restored_from": str(bk)}
