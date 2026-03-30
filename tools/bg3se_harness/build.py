import shutil
import subprocess
import sys

from .config import DEPLOYED_DYLIB, DYLIB_OUTPUT, PROJECT_ROOT


def build():
    build_dir = PROJECT_ROOT / "build"
    if not build_dir.exists():
        print("Build directory missing. Run cmake first:", file=sys.stderr)
        print(f"  mkdir -p {build_dir} && cd {build_dir} && cmake ..", file=sys.stderr)
        return {"success": False, "error": "build/ directory not found"}

    result = subprocess.run(
        ["cmake", "--build", str(build_dir)],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return {"success": False, "error": result.stderr[-500:]}

    return {"success": True}


def verify():
    if not DYLIB_OUTPUT.exists():
        return {"verified": False, "error": f"{DYLIB_OUTPUT} not found"}

    result = subprocess.run(
        ["file", str(DYLIB_OUTPUT)], capture_output=True, text=True,
    )
    output = result.stdout
    has_arm64 = "arm64" in output
    has_x86 = "x86_64" in output

    return {
        "verified": has_arm64 and has_x86,
        "arm64": has_arm64,
        "x86_64": has_x86,
        "file_output": output.strip(),
    }


def deploy():
    if not DYLIB_OUTPUT.exists():
        return {"deployed": False, "error": "dylib not built yet"}

    dest = DEPLOYED_DYLIB
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(DYLIB_OUTPUT), str(dest))

    return {"deployed": True, "deploy_path": str(dest)}
