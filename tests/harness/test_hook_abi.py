"""Hook wrapper ABI audit — does each wrapper's declared return type match what
the SHIPPED game code actually does with x0?

Why this test exists
--------------------
C++ Itanium mangling does not encode return types, and Dobby/dlsym hooking has
no type checking, so nothing in the build can catch a wrapper declared ``void``
in front of a target that returns a value in x0. On 2026-07-25 that exact defect
in ``fake_InitGame`` (COsiris::InitGame returns in x0; our wrapper was ``void``,
so the engine read whatever our last logging call left in x0) aborted every "new
game" with "We were unable to start a new game." It surfaced only when a human
tried to play. The only ground truth is the target's disassembly, so this test
re-derives it from the installed binaries on every run.

What it compares
----------------
* declared return type: parsed out of the C source (so editing a wrapper back to
  ``void`` fails the test — nothing here is a hand-copied ABI constant)
* actual ABI: classified from the target function's epilogue in the shipped
  Mach-O, located by nm symbol lookup (not by a pinned address; pinned addresses
  that appear in the source are cross-checked against nm and reported if stale)

Decision rule: walk backwards from each ``ret`` over the frame-teardown
instructions (ldp/ldr off sp, add/sub sp, mov sp,x29). The first instruction that
is not teardown decides: writes x0/w0 -> the function returns a value; a call
(bl/blr) -> ambiguous, x0 holds the callee's result and only caller analysis can
say whether that is the return value; anything else -> nothing was placed in x0,
so the function returns nothing.

Ambiguous targets cannot be auto-resolved, so the table pins the *deciding
instruction text* observed during the manual caller analysis recorded next to it.
If the binary changes so that instruction differs, the test fails and demands
re-analysis rather than quietly passing.

Offline. Skips (never silently passes) without a game install, without the
pinned game version, or without objdump/nm/lipo.
"""

from __future__ import annotations

import plistlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BG3_APP = Path.home() / (
    "Library/Application Support/Steam/steamapps/common/"
    "Baldurs Gate 3/Baldur's Gate 3.app"
)
GAME_EXEC = BG3_APP / "Contents/MacOS/Baldur's Gate 3"
OSIRIS_DYLIB = BG3_APP / "Contents/Frameworks/libOsiris.dylib"

# Game build the audit runs against. The ambiguous-epilogue resolutions below
# came from caller analysis on 7209685; the pinned deciding instruction is
# what re-validates them here.
PINNED_VERSION = "4.1.1.7398727"


# --------------------------------------------------------------------------- #
# The wrappers under audit
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Wrapper:
    name: str          # C function name of our hook wrapper
    source: str        # repo-relative path of its definition
    symbol: str        # target's Mach-O symbol (nm spelling, extra underscore)
    image: str         # "game" | "osiris"
    # Address literal the source pins for this target, if any. Cross-checked
    # against nm; a mismatch means the constant has rotted.
    pinned_addr: int | None = None
    # For targets the epilogue rule cannot decide on its own: the resolution
    # reached by inspecting the target's call sites, plus the deciding
    # instruction text that resolution was based on.
    ambiguous_resolution: str | None = None
    ambiguous_insn: str | None = None
    notes: str = ""


WRAPPERS: list[Wrapper] = [
    # ---- libOsiris.dylib: the wrappers the 2026-07-25 regression came from ----
    Wrapper(
        "fake_InitGame", "src/injector/main.c",
        "__ZN7COsiris8InitGameEv", "osiris",
        notes="the new-game abort: returns story-init status in x0 (mov x0,x23)",
    ),
    Wrapper(
        "fake_Event", "src/injector/main.c",
        "__ZN7COsiris5EventEjP16COsiArgumentDesc", "osiris",
        notes="same defect, fixed in the same commit (mov x0,x19)",
    ),
    Wrapper(
        "fake_Load", "src/injector/main.c",
        "__ZN7COsiris4LoadER12COsiSmartBuf", "osiris",
        notes="bool COsiris::Load(COsiSmartBuf&) (mov x0,x20)",
    ),
    Wrapper(
        "fake_RegisterDIVFunctions", "src/injector/main.c",
        "__ZN7COsiris20RegisterDIVFunctionsEP19TOsirisInitFunction", "osiris",
        notes="genuinely void: 7 instructions, stores only",
    ),

    # ---- main game binary ----
    Wrapper(
        "hook_EocServerStartUp", "src/entity/entity_system.c",
        "__ZN3esv9EocServer7StartUpERKN3eoc10ServerInitE", "game",
        ambiguous_resolution="void",
        ambiguous_insn="blr\tx8",
        notes="void: sole caller 0x100c8bde4 does `bl StartUp; ldr x8,[x19,#8]` "
              "— x0 is dead on return. (Wrapper is currently dead code: the "
              "DobbyHook call in entity_system.c is commented out.)",
    ),
    Wrapper(
        "hook_FeatGetFeats", "src/staticdata/staticdata_manager.c",
        "__ZNK3eoc11FeatManager8GetFeatsEv", "game",
        notes="void: fills the caller's array through x0; the two paths to its "
              "single ret leave different things in x0, so no caller can rely "
              "on it (0x1011ef964 indeed ignores x0)",
    ),
    Wrapper(
        "hook_GetMessage", "src/network/net_hooks.c",
        "__ZN3net14MessageFactory14GetFreeMessageEi", "game",
        notes="target from GAME_FN_MESSAGE_FACTORY_GET_FREE_MESSAGE; hook "
              "itself is guarded off by BG3SE_NET_HOOK",
    ),
    Wrapper(
        "fake_BinkLoadVideo", "src/game/video_skip.c",
        "__ZN3bik11BinkManager9LoadVideoERKN2ls4PathE", "game",
        notes="target from GAME_FN_BINK_LOAD_VIDEO",
    ),
]


# --------------------------------------------------------------------------- #
# Skip gates — a missing prerequisite must be visible, never a silent pass
# --------------------------------------------------------------------------- #

def _game_version() -> str | None:
    plist = BG3_APP / "Contents/Info.plist"
    if not plist.is_file():
        return None
    with plist.open("rb") as fh:
        data = plistlib.load(fh)
    return data.get("CFBundleShortVersionString") or data.get("CFBundleVersion")


def _require_environment() -> None:
    for tool in ("objdump", "nm", "lipo"):
        if shutil.which(tool) is None:
            pytest.skip(f"SKIP hook-ABI audit: `{tool}` not on PATH "
                        "(needs Xcode command line tools)")
    for path in (GAME_EXEC, OSIRIS_DYLIB):
        if not path.is_file():
            pytest.skip(f"SKIP hook-ABI audit: no game install at {path} "
                        "(CI has none; run locally to audit hook ABIs)")
    version = _game_version()
    if version != PINNED_VERSION:
        pytest.skip(f"SKIP hook-ABI audit: hook addresses are pinned to BG3 "
                    f"{PINNED_VERSION}, installed game is {version!r}")


# --------------------------------------------------------------------------- #
# Mach-O helpers
# --------------------------------------------------------------------------- #

LABEL_RE = re.compile(r"^([0-9a-f]{8,16}) <(.+)>:$")
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+\t?(.*)$")
TEARDOWN_RE = re.compile(
    r"^(ldp\s+[xd]\d+,\s*[xd]\d+,\s*\[sp"
    r"|ldr\s+[xd]\d+,\s*\[sp"
    r"|add\s+sp,\s*sp,"
    r"|sub\s+sp,\s*sp,"
    r"|mov\s+sp,\s*x29"
    r"|autibsp|retab|nop|hint)"
)
WRITES_X0_RE = re.compile(r"^[a-z][a-z0-9.]*\s+([wx])0\b")
CALL_RE = re.compile(r"^(bl|blr)\b")


@pytest.fixture(scope="session")
def thin_slices(tmp_path_factory) -> dict[str, Path]:
    """arm64 slices of the shipped images.

    objdump's --start-address is ignored on a fat Mach-O, so extract the arm64
    slice once per session. (arm64 only: every pinned address in this project is
    an arm64 Ghidra address.)
    """
    _require_environment()
    out_dir = tmp_path_factory.mktemp("bg3_thin")
    slices = {}
    for key, src in (("game", GAME_EXEC), ("osiris", OSIRIS_DYLIB)):
        dst = out_dir / f"{key}.arm64"
        subprocess.run(["lipo", "-thin", "arm64", "-output", str(dst), str(src)],
                       check=True, capture_output=True)
        slices[key] = dst
    return slices


@pytest.fixture(scope="session")
def symbol_addrs(thin_slices) -> dict[str, dict[str, int]]:
    """{image: {symbol: vmaddr}} for the symbols this test needs."""
    wanted: dict[str, set[str]] = {"game": set(), "osiris": set()}
    for w in WRAPPERS:
        wanted[w.image].add(w.symbol)
    resolved: dict[str, dict[str, int]] = {}
    for image, path in thin_slices.items():
        out = subprocess.run(["nm", "-arch", "arm64", str(path)],
                             capture_output=True, text=True).stdout
        table: dict[str, int] = {}
        for line in out.splitlines():
            parts = line.split(maxsplit=2)
            if len(parts) == 3 and parts[2] in wanted[image]:
                table[parts[2]] = int(parts[0], 16)
        resolved[image] = table
    return resolved


def disassemble(binary: Path, addr: int, window: int = 0x40000):
    """Instructions of the function starting at addr (stops at the next symbol)."""
    out = subprocess.run(
        ["objdump", "-d", f"--start-address=0x{addr:x}",
         f"--stop-address=0x{addr + window:x}", str(binary)],
        capture_output=True, text=True).stdout
    insns, started = [], False
    for line in out.splitlines():
        label = LABEL_RE.match(line.strip())
        if label:
            if not started:
                started = True
                continue
            break
        insn = INSN_RE.match(line)
        if insn and started:
            insns.append((int(insn.group(1), 16), insn.group(3).strip()))
    return insns


@dataclass
class RetSite:
    ret_addr: int
    deciding_addr: int
    deciding_insn: str
    verdict: str


@dataclass
class Classification:
    verdict: str            # "value" | "void" | "ambiguous" | "mixed" | "no-ret"
    sites: list[RetSite] = field(default_factory=list)

    def describe(self) -> str:
        return "; ".join(
            f"ret@0x{s.ret_addr:x} decided by 0x{s.deciding_addr:x} "
            f"{s.deciding_insn!r} -> {s.verdict}" for s in self.sites)


def classify(insns) -> Classification:
    sites, verdicts = [], set()
    for i, (addr, text) in enumerate(insns):
        if text != "ret" and not text.startswith("ret "):
            continue
        j = i - 1
        while j >= 0 and TEARDOWN_RE.match(insns[j][1]):
            j -= 1
        dec_addr, dec_insn = insns[j] if j >= 0 else (addr, "<function start>")
        if WRITES_X0_RE.match(dec_insn):
            verdict = "value"
        elif CALL_RE.match(dec_insn):
            verdict = "ambiguous"
        else:
            verdict = "void"
        verdicts.add(verdict)
        sites.append(RetSite(addr, dec_addr, dec_insn, verdict))
    if not sites:
        return Classification("no-ret", sites)
    if verdicts == {"value"}:
        return Classification("value", sites)
    if "ambiguous" in verdicts:
        return Classification("ambiguous", sites)
    if verdicts == {"void"}:
        return Classification("void", sites)
    # Some paths set x0 and some do not: no caller can rely on it.
    return Classification("mixed", sites)


DEF_RE_CACHE: dict[str, str] = {}


def declared_return_type(wrapper: Wrapper) -> str:
    """The return type as written in our C source (not a copy kept in this file)."""
    key = wrapper.source
    if key not in DEF_RE_CACHE:
        DEF_RE_CACHE[key] = (REPO_ROOT / key).read_text()
    src = DEF_RE_CACHE[key]
    matches = [m for m in re.finditer(
        r"^(?P<pre>[^\n;]*?)\b" + re.escape(wrapper.name) + r"\s*\(", src, re.M)
        if "static" in m.group("pre")]
    assert matches, (f"no definition of {wrapper.name}() found in {key} — "
                     "the audit table has rotted, fix the table or the name")
    assert len(matches) == 1, (
        f"{len(matches)} candidate definitions of {wrapper.name}() in {key}; "
        "the return-type parser cannot tell them apart")
    pre = matches[0].group("pre")
    pre = re.sub(r"__attribute__\s*\(\(.*?\)\)", " ", pre)
    pre = pre.replace("static", " ").strip()
    return re.sub(r"\s+", " ", pre)


def returns_something(decl: str) -> bool:
    return decl.replace(" ", "") not in ("void",)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_classifier_detects_both_outcomes(thin_slices, symbol_addrs):
    """The detector must be live: prove it separates a value-returning target
    from a void one on two independently established cases in the shipped
    libOsiris. Without this, a table full of passes could just mean the
    classifier never fires."""
    osiris = thin_slices["osiris"]
    init_game = symbol_addrs["osiris"]["__ZN7COsiris8InitGameEv"]
    reg_div = symbol_addrs["osiris"][
        "__ZN7COsiris20RegisterDIVFunctionsEP19TOsirisInitFunction"]

    init = classify(disassemble(osiris, init_game))
    assert init.verdict == "value", init.describe()
    assert re.match(r"^mov\s+x0,", init.sites[0].deciding_insn), init.describe()

    reg = classify(disassemble(osiris, reg_div))
    assert reg.verdict == "void", reg.describe()


@pytest.mark.parametrize("wrapper", WRAPPERS, ids=lambda w: w.name)
def test_wrapper_return_type_matches_target_abi(wrapper, thin_slices, symbol_addrs):
    addr = symbol_addrs[wrapper.image].get(wrapper.symbol)
    if addr is None:
        pytest.skip(f"SKIP {wrapper.name}: symbol {wrapper.symbol} not found in "
                    f"the {wrapper.image} image — target moved or was stripped, "
                    "ABI cannot be verified")

    if wrapper.pinned_addr is not None:
        assert addr == wrapper.pinned_addr, (
            f"{wrapper.name}: the address pinned in {wrapper.source} "
            f"(0x{wrapper.pinned_addr:x}) is not where {wrapper.symbol} lives on "
            f"{PINNED_VERSION} (nm says 0x{addr:x}) — the hook targets the wrong "
            "function")

    result = classify(disassemble(thin_slices[wrapper.image], addr))
    assert result.verdict != "no-ret", (
        f"{wrapper.name}: found no ret in {wrapper.symbol} @0x{addr:x}; "
        "disassembly window or symbol boundary is wrong, ABI unverified")

    verdict = result.verdict
    if verdict == "ambiguous":
        assert wrapper.ambiguous_resolution is not None, (
            f"{wrapper.name}: {wrapper.symbol} @0x{addr:x} ends in a call, so "
            f"the epilogue alone cannot say whether it returns a value "
            f"({result.describe()}). Inspect its call sites and record the "
            "resolution in the audit table.")
        observed = result.sites[0].deciding_insn
        assert observed == wrapper.ambiguous_insn, (
            f"{wrapper.name}: the manual resolution recorded for "
            f"{wrapper.symbol} was based on deciding instruction "
            f"{wrapper.ambiguous_insn!r}, but the shipped binary now shows "
            f"{observed!r} — re-do the caller analysis, the old verdict is void")
        verdict = wrapper.ambiguous_resolution

    declared = declared_return_type(wrapper)
    target_returns_value = verdict == "value"

    if target_returns_value:
        assert returns_something(declared), (
            f"ABI MISMATCH: {wrapper.name} in {wrapper.source} is declared "
            f"`{declared}` but {wrapper.symbol} @0x{addr:x} returns a value in "
            f"x0 ({result.describe()}). A void wrapper hands the engine "
            "whatever our post-call work left in x0 — the 2026-07-25 "
            "new-game-abort bug. Declare it uint64_t, capture the original's "
            "result, and return it after all post-call work.")
    else:
        assert not returns_something(declared), (
            f"ABI MISMATCH: {wrapper.name} in {wrapper.source} is declared "
            f"`{declared}` but {wrapper.symbol} @0x{addr:x} puts nothing "
            f"meaningful in x0 ({result.describe()}). Benign at runtime, but the "
            "declaration is wrong — make the wrapper void, or update the audit "
            "table if the target's ABI actually changed.")
