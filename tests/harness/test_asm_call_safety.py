"""Inline-asm calls into game code must declare every AAPCS64 caller-saved
register clobbered, and branch decoding must not left-shift signed values.

Both defects are invisible at -O0 and appear only once the optimizer keeps
live values in x2-x7/v* across the asm, or exploits the undefined shift.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CALL_C = REPO / "src/entity/arm64_call.c"
DECODE_C = REPO / "src/hooks/arm64_decode.c"


def _asm_blocks(text):
    return re.findall(r"__asm__\s+volatile\s*\((.*?)\);", text, flags=re.S)


def test_every_blr_asm_block_uses_the_full_clobber_list():
    text = CALL_C.read_text()
    macro = re.search(r"#define AAPCS64_CALL_CLOBBERS(.*?)\n\n", text, flags=re.S).group(1)
    for reg in [f"x{i}" for i in range(0, 18) if i != 18] + ["x30", "cc", "memory"] + \
               [f"v{i}" for i in range(32)]:
        assert f'"{reg}"' in macro, f"AAPCS64_CALL_CLOBBERS is missing {reg}"
    assert '"x18"' not in macro, "x18 is reserved on Darwin"

    blocks = [b for b in _asm_blocks(text) if "blr" in b]
    assert blocks, "found no blr asm blocks — scanner broken"
    for block in blocks:
        assert "AAPCS64_CALL_CLOBBERS" in block, block[:200]


def test_branch_immediates_are_not_left_shifted_as_signed():
    text = DECODE_C.read_text()
    # imm14/imm19/imm26 are sign-extended branch fields; imm12 is unsigned.
    bad = re.findall(r"\(int64_t\)\s*imm(?:14|19|26)\s*<<", text)
    assert not bad, f"signed left shift of a branch immediate is UB: {bad}"
    assert text.count("arm64_scale_branch_imm(") >= 7  # definition + 6 sites
