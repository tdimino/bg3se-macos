/**
 * ARM64 Instruction Decoder Implementation
 * Issue #44 - ARM64-Safe Inline Hooking
 */

#include "arm64_decode.h"
#include "../core/logging.h"
#include <string.h>

// =============================================================================
// Decoding Functions
// =============================================================================

/* Branch immediate -> byte displacement. Not `(int64_t)imm << 2`: left-
 * shifting a negative value is undefined (C11 6.5.7p4) and every branch
 * immediate is sign-extended first, so backward branches hit it on each
 * decode (UBSan caught it live during hook install). The widest field is
 * imm26, so imm * 4 cannot overflow. */
static inline int64_t arm64_scale_branch_imm(int64_t imm) {
    return imm * 4;
}

uint64_t arm64_decode_adrp_target(uint32_t insn, uint64_t pc) {
    if (!arm64_is_adrp(insn)) {
        return 0;
    }

    // Extract immediate fields from ADRP encoding:
    // [31]    = 1 (ADRP)
    // [30:29] = immlo (2 bits)
    // [28:24] = 10000
    // [23:5]  = immhi (19 bits)
    // [4:0]   = Rd
    uint32_t immlo = (insn >> 29) & 0x3;
    uint32_t immhi = (insn >> 5) & 0x7FFFF;

    // Combine into 21-bit immediate
    int64_t imm21 = (int64_t)((immhi << 2) | immlo);

    // Sign-extend from 21 bits
    if (imm21 & 0x100000) {
        imm21 |= ~((int64_t)0x1FFFFF);
    }

    // Calculate target: (PC & ~0xFFF) + (imm21 << 12)
    uint64_t pc_page = pc & ~(uint64_t)0xFFF;
    uint64_t target_page = pc_page + ((uint64_t)imm21 << 12);

    return target_page;
}

uint32_t arm64_decode_ldr_offset(uint32_t insn) {
    // LDR (unsigned offset) encoding:
    // [31:30] = size (10 = 64-bit, 01 = 32-bit)
    // [29:27] = 111
    // [26]    = V (0 for integer)
    // [25:24] = 01
    // [23:22] = opc
    // [21:10] = imm12
    // [9:5]   = Rn
    // [4:0]   = Rt

    uint32_t imm12 = (insn >> 10) & 0xFFF;

    // Scale depends on size bits
    uint32_t size = (insn >> 30) & 0x3;
    uint32_t scale = 1 << size;  // 4 for 32-bit, 8 for 64-bit

    return imm12 * scale;
}

void arm64_decode_instruction(uint32_t insn, uint64_t pc, ARM64DecodedInsn* out) {
    memset(out, 0, sizeof(*out));
    out->raw = insn;
    out->type = ARM64_INSN_UNKNOWN;

    // ADRP
    if (arm64_is_adrp(insn)) {
        out->type = ARM64_INSN_ADRP;
        out->rd = arm64_get_rd(insn);
        out->target_page = arm64_decode_adrp_target(insn, pc);
        out->is_pc_relative = true;

        // Extract immediate for reference
        uint32_t immlo = (insn >> 29) & 0x3;
        uint32_t immhi = (insn >> 5) & 0x7FFFF;
        int64_t imm21 = (int64_t)((immhi << 2) | immlo);
        if (imm21 & 0x100000) imm21 |= ~((int64_t)0x1FFFFF);
        out->imm = imm21;
        return;
    }

    // LDR immediate 64-bit
    if (arm64_is_ldr_imm64(insn)) {
        out->type = ARM64_INSN_LDR_IMM64;
        out->rd = arm64_get_rd(insn);
        out->rn = arm64_get_rn(insn);
        out->ldr_offset = arm64_decode_ldr_offset(insn);
        out->imm = out->ldr_offset;
        return;
    }

    // LDR immediate 32-bit
    if (arm64_is_ldr_imm32(insn)) {
        out->type = ARM64_INSN_LDR_IMM32;
        out->rd = arm64_get_rd(insn);
        out->rn = arm64_get_rn(insn);
        out->ldr_offset = arm64_decode_ldr_offset(insn);
        out->imm = out->ldr_offset;
        return;
    }

    // STP pre-index
    if ((insn & ARM64_STP_PRE_MASK) == ARM64_STP_PRE_OP) {
        out->type = ARM64_INSN_STP_PRE;
        out->rd = insn & 0x1F;              // Rt1
        out->rt2 = (insn >> 10) & 0x1F;     // Rt2
        out->rn = (insn >> 5) & 0x1F;       // Rn

        // imm7 is sign-extended, scaled by 8
        int32_t imm7 = (insn >> 15) & 0x7F;
        if (imm7 & 0x40) imm7 |= (int32_t)0xFFFFFF80;
        out->imm = imm7 * 8;
        return;
    }

    // SUB immediate
    if ((insn & ARM64_SUB_IMM_MASK) == ARM64_SUB_IMM_OP) {
        out->type = ARM64_INSN_SUB_IMM;
        out->rd = arm64_get_rd(insn);
        out->rn = arm64_get_rn(insn);
        uint32_t imm12 = (insn >> 10) & 0xFFF;
        uint32_t shift = ((insn >> 22) & 0x3) ? 12 : 0;
        out->imm = (int64_t)imm12 << shift;
        return;
    }

    // ADD immediate
    if ((insn & ARM64_ADD_IMM_MASK) == ARM64_ADD_IMM_OP) {
        out->type = ARM64_INSN_ADD_IMM;
        out->rd = arm64_get_rd(insn);
        out->rn = arm64_get_rn(insn);
        uint32_t imm12 = (insn >> 10) & 0xFFF;
        uint32_t shift = ((insn >> 22) & 0x3) ? 12 : 0;
        out->imm = (int64_t)imm12 << shift;
        return;
    }

    // B - unconditional branch
    if ((insn & ARM64_B_MASK) == ARM64_B_OP) {
        out->type = ARM64_INSN_B;
        out->is_pc_relative = true;
        int32_t imm26 = insn & 0x3FFFFFF;
        if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000;
        out->imm = arm64_scale_branch_imm(imm26);
        return;
    }

    // BL - branch with link
    if ((insn & ARM64_BL_MASK) == ARM64_BL_OP) {
        out->type = ARM64_INSN_BL;
        out->is_pc_relative = true;
        int32_t imm26 = insn & 0x3FFFFFF;
        if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000;
        out->imm = arm64_scale_branch_imm(imm26);
        return;
    }

    // BR - branch to register
    if ((insn & ARM64_BR_MASK) == ARM64_BR_OP) {
        out->type = ARM64_INSN_BR;
        out->rn = (insn >> 5) & 0x1F;
        return;
    }

    // BLR - branch with link to register
    if ((insn & ARM64_BLR_MASK) == ARM64_BLR_OP) {
        out->type = ARM64_INSN_BLR;
        out->rn = (insn >> 5) & 0x1F;
        return;
    }

    // RET
    if ((insn & ARM64_RET_MASK) == ARM64_RET_OP) {
        out->type = ARM64_INSN_RET;
        out->rn = (insn >> 5) & 0x1F;
        return;
    }

    // CBZ/CBNZ
    if ((insn & ARM64_CBZ_MASK) == ARM64_CBZ_OP) {
        out->type = ARM64_INSN_CBZ;
        out->is_pc_relative = true;
        out->rd = insn & 0x1F;
        int32_t imm19 = (insn >> 5) & 0x7FFFF;
        if (imm19 & 0x40000) imm19 |= (int32_t)0xFFF80000;
        out->imm = arm64_scale_branch_imm(imm19);
        return;
    }
    if ((insn & ARM64_CBZ_MASK) == ARM64_CBNZ_OP) {
        out->type = ARM64_INSN_CBNZ;
        out->is_pc_relative = true;
        out->rd = insn & 0x1F;
        int32_t imm19 = (insn >> 5) & 0x7FFFF;
        if (imm19 & 0x40000) imm19 |= (int32_t)0xFFF80000;
        out->imm = arm64_scale_branch_imm(imm19);
        return;
    }

    // TBZ/TBNZ
    if ((insn & ARM64_TBZ_MASK) == ARM64_TBZ_OP) {
        uint32_t op = (insn >> 24) & 0x1;
        out->type = op ? ARM64_INSN_TBNZ : ARM64_INSN_TBZ;
        out->is_pc_relative = true;
        out->rd = insn & 0x1F;
        int32_t imm14 = (insn >> 5) & 0x3FFF;
        if (imm14 & 0x2000) imm14 |= (int32_t)0xFFFFC000;
        out->imm = arm64_scale_branch_imm(imm14);
        return;
    }

    // B.cond - conditional branch
    if ((insn & ARM64_BCOND_MASK) == ARM64_BCOND_OP) {
        out->type = ARM64_INSN_BCOND;
        out->is_pc_relative = true;
        int32_t imm19 = (insn >> 5) & 0x7FFFF;
        if (imm19 & 0x40000) imm19 |= (int32_t)0xFFF80000;
        out->imm = arm64_scale_branch_imm(imm19);
        return;
    }

    // MOV register (ORR with XZR)
    if ((insn & ARM64_MOV_REG_MASK) == ARM64_MOV_REG_OP) {
        out->type = ARM64_INSN_MOV_REG;
        out->rd = arm64_get_rd(insn);
        out->rm = (insn >> 16) & 0x1F;
        return;
    }

    // STR immediate
    if ((insn & 0xFF800000) == 0xF9000000) {
        out->type = ARM64_INSN_STR_IMM;
        out->rd = arm64_get_rd(insn);
        out->rn = arm64_get_rn(insn);
        uint32_t imm12 = (insn >> 10) & 0xFFF;
        out->imm = imm12 * 8;  // Scaled by 8 for 64-bit
        return;
    }
}

const char* arm64_insn_type_name(ARM64InsnType type) {
    switch (type) {
        case ARM64_INSN_UNKNOWN:   return "UNKNOWN";
        case ARM64_INSN_ADRP:      return "ADRP";
        case ARM64_INSN_LDR_IMM64: return "LDR_IMM64";
        case ARM64_INSN_LDR_IMM32: return "LDR_IMM32";
        case ARM64_INSN_STP_PRE:   return "STP_PRE";
        case ARM64_INSN_SUB_IMM:   return "SUB_IMM";
        case ARM64_INSN_ADD_IMM:   return "ADD_IMM";
        case ARM64_INSN_B:         return "B";
        case ARM64_INSN_BL:        return "BL";
        case ARM64_INSN_BR:        return "BR";
        case ARM64_INSN_BLR:       return "BLR";
        case ARM64_INSN_RET:       return "RET";
        case ARM64_INSN_CBZ:       return "CBZ";
        case ARM64_INSN_CBNZ:      return "CBNZ";
        case ARM64_INSN_TBZ:       return "TBZ";
        case ARM64_INSN_TBNZ:      return "TBNZ";
        case ARM64_INSN_BCOND:     return "B.cond";
        case ARM64_INSN_MOV_REG:   return "MOV_REG";
        case ARM64_INSN_STR_IMM:   return "STR_IMM";
        default:                   return "???";
    }
}

// =============================================================================
// Prologue Analysis Functions
// =============================================================================

bool arm64_analyze_prologue(void* func_addr, int max_instructions, ARM64PrologueAnalysis* out) {
    if (!func_addr || !out || max_instructions <= 0) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->func_addr = func_addr;
    out->num_instructions = max_instructions;
    out->safe_hook_offset = -1;
    out->first_unsafe_offset = -1;

    // Track last ADRP for pairing with subsequent LDR
    int last_adrp_offset = -1;
    uint8_t last_adrp_reg = 0;
    uint64_t last_adrp_page = 0;

    // Track the end of unsafe region (past all ADRP+LDR pairs)
    int unsafe_region_end = 0;

    uint32_t* instructions = (uint32_t*)func_addr;

    for (int i = 0; i < max_instructions; i++) {
        uint32_t insn = instructions[i];
        uint64_t pc = (uint64_t)func_addr + (i * 4);

        ARM64DecodedInsn decoded;
        arm64_decode_instruction(insn, pc, &decoded);

        // Track ADRP instructions
        if (decoded.type == ARM64_INSN_ADRP) {
            if (out->first_unsafe_offset < 0) {
                out->first_unsafe_offset = i * 4;
            }

            last_adrp_offset = i * 4;
            last_adrp_reg = decoded.rd;
            last_adrp_page = decoded.target_page;

            // ADRP extends unsafe region by at least 2 instructions
            if ((i + 2) * 4 > unsafe_region_end) {
                unsafe_region_end = (i + 2) * 4;
            }
        }

        // Check for LDR that pairs with previous ADRP
        if ((decoded.type == ARM64_INSN_LDR_IMM64 || decoded.type == ARM64_INSN_LDR_IMM32) &&
            last_adrp_offset >= 0 &&
            decoded.rn == last_adrp_reg) {

            // Found ADRP+LDR pair
            if (out->adrp_pattern_count < MAX_ADRP_PATTERNS) {
                int idx = out->adrp_pattern_count++;
                out->adrp_patterns[idx].adrp_offset = last_adrp_offset;
                out->adrp_patterns[idx].ldr_offset = i * 4;
                out->adrp_patterns[idx].reg = last_adrp_reg;
                out->adrp_patterns[idx].resolved_target = last_adrp_page + decoded.ldr_offset;
            }

            // LDR completes the pair, extend unsafe region
            if ((i + 1) * 4 > unsafe_region_end) {
                unsafe_region_end = (i + 1) * 4;
            }

            last_adrp_offset = -1;  // Reset for next pair
        }

        // Track stack frame setup
        if (decoded.type == ARM64_INSN_STP_PRE && decoded.rn == 31) {
            // STP to SP - prologue frame setup
            if (decoded.rd == 29 && decoded.rt2 == 30) {
                out->has_frame_pointer = true;
            }
        }

        if (decoded.type == ARM64_INSN_SUB_IMM && decoded.rn == 31 && decoded.rd == 31) {
            // SUB SP, SP, #imm - stack allocation
            out->stack_frame_size = (int)decoded.imm;
        }

        // Any PC-relative instruction extends unsafe region
        if (decoded.is_pc_relative && out->first_unsafe_offset < 0) {
            out->first_unsafe_offset = i * 4;
        }

        // Find safe hook point (first instruction after unsafe region)
        if (out->safe_hook_offset < 0 && i > 0) {
            int current_offset = i * 4;
            if (current_offset >= unsafe_region_end && !decoded.is_pc_relative) {
                out->safe_hook_offset = current_offset;
            }
        }
    }

    // If no unsafe instructions found, safe to hook at entry
    if (out->first_unsafe_offset < 0) {
        out->safe_hook_offset = 0;
    }

    // PREFER offset 0. The 16-byte (4-instruction) patch window is copied verbatim
    // into the trampoline and run exactly once, so hooking at +0 is always correct
    // when that window holds no PC-relative instruction -- regardless of a PC-relative
    // instruction LATER in the prologue (e.g. a `bl` at +0x34). The forward-skip loop
    // above must NOT be used in that case: it re-runs the skipped prologue in the
    // trampoline, and a skipped side-effecting instruction (e.g. `stp x_,x_,[sp,#-imm]!`)
    // then executes TWICE -- double-decrementing SP and corrupting the callee's stack
    // frame. That was the confirmed root cause of the ExecuteStatsFunctors AttackTarget
    // SIGSEGV (skip=4 re-ran `stp x28,x27,[sp,#-0x60]!` -> crash in HitDesc::operator=).
    //
    // A DIRTY window fails closed (-1). The forward skip is not a valid answer
    // there either: the trampoline copies the skipped instructions unrelocated,
    // so an ADRP/ADR/LDR-literal evaluates against the trampoline's PC and a
    // B/BL/CBZ/TBZ branches to the wrong place (issue #106). Until relocation
    // exists, arm64_safe_hook() refuses such targets and callers take their
    // Dobby fallback. Both classifiers are consulted: the decoder's typed view
    // and arm64_is_pc_relative(), which also knows ADR and LDR-literal.
    {
        int window = (max_instructions < 4) ? max_instructions : 4;
        bool window_clean = true;
        for (int w = 0; w < window; w++) {
            ARM64DecodedInsn d;
            arm64_decode_instruction(instructions[w], (uint64_t)func_addr + w * 4, &d);
            if (d.is_pc_relative || arm64_is_pc_relative(instructions[w])) {
                window_clean = false;
                break;
            }
        }
        out->safe_hook_offset = window_clean ? 0 : -1;
    }

    return true;
}

int arm64_find_safe_hook_point(void* func_addr, int max_search) {
    ARM64PrologueAnalysis analysis;
    if (!arm64_analyze_prologue(func_addr, max_search / 4, &analysis)) {
        return -1;
    }
    return analysis.safe_hook_offset;
}

bool arm64_is_safe_to_hook_at_entry(void* func_addr) {
    // Check first 4 instructions (16 bytes)
    uint32_t* instructions = (uint32_t*)func_addr;
    for (int i = 0; i < 4; i++) {
        if (arm64_is_pc_relative(instructions[i])) {
            return false;
        }
    }
    return true;
}

void arm64_print_prologue_analysis(const ARM64PrologueAnalysis* analysis) {
    if (!analysis) return;

    log_message("[ARM64] === Prologue Analysis: %p ===", analysis->func_addr);

    uint32_t* instructions = (uint32_t*)analysis->func_addr;
    for (int i = 0; i < analysis->num_instructions && i < 16; i++) {
        uint32_t insn = instructions[i];
        uint64_t pc = (uint64_t)analysis->func_addr + (i * 4);

        ARM64DecodedInsn decoded;
        arm64_decode_instruction(insn, pc, &decoded);

        const char* marker = "";
        if (analysis->safe_hook_offset == i * 4) {
            marker = " <-- SAFE HOOK POINT";
        } else if (decoded.is_pc_relative) {
            marker = " [PC-relative - UNSAFE]";
        }

        switch (decoded.type) {
            case ARM64_INSN_ADRP:
                log_message("[ARM64] +%02x: %08x  ADRP x%d, 0x%llx%s",
                           i * 4, insn, decoded.rd, decoded.target_page, marker);
                break;
            case ARM64_INSN_LDR_IMM64:
            case ARM64_INSN_LDR_IMM32:
                log_message("[ARM64] +%02x: %08x  LDR  x%d, [x%d, #0x%x]%s",
                           i * 4, insn, decoded.rd, decoded.rn, decoded.ldr_offset, marker);
                break;
            case ARM64_INSN_STP_PRE:
                log_message("[ARM64] +%02x: %08x  STP  x%d, x%d, [x%d, #%lld]!%s",
                           i * 4, insn, decoded.rd, decoded.rt2, decoded.rn, decoded.imm, marker);
                break;
            case ARM64_INSN_SUB_IMM:
                log_message("[ARM64] +%02x: %08x  SUB  x%d, x%d, #0x%llx%s",
                           i * 4, insn, decoded.rd, decoded.rn, decoded.imm, marker);
                break;
            default:
                log_message("[ARM64] +%02x: %08x  %-12s%s",
                           i * 4, insn, arm64_insn_type_name(decoded.type), marker);
                break;
        }
    }

    log_message("[ARM64] --- Summary ---");
    log_message("[ARM64] ADRP+LDR patterns: %d", analysis->adrp_pattern_count);
    for (int i = 0; i < analysis->adrp_pattern_count; i++) {
        log_message("[ARM64]   Pattern %d: ADRP@+%02x + LDR@+%02x -> 0x%llx",
                   i,
                   analysis->adrp_patterns[i].adrp_offset,
                   analysis->adrp_patterns[i].ldr_offset,
                   analysis->adrp_patterns[i].resolved_target);
    }

    log_message("[ARM64] First unsafe offset: %s",
               analysis->first_unsafe_offset >= 0 ?
               "+" : "none");
    if (analysis->first_unsafe_offset >= 0) {
        log_message("[ARM64]   +0x%x", analysis->first_unsafe_offset);
    }

    log_message("[ARM64] Safe hook offset: %s",
               analysis->safe_hook_offset >= 0 ?
               "+" : "NONE FOUND");
    if (analysis->safe_hook_offset >= 0) {
        log_message("[ARM64]   +0x%x", analysis->safe_hook_offset);
    }

    if (analysis->stack_frame_size > 0) {
        log_message("[ARM64] Stack frame: %d bytes", analysis->stack_frame_size);
    }
    if (analysis->has_frame_pointer) {
        log_message("[ARM64] Has frame pointer (x29)");
    }
}
