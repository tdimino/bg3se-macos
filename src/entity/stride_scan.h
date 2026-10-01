/**
 * BG3SE-macOS - Dynamic-array stride DETECTOR
 *
 * WHY THIS EXISTS
 * ---------------
 * A wrong per-element stride on a FIELD_TYPE_DYNAMIC_ARRAY is the quietest bug
 * in this codebase: element [0] sits AT the array base and therefore reads
 * perfectly no matter what the stride says, while every later element slides
 * progressively into garbage. `eoc::spell::BookComponent.Spells` shipped with 88
 * (copied from the Windows BG3SE headers) when the ARM64 stride is 0x68=104, and
 * nothing in the project could see it: the tier-0 sweep in
 * tests/tier0/test_component_offsets.c only checks that a DECLARATION agrees
 * with a canonical table, so it stays green when both sides are wrong.
 *
 * This module checks a declared stride against the DATA. It reads a
 * discriminating field of the element layout at base + i*stride for a set of
 * candidate strides and scores which candidate reads coherently.
 *
 * THE SCORING RULE (and why it is shaped this way)
 * ------------------------------------------------
 * For a candidate stride s and element i, the element is "coherent" iff EVERY
 * probe derived from the element layout is plausible at base + i*s + probeOffset.
 * score(s) = length of the run of consecutive coherent elements starting at i=0.
 *
 *   - A run, not a hit count. Ext.Debug.ReadFixedString resolves ANY integer that
 *     happens to be a valid string-table index; during the 0x68 investigation it
 *     cheerfully returned "Version64", "RampIntensity_R" and an animation path
 *     from unrelated offsets. A single hit — even a majority of hits — is noise.
 *     The measured noise floor there was 7-8 plausible out of 12 for EVERY wrong
 *     candidate; only 0x68 gave 12/12, consecutively.
 *   - Element 0 is coherent for every candidate (same address), so a run of 1 is
 *     free and a run of 2 is a coin flip at that noise rate. Evidence starts at 3.
 *   - Multiples of the true stride (2s, 3s...) read every k-th real element and
 *     tie at a full run BY CONSTRUCTION. So the winner is the SMALLEST stride
 *     achieving the best run, and a declared stride that ties with the best is a
 *     PASS even when a smaller stride also ties.
 *
 * A FAIL is only ever reported when ALL of these hold:
 *   1. the best run is at least STRIDE_SCAN_MIN_RUN (3) elements long,
 *   2. the declared stride's run is strictly shorter than the best, and
 *   3. the winning run beats the MEASURED noise floor:
 *        p_hat = fraction of coherent (candidate, element) pairs over every
 *                candidate except the winner, elements i>=1 — i.e. the noise
 *                floor of this probe set ON THIS DATA, measured, not assumed;
 *        expectedFalseWins = candidates * p_hat^(bestRun-1) <= 0.01.
 * A PASS carries the same significance requirement, so "every stride looks fine"
 * can never be reported as agreement. Otherwise the verdict is INCONCLUSIVE with
 * a specific reason. That is what makes the detector honest with weak probes: a
 * single FixedString probe at p_hat~0.6 needs a ~20-element run before it means
 * anything, and the scan says so instead of guessing, while a Guid+bounded-int
 * conjunction (p_hat~0.02) concludes from 4.
 *
 * The bound is keyed to the RUN rather than to a full sweep of all N elements on
 * purpose: real arrays contain elements whose probe field is legitimately empty,
 * which truncates EVERY candidate's run, and demanding a full sweep would turn
 * those into a permanent "cannot judge".
 *
 * Offline-testable by construction: it reads through safe_memory, so
 * tests/tier0/test_stride_scan.c drives it over synthetic in-process buffers
 * with a known true stride and a deliberately wrong declaration.
 */

#ifndef BG3SE_STRIDE_SCAN_H
#define BG3SE_STRIDE_SCAN_H

#include <stdint.h>
#include <stdbool.h>

#include "component_property.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Probes — per-element plausibility tests derived from the element layout
// ============================================================================

typedef enum {
    STRIDE_PROBE_FIXEDSTRING = 0,  // u32 string-table index that resolves
    STRIDE_PROBE_GUID,             // 16 bytes with GUID-like byte diversity
    STRIDE_PROBE_POINTER,          // 8-byte aligned, in-range, readable pointer
    STRIDE_PROBE_ENTITY_HANDLE,    // packed (index|salt|type) with a sane type
    STRIDE_PROBE_SMALL_INT,        // u32 <= param
    STRIDE_PROBE_BOOL,             // u8 <= 1
} StrideProbeKind;

typedef struct {
    uint16_t offset;        // byte offset within the element
    uint8_t  kind;          // StrideProbeKind
    uint32_t param;         // SMALL_INT: inclusive max. Unused otherwise.
    const char *field;      // field name, for reporting
} StrideProbe;

#define STRIDE_SCAN_MAX_PROBES      6
#define STRIDE_SCAN_MAX_ELEMENTS    32     // cost bound: reads = candidates * N
#define STRIDE_SCAN_MIN_ELEMENTS    4      // below this a run carries no signal
#define STRIDE_SCAN_MIN_RUN         3      // run of 1 is free, run of 2 is a coin flip
#define STRIDE_SCAN_MIN_STRIDE      4
#define STRIDE_SCAN_MAX_STRIDE      512
#define STRIDE_SCAN_STRIDE_STEP     4
#define STRIDE_SCAN_ELEM_WINDOW     288    // bytes read per (candidate, element)

// Max tolerated expected number of candidates that reach a full run by chance.
#define STRIDE_SCAN_MAX_FALSE_WINS  0.01

// ============================================================================
// Result
// ============================================================================

typedef enum {
    STRIDE_VERDICT_PASS = 0,       // declared stride scores as well as the best
    STRIDE_VERDICT_FAIL,           // another stride reads coherently and it does not
    STRIDE_VERDICT_INCONCLUSIVE,   // cannot judge — reason is always specific
} StrideVerdict;

typedef struct {
    StrideVerdict verdict;
    char reason[192];              // ALWAYS set for INCONCLUSIVE/FAIL

    uint32_t declaredStride;
    uint32_t declaredRun;
    uint32_t bestStride;           // smallest stride achieving bestRun
    uint32_t bestRun;

    uint32_t elements;             // N actually scanned
    uint32_t arrayCount;           // Array<T>.size_ as read from memory
    uint32_t candidates;           // candidate strides scored
    uint32_t probeCount;
    char probeSummary[160];        // e.g. "FixedString@0x0,Guid@0x10"

    double noiseRate;              // measured p_hat over non-winning candidates
    double expectedFalseWins;      // candidates * p_hat^(N-1)
} StrideScanResult;

// ============================================================================
// API
// ============================================================================

/**
 * Derive probes for a dynamic-array property from its element layout.
 * Returns the number of probes written (0 = the element type carries no
 * discriminating field, so the stride is not checkable from data).
 */
int stride_scan_build_probes(const ComponentPropertyDef *prop,
                             StrideProbe *out, int maxProbes);

/**
 * Score candidate strides for an array whose elements start at `bufBase`.
 * `count` is the array's element count (Array<T>.size_).
 * Always fills `out` (verdict + reason). Returns false if it could not scan at
 * all (out->verdict is then INCONCLUSIVE with the reason).
 */
bool stride_scan_buffer(uintptr_t bufBase, uint32_t count,
                        uint32_t declaredStride,
                        const StrideProbe *probes, int probeCount,
                        StrideScanResult *out);

/**
 * Full check for one dynamic-array property of a live component: reads the
 * Array<T> header at componentPtr + prop->offset, derives probes from the
 * element layout, and scores. Always fills `out`.
 */
bool stride_scan_property(void *componentPtr, const ComponentPropertyDef *prop,
                          StrideScanResult *out);

/** Verdict name for logs/Lua ("PASS" / "FAIL" / "INCONCLUSIVE"). */
const char *stride_verdict_name(StrideVerdict v);

#ifdef __cplusplus
}
#endif

#endif /* BG3SE_STRIDE_SCAN_H */
