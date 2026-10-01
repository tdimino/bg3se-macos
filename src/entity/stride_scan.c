/**
 * BG3SE-macOS - Dynamic-array stride DETECTOR (see stride_scan.h for the method
 * and for why a run — not a hit count — is the unit of evidence).
 */

#include "stride_scan.h"

#include "../core/safe_memory.h"
#include "../strings/fixed_string.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// Array<T> header, same as component_property.c
#define SS_ARRAY_BUF_OFFSET   0x00
#define SS_ARRAY_SIZE_OFFSET  0x0C

// ============================================================================
// Probe plausibility
// ============================================================================

static uint32_t rd_u32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint64_t rd_u64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint16_t probe_width(const StrideProbe *p) {
    switch ((StrideProbeKind)p->kind) {
        case STRIDE_PROBE_FIXEDSTRING:   return 4;
        case STRIDE_PROBE_GUID:          return 16;
        case STRIDE_PROBE_POINTER:       return 8;
        case STRIDE_PROBE_ENTITY_HANDLE: return 8;
        case STRIDE_PROBE_SMALL_INT:     return 4;
        case STRIDE_PROBE_BOOL:          return 1;
    }
    return 4;
}

static const char *probe_kind_name(uint8_t kind) {
    switch ((StrideProbeKind)kind) {
        case STRIDE_PROBE_FIXEDSTRING:   return "FixedString";
        case STRIDE_PROBE_GUID:          return "Guid";
        case STRIDE_PROBE_POINTER:       return "Ptr";
        case STRIDE_PROBE_ENTITY_HANDLE: return "EntityHandle";
        case STRIDE_PROBE_SMALL_INT:     return "SmallInt";
        case STRIDE_PROBE_BOOL:          return "Bool";
    }
    return "?";
}

/* A resolved FixedString only counts when it looks like an identifier. The
 * string table happily resolves ANY in-range integer, which is exactly how the
 * 0x68 investigation kept seeing "Version64" / "RampIntensity_R" at unrelated
 * offsets — so this is a filter on shape, and the RUN requirement upstream is
 * what actually rejects that noise. */
static bool plausible_fixedstring(uint32_t index) {
    if (index == 0) return false;
    const char *s = fixed_string_resolve(index);
    if (!s) return false;
    size_t n = strlen(s);
    if (n < 2 || n > 160) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}

/* Real GUIDs are byte-diverse. Misaligned reads that straddle pointers/ints are
 * dominated by 0x00 runs, which is what this rejects. */
static bool plausible_guid(const uint8_t *g) {
    uint32_t seen[8] = {0};
    int distinct = 0, zeros = 0, ffs = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t b = g[i];
        if (b == 0x00) zeros++;
        if (b == 0xFF) ffs++;
        if (!(seen[b >> 5] & (1u << (b & 31)))) {
            seen[b >> 5] |= (1u << (b & 31));
            distinct++;
        }
    }
    if (zeros == 16 || ffs == 16) return false;
    return distinct >= 8 && zeros <= 6;
}

static bool plausible_pointer(uint64_t v) {
    if (v == 0) return false;
    if (v & 7) return false;
    if (v < 0x100000000ull) return false;              /* below the image base */
    if (v >= 0x0000800000000000ull) return false;      /* non-canonical / tagged */
    if (safe_memory_is_gpu_region((mach_vm_address_t)v)) return false;
    uint8_t probe;
    return safe_memory_read((mach_vm_address_t)v, &probe, 1);
}

/* EntityHandle packs index(32) | salt(16) | type(16) — see guid_lookup.h. */
static bool plausible_entity_handle(uint64_t v) {
    if (v == 0) return false;
    uint32_t index = (uint32_t)(v & 0xFFFFFFFFu);
    uint16_t type  = (uint16_t)((v >> 48) & 0xFFFF);
    if (index == 0 || index > 0x02000000u) return false;
    return type <= 64;
}

static bool probe_plausible(const uint8_t *elem, size_t elemLen, const StrideProbe *p) {
    size_t end = (size_t)p->offset + probe_width(p);
    if (end > elemLen) return false;
    const uint8_t *at = elem + p->offset;

    switch ((StrideProbeKind)p->kind) {
        case STRIDE_PROBE_FIXEDSTRING:   return plausible_fixedstring(rd_u32(at));
        case STRIDE_PROBE_GUID:          return plausible_guid(at);
        case STRIDE_PROBE_POINTER:       return plausible_pointer(rd_u64(at));
        case STRIDE_PROBE_ENTITY_HANDLE: return plausible_entity_handle(rd_u64(at));
        case STRIDE_PROBE_SMALL_INT:     return rd_u32(at) <= p->param;
        case STRIDE_PROBE_BOOL:          return *at <= 1;
    }
    return false;
}

// ============================================================================
// Probe derivation from the element layout
// ============================================================================

static bool push_probe(StrideProbe *out, int maxProbes, int *n,
                       uint16_t offset, StrideProbeKind kind,
                       uint32_t param, const char *field) {
    if (*n >= maxProbes) return false;
    out[*n].offset = offset;
    out[*n].kind = (uint8_t)kind;
    out[*n].param = param;
    out[*n].field = field;
    (*n)++;
    return true;
}


int stride_scan_build_probes(const ComponentPropertyDef *prop,
                             StrideProbe *out, int maxProbes) {
    if (!prop || !out || maxProbes <= 0) return 0;
    int n = 0;

    switch (prop->elemType) {
        case ELEM_TYPE_SPELL_DATA:
            /* LIVE-MEASURED: a FixedString spell id sits at +0x00 of each element. */
            push_probe(out, maxProbes, &n, 0, STRIDE_PROBE_FIXEDSTRING, 0, "SpellId");
            break;

        case ELEM_TYPE_SPELL_META:
            /* ASSUMED (not verified): spell-ish structs in this engine start with a
             * FixedString prototype id. If the assumption is wrong the scan finds no
             * full run and reports INCONCLUSIVE rather than a suggestion. */
            push_probe(out, maxProbes, &n, 0, STRIDE_PROBE_FIXEDSTRING, 0, "SpellId?(assumed)");
            break;

        case ELEM_TYPE_CLASS_INFO:
            push_probe(out, maxProbes, &n, 0x00, STRIDE_PROBE_GUID, 0, "ClassUUID");
            push_probe(out, maxProbes, &n, 0x10, STRIDE_PROBE_GUID, 0, "SubClassUUID");
            push_probe(out, maxProbes, &n, 0x20, STRIDE_PROBE_SMALL_INT, 20, "Level");
            break;

        case ELEM_TYPE_BOOST_ENTRY:
            push_probe(out, maxProbes, &n, 0x00, STRIDE_PROBE_SMALL_INT, 255, "BoostType");
            push_probe(out, maxProbes, &n, 0x14, STRIDE_PROBE_SMALL_INT, 4096, "Boosts.size");
            break;

        case ELEM_TYPE_GUID:
            push_probe(out, maxProbes, &n, 0, STRIDE_PROBE_GUID, 0, "Guid");
            break;

        case ELEM_TYPE_FIXED_STRING:
            push_probe(out, maxProbes, &n, 0, STRIDE_PROBE_FIXEDSTRING, 0, "FixedString");
            break;

        case ELEM_TYPE_ENTITY_HANDLE:
            push_probe(out, maxProbes, &n, 0, STRIDE_PROBE_ENTITY_HANDLE, 0, "EntityHandle");
            break;

        case ELEM_TYPE_STATUS_INFO:
        case ELEM_TYPE_UNKNOWN:
        default:
            break;
    }
    return n;
}

static void summarize_probes(const StrideProbe *probes, int n, char *out, size_t cap) {
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < n; i++) {
        char one[64];
        int w = snprintf(one, sizeof(one), "%s%s@0x%X",
                         (i ? "," : ""), probe_kind_name(probes[i].kind), probes[i].offset);
        if (w < 0) break;
        if (used + (size_t)w + 1 >= cap) break;
        memcpy(out + used, one, (size_t)w + 1);
        used += (size_t)w;
    }
}

// ============================================================================
// Scan
// ============================================================================

const char *stride_verdict_name(StrideVerdict v) {
    switch (v) {
        case STRIDE_VERDICT_PASS:         return "PASS";
        case STRIDE_VERDICT_FAIL:         return "FAIL";
        case STRIDE_VERDICT_INCONCLUSIVE: return "INCONCLUSIVE";
    }
    return "?";
}

static void result_init(StrideScanResult *out) {
    memset(out, 0, sizeof(*out));
    out->verdict = STRIDE_VERDICT_INCONCLUSIVE;
}

static bool inconclusive(StrideScanResult *out, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static bool inconclusive(StrideScanResult *out, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out->reason, sizeof(out->reason), fmt, ap);
    va_end(ap);
    out->verdict = STRIDE_VERDICT_INCONCLUSIVE;
    return false;
}

bool stride_scan_buffer(uintptr_t bufBase, uint32_t count,
                        uint32_t declaredStride,
                        const StrideProbe *probes, int probeCount,
                        StrideScanResult *out) {
    if (!out) return false;
    result_init(out);
    out->declaredStride = declaredStride;
    out->arrayCount = count;
    out->probeCount = (uint32_t)(probeCount < 0 ? 0 : probeCount);
    if (probes && probeCount > 0) {
        summarize_probes(probes, probeCount, out->probeSummary, sizeof(out->probeSummary));
    }

    if (!probes || probeCount <= 0) {
        return inconclusive(out, "element layout has no discriminating field "
                                 "(opaque element type) — stride not checkable from data");
    }
    if (declaredStride == 0) {
        return inconclusive(out, "declared elemSize is 0 — the reader refuses to index "
                                 "this array, so there is no stride to check");
    }
    if (bufBase == 0) {
        return inconclusive(out, "array buffer pointer is NULL");
    }
    if (count < STRIDE_SCAN_MIN_ELEMENTS) {
        return inconclusive(out, "array holds %u element(s); a stride is only visible "
                                 "with >= %d (element [0] sits at the base for EVERY stride)",
                            count, STRIDE_SCAN_MIN_ELEMENTS);
    }

    uint32_t N = count;
    if (N > STRIDE_SCAN_MAX_ELEMENTS) N = STRIDE_SCAN_MAX_ELEMENTS;
    out->elements = N;

    /* Element window: only as many bytes as the probes actually need. */
    size_t window = 0;
    for (int i = 0; i < probeCount; i++) {
        size_t end = (size_t)probes[i].offset + probe_width(&probes[i]);
        if (end > window) window = end;
    }
    if (window == 0 || window > STRIDE_SCAN_ELEM_WINDOW) {
        return inconclusive(out, "probe extent %zu bytes is outside the scan window", window);
    }

    /* Candidate strides: the 4-byte grid, plus the declared value if off-grid. */
    uint32_t cands[STRIDE_SCAN_MAX_STRIDE / STRIDE_SCAN_STRIDE_STEP + 2];
    uint32_t nc = 0;
    for (uint32_t s = STRIDE_SCAN_MIN_STRIDE; s <= STRIDE_SCAN_MAX_STRIDE; s += STRIDE_SCAN_STRIDE_STEP) {
        cands[nc++] = s;
    }
    if (declaredStride % STRIDE_SCAN_STRIDE_STEP != 0 || declaredStride > STRIDE_SCAN_MAX_STRIDE) {
        cands[nc++] = declaredStride;
    }
    out->candidates = nc;

    uint32_t runs[STRIDE_SCAN_MAX_STRIDE / STRIDE_SCAN_STRIDE_STEP + 2];
    uint32_t hits[STRIDE_SCAN_MAX_STRIDE / STRIDE_SCAN_STRIDE_STEP + 2];

    uint8_t elem[STRIDE_SCAN_ELEM_WINDOW];
    for (uint32_t c = 0; c < nc; c++) {
        uint32_t s = cands[c];
        uint32_t run = 0;
        uint32_t hit = 0;
        bool runOpen = true;
        for (uint32_t i = 0; i < N; i++) {
            bool coherent = false;
            if (safe_memory_read((mach_vm_address_t)(bufBase + (uintptr_t)i * s), elem, window)) {
                coherent = true;
                for (int p = 0; p < probeCount && coherent; p++) {
                    if (!probe_plausible(elem, window, &probes[p])) coherent = false;
                }
            }
            if (coherent) {
                if (i >= 1) hit++;
                if (runOpen) run++;
            } else {
                runOpen = false;
            }
        }
        runs[c] = run;
        hits[c] = hit;
    }

    uint32_t bestRun = 0, bestStride = 0, declaredRun = 0;
    for (uint32_t c = 0; c < nc; c++) {
        if (runs[c] > bestRun) { bestRun = runs[c]; bestStride = cands[c]; }
        if (cands[c] == declaredStride) declaredRun = runs[c];
    }
    out->bestRun = bestRun;
    out->bestStride = bestStride;
    out->declaredRun = declaredRun;

    /* Measured noise floor: coherence rate of this probe set ON THIS DATA at
     * every stride except the winner. Multiples of the winner are deliberately
     * NOT excluded: they contribute a handful of genuinely-coherent pairs out of
     * ~128 candidates (immaterial), whereas excluding them lets a degenerate
     * winner (e.g. 4, of which every candidate is a multiple) empty the sample
     * and manufacture p=0 — a false green in exactly the shape of good news. */
    uint64_t noiseHits = 0, noisePairs = 0;
    for (uint32_t c = 0; c < nc; c++) {
        if (cands[c] == bestStride) continue;
        noiseHits += hits[c];
        noisePairs += (N - 1);
    }
    /* No sample => no measurement => cannot conclude (p=1 forces INCONCLUSIVE). */
    double p = (noisePairs > 0) ? (double)noiseHits / (double)noisePairs : 1.0;
    out->noiseRate = p;
    /* The evidence is a run of length bestRun. Under the measured noise floor a
     * given candidate reaches it with probability ~p^(bestRun-1) (element 0 is
     * free), so this is the expected number of candidates that get there by
     * chance. It is deliberately keyed to the RUN, not to N: a real array whose
     * element [7] legitimately holds an empty field truncates every candidate's
     * run, and demanding a full sweep would turn that into a permanent
     * "cannot judge" instead of the weaker-but-real evidence it is. */
    out->expectedFalseWins = (bestRun >= 1)
        ? (double)nc * pow(p, (double)(bestRun - 1))
        : (double)nc;

    if (bestRun < STRIDE_SCAN_MIN_RUN) {
        return inconclusive(out,
            "best run is only %u element(s) at stride %u/0x%X over %u scanned; element [0] sits at "
            "the base for EVERY stride, so a run under %d is not evidence (probes: %s)",
            bestRun, bestStride, bestStride, N, STRIDE_SCAN_MIN_RUN, out->probeSummary);
    }
    if (out->expectedFalseWins > STRIDE_SCAN_MAX_FALSE_WINS) {
        return inconclusive(out,
            "best run %u/%u at stride %u/0x%X is not distinguishable from the measured noise floor "
            "(p=%.2f over %u candidates => %.3f expected by chance, need <= %.2f); more elements or "
            "a stronger probe set than %s required",
            bestRun, N, bestStride, bestStride, p, nc, out->expectedFalseWins,
            STRIDE_SCAN_MAX_FALSE_WINS, out->probeSummary);
    }

    if (declaredRun == bestRun) {
        out->verdict = STRIDE_VERDICT_PASS;
        snprintf(out->reason, sizeof(out->reason),
                 "declared stride %u/0x%X reads %u/%u elements coherently (probes: %s, noise p=%.2f)",
                 declaredStride, declaredStride, declaredRun, N, out->probeSummary, p);
        return true;
    }

    out->verdict = STRIDE_VERDICT_FAIL;
    snprintf(out->reason, sizeof(out->reason),
             "declared stride %u/0x%X reads only %u/%u elements coherently, but %u/0x%X reads %u/%u "
             "(probes: %s, noise p=%.2f, expected false wins %.4f)",
             declaredStride, declaredStride, declaredRun, N,
             bestStride, bestStride, bestRun, N, out->probeSummary, p, out->expectedFalseWins);
    return true;
}

bool stride_scan_property(void *componentPtr, const ComponentPropertyDef *prop,
                          StrideScanResult *out) {
    if (!out) return false;
    result_init(out);
    if (!componentPtr || !prop) {
        return inconclusive(out, "no component pointer or property definition");
    }
    if (prop->type != FIELD_TYPE_DYNAMIC_ARRAY) {
        return inconclusive(out, "property '%s' is not a dynamic array",
                            prop->name ? prop->name : "?");
    }

    uintptr_t arrayAddr = (uintptr_t)componentPtr + prop->offset;
    void *buf = NULL;
    uint32_t count = 0;
    if (!safe_memory_read((mach_vm_address_t)(arrayAddr + SS_ARRAY_BUF_OFFSET), &buf, sizeof(buf))) {
        return inconclusive(out, "Array<T> header at 0x%llx is unreadable",
                            (unsigned long long)arrayAddr);
    }
    if (!safe_memory_read_u32((mach_vm_address_t)(arrayAddr + SS_ARRAY_SIZE_OFFSET), &count)) {
        return inconclusive(out, "Array<T>.size_ at 0x%llx is unreadable",
                            (unsigned long long)(arrayAddr + SS_ARRAY_SIZE_OFFSET));
    }

    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(prop, probes, STRIDE_SCAN_MAX_PROBES);

    return stride_scan_buffer((uintptr_t)buf, count, prop->elemSize, probes, np, out);
}
