/*
 * Tier 0 tests for the dynamic-array stride DETECTOR (src/entity/stride_scan.c).
 *
 * WHAT IS UNDER TEST: not "does the declared stride match a table" (that is
 * tests/tier0/test_component_offsets.c, a consistency check that stays GREEN
 * when both sides are wrong — which is exactly how SpellData shipped at 88 when
 * the ARM64 stride is 0x68). Here the question is whether the detector can look
 * at DATA and say the declaration is wrong.
 *
 * A detector that has only ever been green is not evidence, so every scenario
 * below is driven from both sides: the same synthetic array is scanned once with
 * the WRONG declared stride (must FAIL, and must name the right one) and once
 * with the RIGHT one (must PASS).
 *
 * HONESTY OF THE SYNTHETIC DATA. The pitfall this detector exists to survive is
 * that FixedString resolution is noisy — during the live 0x68 investigation
 * ~7-8 of 12 reads at EVERY wrong candidate stride resolved to some real string
 * ("Version64", "RampIntensity_R", an animation path). So the fixtures here do
 * not use clean zero padding: element bodies are filled with a ~60% mix of
 * resolvable "decoy" indices, reproducing that measured noise floor, and the
 * arrays live inside a large mapped arena so reads past the end still succeed
 * (as they do in the game). The tests assert the measured noise rate lands in
 * that band, so a fixture that silently became easy is a visible failure.
 *
 * Offline / CI-safe: no game process. safe_memory_read* reads this test's own
 * heap; the string table is tests/tier0/stub_fixed_string.c.
 */

#include "test_harness.h"
#include "stub_fixed_string.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "stride_scan.h"          /* include dir: src/entity */
#include "component_property.h"
#include "component_offsets.h"
#include "../../src/lifetime/lifetime.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* ------------------------------------------------------------------ fixtures */

#define ARENA_BYTES     (96 * 1024)   /* > STRIDE_SCAN_MAX_ELEMENTS * MAX_STRIDE */
#define DECOY_COUNT     48
#define FS_DECOY_BASE   0x00A10000u   /* resolvable indices */
#define FS_JUNK_BASE    0x7F000000u   /* never in the table */

static char g_decoyNames[DECOY_COUNT][24];
static StubFixedStringEntry g_decoyTable[DECOY_COUNT];

static void install_decoy_table(void) {
    for (int i = 0; i < DECOY_COUNT; i++) {
        snprintf(g_decoyNames[i], sizeof(g_decoyNames[i]), "Target_Decoy%02d", i);
        g_decoyTable[i].index = FS_DECOY_BASE + (uint32_t)i * 16u;
        g_decoyTable[i].str = g_decoyNames[i];
    }
    stub_fixed_string_set_table(g_decoyTable, DECOY_COUNT);
}

/* Deterministic PRNG so a failure is reproducible and no seed was cherry-picked
 * per scenario (one seed, used by every fixture). Verified not seed-dependent:
 * all 13 scenarios pass at 0xC0FFEE, 0x11111111, 0xDEADBEEF, 0x2468ACE0, 0x7,
 * 0x5A5A5A5A, 0x31337 and 0xFACEB00C (swept 2026-07-26). The sweep is what
 * caught an over-specified assertion in the noise scenario: at 0x7 the arena's
 * element [0] itself failed the probe, so every candidate scored a run of 0. */
static uint32_t g_rng = 0x9E3779B9u;
static void rng_seed(uint32_t s) { g_rng = s ? s : 1u; }
static uint32_t rng_next(void) {
    uint32_t x = g_rng;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    g_rng = x;
    return x;
}

/* A word that resolves (decoy) with probability `pctResolvable`, else junk. */
static uint32_t noisy_word(int pctResolvable) {
    if ((int)(rng_next() % 100u) < pctResolvable) {
        return FS_DECOY_BASE + (rng_next() % DECOY_COUNT) * 16u;
    }
    return FS_JUNK_BASE + (rng_next() & 0xFFFFu);
}

/* Arena filled edge-to-edge with the noise mix, so every candidate stride reads
 * MAPPED memory that mostly looks plausible — the adversarial case. */
static uint8_t *make_noise_arena(int pctResolvable) {
    uint8_t *arena = (uint8_t *)malloc(ARENA_BYTES);
    for (size_t off = 0; off + 4 <= ARENA_BYTES; off += 4) {
        uint32_t w = noisy_word(pctResolvable);
        memcpy(arena + off, &w, sizeof(w));
    }
    return arena;
}

/* SpellData shape: a resolvable spell id at +0x00 of every element, element body
 * = the noise mix. This is the shipped bug's exact geometry. */
static uint8_t *make_spelldata_arena(uint32_t stride, uint32_t count) {
    uint8_t *arena = make_noise_arena(60);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t id = FS_DECOY_BASE + (i % DECOY_COUNT) * 16u;
        memcpy(arena + (size_t)i * stride, &id, sizeof(id));
    }
    return arena;
}

/* ClassInfo shape: Guid(16) + Guid(16) + int Level + pad, stride 40.
 * `holeAt` (>= 0) makes that one element fail a probe — real arrays contain
 * elements whose field is legitimately out of the probe's expected shape, and
 * that truncates EVERY candidate's run, including the correct stride's. */
static uint8_t *make_classinfo_arena_hole(uint32_t stride, uint32_t count, int holeAt) {
    uint8_t *arena = make_noise_arena(60);
    for (uint32_t i = 0; i < count; i++) {
        uint8_t *e = arena + (size_t)i * stride;
        for (int b = 0; b < 32; b++) e[b] = (uint8_t)(rng_next() & 0xFF);
        uint32_t level = ((int)i == holeAt) ? 0x7FFF0000u : (1u + (rng_next() % 12u));
        memcpy(e + 32, &level, sizeof(level));
        memset(e + 36, 0, 4);
    }
    return arena;
}

static uint8_t *make_classinfo_arena(uint32_t stride, uint32_t count) {
    return make_classinfo_arena_hole(stride, count, -1);
}

static const ComponentPropertyDef *spell_prop(uint16_t declaredStride) {
    static ComponentPropertyDef p;
    p = (ComponentPropertyDef){
        .name = "Spells", .offset = 0, .type = FIELD_TYPE_DYNAMIC_ARRAY,
        .readOnly = true, .elemType = ELEM_TYPE_SPELL_DATA, .elemSize = declaredStride,
    };
    return &p;
}

typedef struct { void *buf; uint32_t capacity; uint32_t size; } FakeArray;

/* ---------------------------------------------------------------- scenarios */

/* THE SHIPPED BUG, reproduced: SpellData declared 88 (Windows headers) over data
 * whose real stride is 0x68. The detector must FAIL and name 104. */
TEST(wrong_spelldata_stride_is_detected_and_0x68_suggested) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    const uint32_t TRUE_STRIDE = 0x68, COUNT = 40;
    uint8_t *arena = make_spelldata_arena(TRUE_STRIDE, COUNT);

    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(spell_prop(88), probes, STRIDE_SCAN_MAX_PROBES);
    ASSERT_EQ(np, 1);

    StrideScanResult r;
    stride_scan_buffer((uintptr_t)arena, COUNT, 88, probes, np, &r);

    ASSERT_EQ(r.verdict, STRIDE_VERDICT_FAIL);
    ASSERT_EQ(r.bestStride, TRUE_STRIDE);
    ASSERT_EQ(r.bestRun, r.elements);
    ASSERT_TRUE(r.declaredRun < r.elements);
    /* The fixture must actually be noisy — a clean fixture would prove nothing. */
    ASSERT_TRUE(r.noiseRate > 0.35 && r.noiseRate < 0.85);
    ASSERT_TRUE(r.expectedFalseWins <= STRIDE_SCAN_MAX_FALSE_WINS);

    free(arena);
}

/* Same data, correct declaration: PASS. Multiples of 104 (208, 312, ...) read
 * every k-th real element and tie at a full run by construction, so the winner
 * must be the SMALLEST full-run stride, not one of them. */
TEST(correct_spelldata_stride_passes_and_smallest_wins) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    const uint32_t TRUE_STRIDE = 0x68, COUNT = 40;
    uint8_t *arena = make_spelldata_arena(TRUE_STRIDE, COUNT);

    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(spell_prop(TRUE_STRIDE), probes, STRIDE_SCAN_MAX_PROBES);

    StrideScanResult r;
    stride_scan_buffer((uintptr_t)arena, COUNT, TRUE_STRIDE, probes, np, &r);

    ASSERT_EQ(r.verdict, STRIDE_VERDICT_PASS);
    ASSERT_EQ(r.declaredRun, r.elements);
    ASSERT_EQ(r.bestStride, TRUE_STRIDE);

    free(arena);
}

/* A second array shape, strong probe set (two Guids + a bounded Level): the same
 * mutation must be caught with far fewer elements than the FixedString case. */
TEST(wrong_classinfo_stride_is_detected) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    const uint32_t TRUE_STRIDE = 40, COUNT = 12;
    uint8_t *arena = make_classinfo_arena(TRUE_STRIDE, COUNT);

    static const ComponentPropertyDef prop = {
        .name = "Classes", .offset = 0, .type = FIELD_TYPE_DYNAMIC_ARRAY,
        .readOnly = true, .elemType = ELEM_TYPE_CLASS_INFO, .elemSize = 48,
    };
    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(&prop, probes, STRIDE_SCAN_MAX_PROBES);
    ASSERT_EQ(np, 3);

    StrideScanResult r;
    stride_scan_buffer((uintptr_t)arena, COUNT, 48, probes, np, &r);
    ASSERT_EQ(r.verdict, STRIDE_VERDICT_FAIL);
    ASSERT_EQ(r.bestStride, TRUE_STRIDE);

    /* ... and the correct declaration passes on the same bytes. */
    StrideScanResult ok;
    stride_scan_buffer((uintptr_t)arena, COUNT, TRUE_STRIDE, probes, np, &ok);
    ASSERT_EQ(ok.verdict, STRIDE_VERDICT_PASS);

    free(arena);
}

/* An element whose probe field is legitimately out of shape truncates every
 * candidate's run. The verdict is keyed to the RUN's significance, not to a
 * full sweep, so a strong probe set still concludes from the shortened run —
 * otherwise arrays with any such element would be permanently unjudgeable. */
TEST(truncated_run_still_concludes_with_strong_probes) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    const uint32_t TRUE_STRIDE = 40, COUNT = 12;
    uint8_t *arena = make_classinfo_arena_hole(TRUE_STRIDE, COUNT, 6);

    static const ComponentPropertyDef prop = {
        .name = "Classes", .offset = 0, .type = FIELD_TYPE_DYNAMIC_ARRAY,
        .readOnly = true, .elemType = ELEM_TYPE_CLASS_INFO, .elemSize = 48,
    };
    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(&prop, probes, STRIDE_SCAN_MAX_PROBES);

    StrideScanResult r;
    stride_scan_buffer((uintptr_t)arena, COUNT, 48, probes, np, &r);
    ASSERT_EQ(r.verdict, STRIDE_VERDICT_FAIL);
    ASSERT_EQ(r.bestStride, TRUE_STRIDE);
    ASSERT_EQ(r.bestRun, 6u);                 /* stops at the hole, as it must */
    ASSERT_TRUE(r.bestRun < r.elements);

    free(arena);
}

/* Structureless data must never produce a suggestion. This is the pitfall the
 * whole design turns on: plenty of individual reads resolve, so a hit-count
 * scorer would "find" a stride here. */
TEST(pure_noise_never_yields_a_fail) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    uint8_t *arena = make_noise_arena(60);   /* no element structure at all */

    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(spell_prop(88), probes, STRIDE_SCAN_MAX_PROBES);

    StrideScanResult r;
    stride_scan_buffer((uintptr_t)arena, 40, 88, probes, np, &r);

    /* Printed, not just asserted: this line IS the measured noise floor, and it
     * is what justifies the significance gate's threshold. */
    printf("      [noise floor] p=%.2f, longest chance run %u/%u at stride %u "
           "=> %.2f expected by chance (verdict %s)\n",
           r.noiseRate, r.bestRun, r.elements, r.bestStride,
           r.expectedFalseWins, stride_verdict_name(r.verdict));
    /* The only invariant that holds for ALL structureless data: never a verdict.
     * (How long the longest chance run happens to be is seed-dependent — the
     * printed line above shows it, and at p~0.6 it is regularly 8-10 elements,
     * which is exactly why a hit-count or short-run scorer would "find" a
     * stride here and this one must not.) */
    ASSERT_EQ(r.verdict, STRIDE_VERDICT_INCONCLUSIVE);
    ASSERT_TRUE(r.noiseRate > 0.35 && r.noiseRate < 0.85);

    free(arena);
}

/* A probe set that everything satisfies must NOT be reported as a PASS — a green
 * that means "every stride looks fine" is the false-green this project keeps
 * getting burned by. */
TEST(non_discriminating_probe_set_is_inconclusive_not_pass) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    uint8_t *arena = make_noise_arena(100);   /* every word resolves */

    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(spell_prop(0x68), probes, STRIDE_SCAN_MAX_PROBES);

    StrideScanResult r;
    stride_scan_buffer((uintptr_t)arena, 40, 0x68, probes, np, &r);

    ASSERT_EQ(r.verdict, STRIDE_VERDICT_INCONCLUSIVE);
    ASSERT_TRUE(r.noiseRate > 0.9);
    ASSERT_TRUE(strstr(r.reason, "noise floor") != NULL);

    free(arena);
}

/* Too few elements: element [0] sits at the base for EVERY candidate, so a
 * 1-2 element array proves nothing. It must say so, not pass. */
TEST(short_array_is_inconclusive_with_a_specific_reason) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    uint8_t *arena = make_spelldata_arena(0x68, 2);

    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(spell_prop(88), probes, STRIDE_SCAN_MAX_PROBES);

    StrideScanResult r;
    stride_scan_buffer((uintptr_t)arena, 2, 88, probes, np, &r);
    ASSERT_EQ(r.verdict, STRIDE_VERDICT_INCONCLUSIVE);
    ASSERT_TRUE(strstr(r.reason, "element") != NULL);

    free(arena);
}

/* elemSize == 0: 53 declarations in component_offsets.h look like this. The
 * reader refuses to index them, so they silently return count-only with nil
 * elements — that gap must be VISIBLE, not a pass. */
TEST(zero_elemsize_is_inconclusive) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    uint8_t *arena = make_spelldata_arena(0x68, 40);

    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    int np = stride_scan_build_probes(spell_prop(0), probes, STRIDE_SCAN_MAX_PROBES);

    StrideScanResult r;
    stride_scan_buffer((uintptr_t)arena, 40, 0, probes, np, &r);
    ASSERT_EQ(r.verdict, STRIDE_VERDICT_INCONCLUSIVE);
    ASSERT_TRUE(strstr(r.reason, "elemSize is 0") != NULL);

    free(arena);
}

/* An opaque element type yields no probes at all, and that must surface as an
 * explicit "not checkable", never as silence. */
TEST(opaque_element_type_yields_no_probes) {
    static const ComponentPropertyDef prop = {
        .name = "Data", .offset = 0, .type = FIELD_TYPE_DYNAMIC_ARRAY,
        .readOnly = true, .elemType = ELEM_TYPE_UNKNOWN, .elemSize = 16,
    };
    StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
    ASSERT_EQ(stride_scan_build_probes(&prop, probes, STRIDE_SCAN_MAX_PROBES), 0);

    StrideScanResult r;
    stride_scan_buffer(0x1000, 40, 16, probes, 0, &r);
    ASSERT_EQ(r.verdict, STRIDE_VERDICT_INCONCLUSIVE);
    ASSERT_TRUE(strstr(r.reason, "no discriminating field") != NULL);
}

TEST(scan_property_reads_the_array_header) {
    install_decoy_table();
    rng_seed(0xC0FFEE);
    const uint32_t TRUE_STRIDE = 0x68, COUNT = 40;
    uint8_t *arena = make_spelldata_arena(TRUE_STRIDE, COUNT);
    FakeArray arr = { .buf = arena, .capacity = COUNT, .size = COUNT };

    StrideScanResult r;
    stride_scan_property(&arr, spell_prop(88), &r);
    ASSERT_EQ(r.verdict, STRIDE_VERDICT_FAIL);
    ASSERT_EQ(r.bestStride, TRUE_STRIDE);
    ASSERT_EQ(r.arrayCount, COUNT);

    stride_scan_property(&arr, spell_prop(TRUE_STRIDE), &r);
    ASSERT_EQ(r.verdict, STRIDE_VERDICT_PASS);

    free(arena);
}


/* ------------------------------------------------------------------ census */

/* How much of the DECLARED population this detector can even attempt, measured
 * off component_offsets.h rather than estimated. An in-game run additionally
 * needs the array to be non-empty on a reachable entity, so this is the ceiling,
 * not the coverage. */
static int g_censusTotal, g_censusCheckable, g_censusNoProbe, g_censusZeroSize;
static int g_probeOutsideElement;

static void census_layout(const ComponentLayoutDef *layout, int depth) {
    if (!layout || depth > 4) return;
    for (int i = 0; i < layout->propertyCount; i++) {
        const ComponentPropertyDef *p = &layout->properties[i];
        if (p->type != FIELD_TYPE_DYNAMIC_ARRAY) continue;
        g_censusTotal++;

        StrideProbe probes[STRIDE_SCAN_MAX_PROBES];
        int np = stride_scan_build_probes(p, probes, STRIDE_SCAN_MAX_PROBES);
        if (p->elemSize == 0) {
            g_censusZeroSize++;
        } else if (np == 0) {
            g_censusNoProbe++;
        } else {
            g_censusCheckable++;
            /* A probe reaching past the declared element would read the NEXT
             * element's bytes and score the declaration in its own favour. */
            for (int k = 0; k < np; k++) {
                uint16_t end = probes[k].offset +
                               (probes[k].kind == STRIDE_PROBE_GUID ? 16 :
                                probes[k].kind == STRIDE_PROBE_POINTER ||
                                probes[k].kind == STRIDE_PROBE_ENTITY_HANDLE ? 8 : 4);
                if (end > p->elemSize) {
                    fprintf(stderr, "    probe past element end: %s.%s probe@0x%X ends 0x%X > "
                                    "elemSize 0x%X\n",
                            layout->shortName ? layout->shortName : layout->componentName,
                            p->name, probes[k].offset, end, p->elemSize);
                    g_probeOutsideElement++;
                }
            }
        }
    }
}

TEST(census_of_checkable_declared_arrays) {
    g_censusTotal = g_censusCheckable = g_censusNoProbe = g_censusZeroSize = 0;
    g_probeOutsideElement = 0;

    for (int i = 0; g_AllComponentLayouts[i] != NULL; i++)
        census_layout(g_AllComponentLayouts[i], 0);

    fprintf(stderr, "    %d declared dynamic array(s): %d checkable (have a probe and a "
                    "stride), %d opaque element type (no probe), %d elemSize==0\n",
            g_censusTotal, g_censusCheckable, g_censusNoProbe, g_censusZeroSize);

    /* A census that reaches nothing means the probe derivation is broken. */
    ASSERT_TRUE(g_censusTotal > 50);
    ASSERT_TRUE(g_censusCheckable > 10);  /* 14 of 53 on 4.1.1.7398727 layouts */
    ASSERT_EQ(g_probeOutsideElement, 0);
}

void register_stride_scan_tests(void) {
    printf("Dynamic-array stride detector:\n");
    RUN_TEST(wrong_spelldata_stride_is_detected_and_0x68_suggested);
    RUN_TEST(correct_spelldata_stride_passes_and_smallest_wins);
    RUN_TEST(wrong_classinfo_stride_is_detected);
    RUN_TEST(truncated_run_still_concludes_with_strong_probes);
    RUN_TEST(pure_noise_never_yields_a_fail);
    RUN_TEST(non_discriminating_probe_set_is_inconclusive_not_pass);
    RUN_TEST(short_array_is_inconclusive_with_a_specific_reason);
    RUN_TEST(zero_elemsize_is_inconclusive);
    RUN_TEST(opaque_element_type_yields_no_probes);
    RUN_TEST(scan_property_reads_the_array_header);
    RUN_TEST(census_of_checkable_declared_arrays);
    printf("\n");
}
