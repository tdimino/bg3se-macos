/*
 * BG3SE-macOS Tier 0 Test Runner
 * Minimal assert+printf framework. No external dependencies.
 */

#include "test_harness.h"

int g_passed = 0;
int g_failed = 0;
jmp_buf g_test_jmp;

void register_safe_memory_tests(void);
void register_pattern_scan_tests(void);
void register_osiris_handle_tests(void);
void register_entity_events_tests(void);
void register_mod_paths_tests(void);
void register_lua_runtime_tests(void);
void register_guid_lookup_tests(void);
void register_persistentvars_tests(void);
void register_json_proxy_tests(void);
void register_lua_json_tests(void);
void register_component_bounds_tests(void);
void register_arm64_prologue_tests(void);
void register_enum_ext_tests(void);
void register_osi_hook_abi_tests(void);
void register_staticdata_layout_tests(void);

int main(void) {
    printf("=== BG3SE Tier 0 Unit Tests ===\n\n");

    register_safe_memory_tests();
    register_pattern_scan_tests();
    register_osiris_handle_tests();
    register_entity_events_tests();
    register_mod_paths_tests();
    register_lua_runtime_tests();
    register_guid_lookup_tests();
    register_persistentvars_tests();
    register_json_proxy_tests();
    register_lua_json_tests();
    register_component_bounds_tests();
    register_arm64_prologue_tests();
    register_enum_ext_tests();
    register_osi_hook_abi_tests();
    register_staticdata_layout_tests();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           g_passed, g_passed + g_failed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
