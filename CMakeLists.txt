cmake_minimum_required(VERSION 3.20)
# ============================================
# SDK Detection (fixes 'tuple' not found on CommandLineTools-only systems)
# Must precede project(): once the languages are enabled CMAKE_OSX_SYSROOT is
# a cache entry and a later non-FORCE set() would be ignored.
# ============================================
if(NOT CMAKE_OSX_SYSROOT)
    execute_process(
        COMMAND xcrun --sdk macosx --show-sdk-path
        OUTPUT_VARIABLE _detected_sdk
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE _xcrun_rc
    )
    if(_xcrun_rc EQUAL 0 AND _detected_sdk)
        set(CMAKE_OSX_SYSROOT "${_detected_sdk}" CACHE PATH "macOS SDK path (auto-detected)" FORCE)
        message(STATUS "Auto-detected macOS SDK: ${_detected_sdk}")
    else()
        # Fallback: probe the standard CommandLineTools path
        file(GLOB _clt_sdks "/Library/Developer/CommandLineTools/SDKs/MacOSX*.sdk")
        if(_clt_sdks)
            list(SORT _clt_sdks)
            list(GET _clt_sdks -1 _clt_latest)
            set(CMAKE_OSX_SYSROOT "${_clt_latest}" CACHE PATH "macOS SDK path (CommandLineTools fallback)" FORCE)
            message(STATUS "Using CommandLineTools SDK: ${_clt_latest}")
        else()
            message(WARNING
                "Could not detect macOS SDK. Install Xcode or CommandLineTools:\n"
                "  xcode-select --install\n"
                "Build may fail with 'tuple file not found' or similar C++ header errors.\n"
                "You can set CMAKE_OSX_SYSROOT manually: cmake -DCMAKE_OSX_SYSROOT=/path/to/sdk ..")
        endif()
    endif()
endif()

project(bg3se-macos VERSION 0.1.0 LANGUAGES C CXX OBJC OBJCXX)

# Set C/C++/Objective-C++ standards
# Using C23 for __VA_OPT__ support in variadic macros (logging.h)
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_OBJCXX_STANDARD 20)
set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)

# Build for both architectures (universal binary)
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")

# ============================================
# Toolchain probe (#77, #88)
# ============================================
# The Metal/ImGui backend is Objective-C++ and the SDK's simd headers include
# <tuple>. On CommandLineTools-only machines a mismatched sysroot surfaces as
# "fatal error: 'tuple' file not found" at ~57% of the build. Compile the same
# include chain at configure time and fail here with the facts needed to fix it.
option(BG3SE_SKIP_TOOLCHAIN_PROBE "Skip the configure-time Objective-C++ toolchain probe" OFF)
if(NOT BG3SE_SKIP_TOOLCHAIN_PROBE)
    include(CheckSourceCompiles)
    # Re-run on every configure: a cached pass must not outlive an Xcode change.
    unset(BG3SE_OBJCXX_TOOLCHAIN_OK CACHE)
    check_source_compiles(OBJCXX "
#include <tuple>
#import <MetalKit/MetalKit.h>
int main() { std::tuple<int, MTKView *> probe{0, nil}; return std::get<0>(probe); }
" BG3SE_OBJCXX_TOOLCHAIN_OK)

    if(NOT BG3SE_OBJCXX_TOOLCHAIN_OK)
        execute_process(COMMAND xcode-select -p
            OUTPUT_VARIABLE _probe_developer_dir OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET RESULT_VARIABLE _probe_xcs_rc)
        if(NOT _probe_xcs_rc EQUAL 0)
            set(_probe_developer_dir "<xcode-select -p failed: rc ${_probe_xcs_rc}>")
        endif()
        execute_process(COMMAND xcrun --sdk macosx --show-sdk-path
            OUTPUT_VARIABLE _probe_xcrun_sdk OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET RESULT_VARIABLE _probe_xcrun_rc)
        if(NOT _probe_xcrun_rc EQUAL 0)
            set(_probe_xcrun_sdk "<xcrun --show-sdk-path failed: rc ${_probe_xcrun_rc}>")
        endif()

        # Where libc++'s <tuple> actually lives on this machine, if anywhere.
        set(_probe_tuple_candidates
            "${CMAKE_OSX_SYSROOT}/usr/include/c++/v1/tuple"
            "${_probe_developer_dir}/usr/include/c++/v1/tuple"
            "${_probe_developer_dir}/Toolchains/XcodeDefault.xctoolchain/usr/include/c++/v1/tuple")
        set(_probe_tuple_found "none of the expected locations")
        foreach(_candidate IN LISTS _probe_tuple_candidates)
            if(EXISTS "${_candidate}")
                set(_probe_tuple_found "${_candidate}")
                break()
            endif()
        endforeach()

        message(FATAL_ERROR
            "\n"
            "The Objective-C++ toolchain cannot compile <tuple> + <MetalKit/MetalKit.h>,\n"
            "so the build would fail on src/imgui/imgui_metal_backend.mm (issues #77, #88).\n"
            "Details are in ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeConfigureLog.yaml.\n"
            "\n"
            "  xcode-select -p         : ${_probe_developer_dir}\n"
            "  xcrun --show-sdk-path   : ${_probe_xcrun_sdk}\n"
            "  CMAKE_OSX_SYSROOT       : ${CMAKE_OSX_SYSROOT}\n"
            "  CMAKE_OBJCXX_COMPILER   : ${CMAKE_OBJCXX_COMPILER} (${CMAKE_OBJCXX_COMPILER_VERSION})\n"
            "  libc++ <tuple> found at : ${_probe_tuple_found}\n"
            "\n"
            "Fixes, in order of likelihood:\n"
            "  1. Point the build at the SDK xcrun reports:\n"
            "       rm -rf build && cmake -B build -DCMAKE_OSX_SYSROOT=\"$(xcrun --sdk macosx --show-sdk-path)\"\n"
            "  2. Repair the developer directory:\n"
            "       sudo xcode-select -s /Library/Developer/CommandLineTools   (CLT-only)\n"
            "       sudo xcode-select -s /Applications/Xcode.app/Contents/Developer   (Xcode)\n"
            "  3. Reinstall the tools: xcode-select --install, or install Xcode from the App Store.\n"
            "Run `PYTHONPATH=tools python3 -m bg3se_harness doctor` for the same checks as JSON.\n"
            "Pass -DBG3SE_SKIP_TOOLCHAIN_PROBE=ON to bypass this probe.\n")
    endif()
endif()

# Output directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ============================================
# Submodule check - fail early with clear message
# ============================================
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/lib/Dobby/CMakeLists.txt")
    message(FATAL_ERROR
        "\n"
        "========================================\n"
        "ERROR: Dobby submodule not initialized!\n"
        "========================================\n"
        "\n"
        "It looks like you cloned without --recursive.\n"
        "\n"
        "Run this command to fix:\n"
        "    git submodule update --init --recursive\n"
        "\n"
        "Then re-run cmake.\n"
    )
endif()

# ============================================
# Dobby (inline hooking framework) - built from source
# ============================================
set(DOBBY_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(DOBBY_DEBUG OFF CACHE BOOL "" FORCE)
add_subdirectory(lib/Dobby)

# ============================================
# Lua 5.4 - built from source
# ============================================
set(LUA_SRC_DIR ${CMAKE_SOURCE_DIR}/lib/lua/src)
set(LUA_CORE_SOURCES
    ${LUA_SRC_DIR}/lapi.c ${LUA_SRC_DIR}/lcode.c ${LUA_SRC_DIR}/lctype.c
    ${LUA_SRC_DIR}/ldebug.c ${LUA_SRC_DIR}/ldo.c ${LUA_SRC_DIR}/ldump.c
    ${LUA_SRC_DIR}/lfunc.c ${LUA_SRC_DIR}/lgc.c ${LUA_SRC_DIR}/llex.c
    ${LUA_SRC_DIR}/lmem.c ${LUA_SRC_DIR}/lobject.c ${LUA_SRC_DIR}/lopcodes.c
    ${LUA_SRC_DIR}/lparser.c ${LUA_SRC_DIR}/lstate.c ${LUA_SRC_DIR}/lstring.c
    ${LUA_SRC_DIR}/ltable.c ${LUA_SRC_DIR}/ltm.c ${LUA_SRC_DIR}/lundump.c
    ${LUA_SRC_DIR}/lvm.c ${LUA_SRC_DIR}/lzio.c
)
set(LUA_LIB_SOURCES
    ${LUA_SRC_DIR}/lauxlib.c ${LUA_SRC_DIR}/lbaselib.c ${LUA_SRC_DIR}/lcorolib.c
    ${LUA_SRC_DIR}/ldblib.c ${LUA_SRC_DIR}/liolib.c ${LUA_SRC_DIR}/lmathlib.c
    ${LUA_SRC_DIR}/loadlib.c ${LUA_SRC_DIR}/loslib.c ${LUA_SRC_DIR}/lstrlib.c
    ${LUA_SRC_DIR}/ltablib.c ${LUA_SRC_DIR}/lutf8lib.c ${LUA_SRC_DIR}/linit.c
)
add_library(lua_static STATIC ${LUA_CORE_SOURCES} ${LUA_LIB_SOURCES})
target_include_directories(lua_static PUBLIC ${LUA_SRC_DIR})
target_compile_definitions(lua_static PRIVATE LUA_USE_MACOSX)
target_compile_options(lua_static PRIVATE -O2 -Wall)
set_target_properties(lua_static PROPERTIES OUTPUT_NAME "lua")

# ============================================
# Main injection dylib
# ============================================

# ImGui library
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/lib/imgui)

# Include paths
include_directories(
    ${CMAKE_SOURCE_DIR}/lib
    ${CMAKE_SOURCE_DIR}/lib/Dobby/include
    ${CMAKE_SOURCE_DIR}/lib/lua/src
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${CMAKE_SOURCE_DIR}/src/console
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/entity
    ${CMAKE_SOURCE_DIR}/src/enum
    ${CMAKE_SOURCE_DIR}/src/game
    ${CMAKE_SOURCE_DIR}/src/input
    ${CMAKE_SOURCE_DIR}/src/lua
    ${CMAKE_SOURCE_DIR}/src/math
    ${CMAKE_SOURCE_DIR}/src/mod
    ${CMAKE_SOURCE_DIR}/src/osiris
    ${CMAKE_SOURCE_DIR}/src/overlay
    ${CMAKE_SOURCE_DIR}/src/pak
    ${CMAKE_SOURCE_DIR}/src/stats
    ${CMAKE_SOURCE_DIR}/src/resource
    ${CMAKE_SOURCE_DIR}/src/staticdata
    ${CMAKE_SOURCE_DIR}/src/strings
    ${CMAKE_SOURCE_DIR}/src/template
    ${CMAKE_SOURCE_DIR}/src/timer
    ${CMAKE_SOURCE_DIR}/src/vars
    ${CMAKE_SOURCE_DIR}/src/lifetime
    ${CMAKE_SOURCE_DIR}/src/localization
    ${CMAKE_SOURCE_DIR}/src/hooks
    ${CMAKE_SOURCE_DIR}/src/io
    ${CMAKE_SOURCE_DIR}/src/imgui
    ${CMAKE_SOURCE_DIR}/src/network
    ${CMAKE_SOURCE_DIR}/src/level
    ${CMAKE_SOURCE_DIR}/src/audio
    ${CMAKE_SOURCE_DIR}/src/core/mach_exc_stubs
)

add_library(bg3se SHARED
    src/injector/main.c
    src/core/logging.c
    src/core/safe_memory.c
    src/core/crashlog.c
    src/core/version_detect.c
    src/core/offset_table.c
    src/core/mach_exception.c
    src/core/mach_exc_stubs/mach_excServer.c
    src/lua/lua_gate.c
    src/lua/lua_runtime.c
    src/lua/lua_ext.c
    src/lua/lua_ide_helpers.c
    src/lua/lua_json.c
    src/lua/lua_context.c
    src/lua/lua_osiris.c
    src/lua/lua_stats.c
    src/lua/lua_debug.c
    src/lua/lua_logging.c
    src/mod/mod_loader.c
    src/mod/mod_paths.c
    src/osiris/pattern_scan.c
    src/osiris/osiris_functions.c
    src/osiris/custom_functions.c
    src/pak/pak_reader.c
    src/entity/entity_system.c
    src/entity/replication_flags.h
    src/entity/replication_flags.c
    src/entity/guid_lookup.c
    src/entity/arm64_call.c
    src/entity/component_registry.c
    src/entity/generated_component_registry.c
    src/entity/component_lookup.c
    src/entity/component_typeid.c
    src/entity/component_property.c
    src/entity/entity_events.c
    src/entity/ecs_system_update.h
    src/entity/ecs_system_update.c
    src/entity/entity_tracing.h
    src/entity/entity_tracing.c
    src/stats/stats_manager.c
    src/stats/prototype_managers.c
    src/stats/functor_hooks.c
    src/strings/fixed_string.c
    src/console/console.c
    src/timer/timer.c
    src/enum/enum_registry.c
    src/enum/enum_lua.c
    src/enum/bitfield_lua.c
    src/enum/enum_ext.c
    src/enum/enum_definitions.c
    src/lua/lua_timer.c
    src/lua/lua_persistentvars.c
    src/lua/lua_events.c
    src/game/game_state.c
    src/game/global_switches.c
    src/game/savegame_hook.h
    src/game/savegame_hook.c
    src/game/video_skip.c
    src/game/focus_hack.c
    src/input/input_hooks.m
    src/input/focusless_input.m
    src/input/lua_input.c
    src/math/math_ext.c
    src/math/lua_math.c
    src/overlay/overlay.m
    src/vars/user_variables.c
    src/lifetime/lifetime.c
    src/localization/localization.c
    src/lua/lua_localization.c
    src/lua/lua_ui.c
    src/staticdata/staticdata_manager.c
    src/staticdata/staticdata_layouts.c
    src/lua/lua_staticdata.c
    src/template/template_manager.c
    src/lua/lua_template.c
    src/resource/resource_manager.c
    src/lua/lua_resource.c
    src/lua/lua_imgui.c
    src/lua/lua_mod.c
    src/lua/lua_net.c
    src/network/message_bus.c
    src/network/callback_registry.c
    src/network/network_backend.c
    src/network/peer_manager.c
    src/network/extender_protocol.c
    src/network/extender_message.c
    src/network/net_hooks.c
    src/hooks/arm64_decode.c
    src/hooks/arm64_hook.c
    src/io/path_override.c
    src/level/level_manager.c
    src/lua/lua_level.c
    src/audio/audio_manager.c
    src/lua/lua_audio.c
    lib/lz4/lz4.c
    # ImGui core
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    # ImGui backends
    ${IMGUI_DIR}/backends/imgui_impl_metal.mm
    ${IMGUI_DIR}/backends/imgui_impl_osx.mm
    # ImGui Metal backend (our wrapper)
    src/imgui/imgui_metal_backend.mm
    src/imgui/imgui_input_hooks.mm
    src/imgui/imgui_objects.c
)

target_compile_options(bg3se PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -fvisibility=hidden
)

# Link against required frameworks and libraries
target_link_libraries(bg3se PRIVATE
    "-framework Foundation"
    "-framework CoreFoundation"
    "-framework AppKit"
    "-framework QuartzCore"
    "-framework Metal"
    "-framework MetalKit"
    "-framework GameController"
    dobby_static
    lua_static
    z  # zlib for compression
)

# Set dylib properties
set_target_properties(bg3se PROPERTIES
    OUTPUT_NAME "bg3se"
    SUFFIX ".dylib"
    # Allow undefined symbols (we'll resolve them at runtime)
    LINK_FLAGS "-undefined dynamic_lookup"
)

# ============================================
# Console client tool
# ============================================

# Find readline (usually at /usr/local/opt/readline on macOS with Homebrew)
find_library(READLINE_LIBRARY readline PATHS /usr/local/opt/readline/lib /opt/homebrew/opt/readline/lib)
find_path(READLINE_INCLUDE_DIR readline/readline.h PATHS /usr/local/opt/readline/include /opt/homebrew/opt/readline/include)

if(READLINE_LIBRARY AND READLINE_INCLUDE_DIR)
    add_executable(bg3se-console tools/bg3se-console.c)
    target_include_directories(bg3se-console PRIVATE ${READLINE_INCLUDE_DIR})
    target_link_libraries(bg3se-console PRIVATE ${READLINE_LIBRARY})
    target_compile_options(bg3se-console PRIVATE -Wall -Wextra)
    # Console client is native arch only (not universal)
    set_target_properties(bg3se-console PROPERTIES
        OSX_ARCHITECTURES "${CMAKE_HOST_SYSTEM_PROCESSOR}"
    )
    message(STATUS "Building bg3se-console with readline from ${READLINE_LIBRARY}")
else()
    message(WARNING "readline not found - bg3se-console will not be built")
    message(STATUS "Install with: brew install readline")
endif()

# ============================================
# Installation
# ============================================
install(TARGETS bg3se
    LIBRARY DESTINATION lib
)

# Install launch script
install(PROGRAMS scripts/launch_bg3.sh
    DESTINATION bin
)

# ============================================
# Custom targets
# ============================================

# Quick build target
add_custom_target(quick
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target bg3se
    COMMENT "Building bg3se.dylib..."
)

# Test injection target (run after building)
add_custom_target(test-inject
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/launch_bg3.sh
    DEPENDS bg3se
    COMMENT "Testing injection..."
)

# Print info about the built dylib and auto-deploy to Steam
add_custom_command(TARGET bg3se POST_BUILD
    COMMAND echo "Built: ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libbg3se.dylib"
    COMMAND file ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libbg3se.dylib
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/deploy.sh
)

# ============================================
# Optional: ImGui standalone test tool
# ============================================
option(BUILD_IMGUI_TEST "Build standalone ImGui test application" ON)
if(BUILD_IMGUI_TEST)
    add_subdirectory(tools/imgui_test)
endif()

# ============================================
# Tier 0: Native C unit tests (no game dependency)
# ============================================
option(BUILD_TESTS "Build Tier 0 unit test binary" ON)
if(BUILD_TESTS)
    add_executable(bg3se_test_tier0
        tests/tier0/test_main.c
        tests/tier0/test_safe_memory.c
        tests/tier0/test_pattern_scan.c
        tests/tier0/test_osiris_handles.c
        tests/tier0/test_entity_events.c
        tests/tier0/test_mod_paths.c
        tests/tier0/test_lua_runtime.c
        tests/tier0/test_guid_lookup.c
        tests/tier0/test_persistentvars.c
        tests/tier0/test_json_proxies.c
        tests/tier0/test_lua_json.c
        tests/tier0/test_arm64_prologue.c
        tests/tier0/test_enum_ext.c
        tests/tier0/test_osi_hook_abi.c
        tests/tier0/test_staticdata_layouts.c
        tests/tier0/stub_logging.c
        src/core/safe_memory.c
        src/entity/guid_lookup.c
        src/osiris/pattern_scan.c
        src/mod/mod_paths.c
        src/lua/lua_runtime.c
        src/lua/lua_context.c
        src/lua/lua_persistentvars.c
        src/lua/lua_json.c
        src/hooks/arm64_decode.c
        src/hooks/arm64_hook.c
        src/enum/enum_registry.c
        src/enum/enum_definitions.c
        src/enum/enum_lua.c
        src/enum/bitfield_lua.c
        src/enum/enum_ext.c
        src/staticdata/staticdata_layouts.c
    )
    target_include_directories(bg3se_test_tier0 PRIVATE
        ${CMAKE_SOURCE_DIR}/tests/tier0
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/osiris
        ${CMAKE_SOURCE_DIR}/src/entity
        ${CMAKE_SOURCE_DIR}/src/mod
        ${CMAKE_SOURCE_DIR}/src/lua
        ${CMAKE_SOURCE_DIR}/src/hooks
        ${CMAKE_SOURCE_DIR}/src/enum
        ${CMAKE_SOURCE_DIR}/src/staticdata
        ${LUA_SRC_DIR}
    )
    target_link_libraries(bg3se_test_tier0 PRIVATE lua_static "-framework Foundation")
    set_target_properties(bg3se_test_tier0 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        OSX_ARCHITECTURES "${CMAKE_HOST_SYSTEM_PROCESSOR}"
    )
endif()
