cmake_minimum_required(VERSION 3.20)
project(bg3se-macos VERSION 0.1.0 LANGUAGES C CXX OBJC OBJCXX)

# Set C/C++ standards
# Using C23 for __VA_OPT__ support in variadic macros (logging.h)
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build for both architectures (universal binary)
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")

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
)

add_library(bg3se SHARED
    src/injector/main.c
    src/core/logging.c
    src/core/safe_memory.c
    src/lua/lua_ext.c
    src/lua/lua_ide_helpers.c
    src/lua/lua_json.c
    src/lua/lua_context.c
    src/lua/lua_osiris.c
    src/lua/lua_stats.c
    src/lua/lua_debug.c
    src/lua/lua_logging.c
    src/mod/mod_loader.c
    src/osiris/pattern_scan.c
    src/osiris/osiris_functions.c
    src/osiris/custom_functions.c
    src/pak/pak_reader.c
    src/entity/entity_system.c
    src/entity/guid_lookup.c
    src/entity/arm64_call.c
    src/entity/component_registry.c
    src/entity/generated_component_registry.c
    src/entity/component_lookup.c
    src/entity/component_typeid.c
    src/entity/component_property.c
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
    src/input/input_hooks.m
    src/input/lua_input.c
    src/math/math_ext.c
    src/math/lua_math.c
    src/overlay/overlay.m
    src/vars/user_variables.c
    src/lifetime/lifetime.c
    src/localization/localization.c
    src/lua/lua_localization.c
    src/staticdata/staticdata_manager.c
    src/lua/lua_staticdata.c
    src/template/template_manager.c
    src/lua/lua_template.c
    src/resource/resource_manager.c
    src/lua/lua_resource.c
    src/lua/lua_imgui.c
    src/hooks/arm64_decode.c
    src/hooks/arm64_hook.c
    src/io/path_override.c
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
    ${CMAKE_SOURCE_DIR}/lib/Dobby/libdobby-universal.a
    ${CMAKE_SOURCE_DIR}/lib/lua/liblua-universal.a
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
