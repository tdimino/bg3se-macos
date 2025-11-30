cmake_minimum_required(VERSION 3.20)
project(bg3se-macos VERSION 0.1.0 LANGUAGES C CXX OBJC)

# Set C/C++ standards
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build for both architectures (universal binary)
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")

# Output directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ============================================
# Main injection dylib
# ============================================

# Include paths
include_directories(
    ${CMAKE_SOURCE_DIR}/lib
    ${CMAKE_SOURCE_DIR}/lib/Dobby/include
    ${CMAKE_SOURCE_DIR}/lib/lua/src
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/entity
    ${CMAKE_SOURCE_DIR}/src/lua
    ${CMAKE_SOURCE_DIR}/src/mod
    ${CMAKE_SOURCE_DIR}/src/osiris
    ${CMAKE_SOURCE_DIR}/src/pak
)

add_library(bg3se SHARED
    src/injector/main.c
    src/core/logging.c
    src/lua/lua_ext.c
    src/lua/lua_json.c
    src/lua/lua_osiris.c
    src/mod/mod_loader.c
    src/osiris/pattern_scan.c
    src/osiris/osiris_functions.c
    src/pak/pak_reader.c
    src/entity/entity_system.c
    src/entity/guid_lookup.c
    src/entity/arm64_call.c
    lib/lz4/lz4.c
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

# Print info about the built dylib
add_custom_command(TARGET bg3se POST_BUILD
    COMMAND echo "Built: ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libbg3se.dylib"
    COMMAND file ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libbg3se.dylib
    COMMAND otool -L ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libbg3se.dylib | head -5
)
