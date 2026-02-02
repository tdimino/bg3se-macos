# CMakeLists.txt for BG3SE ImGui Test Application
# Standalone tool for testing Ext.IMGUI widgets without launching BG3

cmake_minimum_required(VERSION 3.16)

# Project setup
project(imgui_test LANGUAGES C CXX OBJC OBJCXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_OBJC_STANDARD 11)
set(CMAKE_OBJCXX_STANDARD 20)

# Root of main BG3SE project
set(BG3SE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# Source files
set(IMGUI_TEST_SOURCES
    main.mm
)

# ImGui sources (minimal set needed)
set(IMGUI_SOURCES
    ${BG3SE_ROOT}/lib/imgui/imgui.cpp
    ${BG3SE_ROOT}/lib/imgui/imgui_demo.cpp
    ${BG3SE_ROOT}/lib/imgui/imgui_draw.cpp
    ${BG3SE_ROOT}/lib/imgui/imgui_tables.cpp
    ${BG3SE_ROOT}/lib/imgui/imgui_widgets.cpp
    ${BG3SE_ROOT}/lib/imgui/backends/imgui_impl_metal.mm
    ${BG3SE_ROOT}/lib/imgui/backends/imgui_impl_osx.mm
)

# BG3SE IMGUI system sources
set(BG3SE_IMGUI_SOURCES
    ${BG3SE_ROOT}/src/imgui/imgui_objects.c
)

# BG3SE Lua IMGUI bindings
set(BG3SE_LUA_SOURCES
    ${BG3SE_ROOT}/src/lua/lua_imgui.c
)

# Pre-built Lua library
set(LUA_LIBRARY ${BG3SE_ROOT}/lib/lua/liblua-universal.a)

# Create executable
add_executable(imgui_test
    ${IMGUI_TEST_SOURCES}
    ${IMGUI_SOURCES}
    ${BG3SE_IMGUI_SOURCES}
    ${BG3SE_LUA_SOURCES}
)

# Include directories
target_include_directories(imgui_test PRIVATE
    ${BG3SE_ROOT}/lib/imgui
    ${BG3SE_ROOT}/lib/imgui/backends
    ${BG3SE_ROOT}/lib/lua/src
    ${BG3SE_ROOT}/src/imgui
    ${BG3SE_ROOT}/src/lua
    ${BG3SE_ROOT}/src
)

# Find required frameworks
find_library(COCOA_FRAMEWORK Cocoa REQUIRED)
find_library(METAL_FRAMEWORK Metal REQUIRED)
find_library(METALKIT_FRAMEWORK MetalKit REQUIRED)
find_library(QUARTZCORE_FRAMEWORK QuartzCore REQUIRED)
find_library(GAMECONTROLLER_FRAMEWORK GameController REQUIRED)

# Link frameworks and libraries
target_link_libraries(imgui_test PRIVATE
    ${COCOA_FRAMEWORK}
    ${METAL_FRAMEWORK}
    ${METALKIT_FRAMEWORK}
    ${QUARTZCORE_FRAMEWORK}
    ${GAMECONTROLLER_FRAMEWORK}
    ${LUA_LIBRARY}
)

# Compile definitions
target_compile_definitions(imgui_test PRIVATE
    IMGUI_TEST_STANDALONE=1
    LUA_USE_MACOSX=1
)

# Compile options for ARC
set_target_properties(imgui_test PROPERTIES
    XCODE_ATTRIBUTE_CLANG_ENABLE_OBJC_ARC "YES"
)

# Output to bin directory
set_target_properties(imgui_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Copy test scripts to build directory
add_custom_command(TARGET imgui_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/test_scripts"
            "$<TARGET_FILE_DIR:imgui_test>/test_scripts"
    COMMENT "Copying test scripts to build directory"
)

message(STATUS "ImGui Test Tool configured")
message(STATUS "  BG3SE Root: ${BG3SE_ROOT}")
message(STATUS "  Output: ${CMAKE_BINARY_DIR}/bin/imgui_test")
