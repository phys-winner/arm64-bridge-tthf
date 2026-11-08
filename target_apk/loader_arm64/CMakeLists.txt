# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)
project(tinythief_arm64_bridge LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(TT_RELEASE_NO_LOGS "Compile out all arm64 bridge log output" OFF)

include(FetchContent)

# Size: applied before FetchContent so dynarmic/fmt/mcl inherit them.
# Only JNI_OnLoad needs to be exported (everything else is registered at
# runtime), so hiding the rest drops the dynsym table and most of .rela.
add_compile_options(-fvisibility=hidden -fvisibility-inlines-hidden
                    -ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections -Wl,--icf=all -Wl,--exclude-libs,ALL)

# Boost is supplied externally; point BOOST_ROOT at an unpacked release.
set(Boost_NO_BOOST_CMAKE ON)
# These headers live outside the Android sysroot.
find_path(Boost_INCLUDE_DIR boost/version.hpp
    HINTS "${BOOST_ROOT}" "$ENV{BOOST_ROOT}"
    PATH_SUFFIXES include
    NO_CMAKE_FIND_ROOT_PATH)
find_package(Boost 1.83 REQUIRED)

# Configure Dynarmic.
# NOTE: the real option is DYNARMIC_FRONTENDS (a list), not DYNARMIC_ENABLE_A32/A64 --
# the old names were silently ignored, so A64 was being built too.
set(DYNARMIC_FRONTENDS "A32" CACHE STRING "" FORCE)
set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)  # cross-compiling: never pick up host libs

message(STATUS "Fetching Dynarmic from GitHub...")
FetchContent_Declare(
    dynarmic
    GIT_REPOSITORY https://github.com/azahar-emu/dynarmic.git
    GIT_TAG        e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
)
FetchContent_MakeAvailable(dynarmic)

set(BRIDGE_SOURCES
    src/elf_loader.cpp
    src/dynarmic_host.cpp
    src/thunk_manager.cpp
    src/thunks_gl.cpp
    src/thunks_libc.cpp
    src/jni_fake_env.cpp
    src/jni_bridge.cpp
)

add_library(tinythief_arm64_bridge SHARED ${BRIDGE_SOURCES})
set_target_properties(tinythief_arm64_bridge PROPERTIES OUTPUT_NAME "tinythief")

target_include_directories(tinythief_arm64_bridge PRIVATE
    src
    ${dynarmic_SOURCE_DIR}/include
)

target_link_libraries(tinythief_arm64_bridge PRIVATE
    dynarmic
    Boost::headers
    GLESv2
    OpenSLES
    android
    m
)

if(NOT TT_RELEASE_NO_LOGS)
    target_link_libraries(tinythief_arm64_bridge PRIVATE log)
endif()

target_compile_definitions(tinythief_arm64_bridge PRIVATE
    ANDROID
    __ANDROID__
)

if(TT_RELEASE_NO_LOGS)
    target_compile_definitions(tinythief_arm64_bridge PRIVATE TT_RELEASE_NO_LOGS=1)
endif()

# Android 15+ devices (Pixel 8a/10a, ...) boot with 16 KB pages; a 4 KB-aligned
# LOAD segment triggers the "app isn't 16 KB compatible" loader warning.
target_link_options(tinythief_arm64_bridge PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
)
