cmake_minimum_required(VERSION 3.20)
project(decomp VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(DECOMP_BUILD_TESTS "Build the decomp test suite" ON)
option(DECOMP_USE_SYSTEM_CAPSTONE "Use an installed Capstone (pkg-config) instead of building it" OFF)
option(DECOMP_SANITIZE "Build with address/undefined sanitizers (GCC/Clang)" OFF)

# ---------------------------------------------------------------------------
# Capstone (used only for raw x86/x64 decoding, hidden behind src/disasm)
# ---------------------------------------------------------------------------
if(DECOMP_USE_SYSTEM_CAPSTONE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)
  add_library(decomp_capstone INTERFACE)
  target_link_libraries(decomp_capstone INTERFACE PkgConfig::CAPSTONE)
else()
  set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_X86_ATT_DISABLE ON CACHE BOOL "" FORCE)
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone/CMakeLists.txt")
    add_subdirectory(third_party/capstone EXCLUDE_FROM_ALL)
  else()
    include(FetchContent)
    FetchContent_Declare(capstone
      GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
      GIT_TAG 5.0.1
      GIT_SHALLOW TRUE)
    FetchContent_GetProperties(capstone)
    if(NOT capstone_POPULATED)
      FetchContent_Populate(capstone)
      add_subdirectory(${capstone_SOURCE_DIR} ${capstone_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
  endif()
  add_library(decomp_capstone INTERFACE)
  target_link_libraries(decomp_capstone INTERFACE capstone::capstone)
endif()

# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------
add_library(decomp_warnings INTERFACE)
if(MSVC)
  target_compile_options(decomp_warnings INTERFACE /W4 /permissive- /utf-8 /wd4100 /wd4146)
  target_compile_definitions(decomp_warnings INTERFACE _CRT_SECURE_NO_WARNINGS NOMINMAX)
else()
  target_compile_options(decomp_warnings INTERFACE -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)
  if(DECOMP_SANITIZE)
    target_compile_options(decomp_warnings INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(decomp_warnings INTERFACE -fsanitize=address,undefined)
  endif()
endif()

add_subdirectory(src)

if(DECOMP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
