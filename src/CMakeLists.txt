file(GLOB_RECURSE DECOMP_CORE_SOURCES CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/support/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pe/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/arch/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/disasm/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/analysis/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/ir/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lift/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/ssa/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/opt/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/types/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/winapi/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/structure/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/ast/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/cgen/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp
)

add_library(decomp_core STATIC ${DECOMP_CORE_SOURCES})
target_include_directories(decomp_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(decomp_core PUBLIC decomp_warnings PRIVATE decomp_capstone)

add_executable(decomp cli/main.cpp)
target_link_libraries(decomp PRIVATE decomp_core decomp_warnings)
