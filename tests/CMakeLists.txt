file(GLOB DECOMP_UNIT_TESTS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/unit/*.cpp)
add_executable(decomp_tests ${DECOMP_UNIT_TESTS})
target_link_libraries(decomp_tests PRIVATE decomp_core decomp_warnings)
target_include_directories(decomp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/integration)
target_compile_definitions(decomp_tests PRIVATE
  DECOMP_CORPUS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/corpus"
  DECOMP_INTEGRATION_DIR="${CMAKE_CURRENT_BINARY_DIR}/integration")

# Build the integration corpus with the MinGW cross compilers when available,
# once for x64 and once for x86, so both lifter paths are covered.
find_program(MINGW64_CC x86_64-w64-mingw32-gcc)
find_program(MINGW32_CC i686-w64-mingw32-gcc)
set(INTEGRATION_OUT ${CMAKE_CURRENT_BINARY_DIR}/integration)
file(MAKE_DIRECTORY ${INTEGRATION_OUT})
set(INTEGRATION_DLLS)

function(add_integration_dll cc arch opt)
  if(NOT ${cc})
    return()
  endif()
  set(out ${INTEGRATION_OUT}/cases_${arch}_${opt}.dll)
  add_custom_command(OUTPUT ${out}
    COMMAND ${${cc}} -shared -${opt} -g0 -fno-asynchronous-unwind-tables
            -DDECOMP_EXPORT -o ${out} ${CMAKE_CURRENT_SOURCE_DIR}/integration/cases.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/integration/cases.c
    COMMENT "Building integration corpus ${arch} ${opt}"
    VERBATIM)
  set(INTEGRATION_DLLS ${INTEGRATION_DLLS} ${out} PARENT_SCOPE)
endfunction()

add_integration_dll(MINGW64_CC x64 O2)
set(ALL_DLLS ${INTEGRATION_DLLS})
add_integration_dll(MINGW64_CC x64 O0)
list(APPEND ALL_DLLS ${INTEGRATION_DLLS})
add_integration_dll(MINGW32_CC x86 O2)
list(APPEND ALL_DLLS ${INTEGRATION_DLLS})
add_integration_dll(MINGW32_CC x86 O0)
list(APPEND ALL_DLLS ${INTEGRATION_DLLS})
list(REMOVE_DUPLICATES ALL_DLLS)

if(ALL_DLLS)
  add_custom_target(integration_corpus ALL DEPENDS ${ALL_DLLS})
  add_dependencies(decomp_tests integration_corpus)
  target_compile_definitions(decomp_tests PRIVATE DECOMP_HAVE_INTEGRATION=1)
else()
  message(STATUS "MinGW cross compilers not found: integration corpus disabled")
endif()

add_test(NAME unit COMMAND decomp_tests)
