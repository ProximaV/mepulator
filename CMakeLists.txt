cmake_minimum_required(VERSION 3.16)
project(mepulator LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(INSN_GEN_CPP "${CMAKE_CURRENT_BINARY_DIR}/insn_gen.cpp")

add_custom_command(
    OUTPUT "${INSN_GEN_CPP}"
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/generate_insn.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/insn.in"
            "${INSN_GEN_CPP}"
    DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/generate_insn.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/insn.in"
    COMMENT "Generating MeP instruction decoder table (insn_gen.cpp)"
)

set(MEPULATOR_CORE_SOURCES
    src/arm.cpp
    src/cpu.cpp
    src/debugger.cpp
    src/device.cpp
    src/f00d_machine.cpp
    src/insn.cpp
    src/log.cpp
    src/memory.cpp
    src/util.cpp

    src/devices/armcomm.cpp
    src/devices/bigmac.cpp
    src/devices/e001device.cpp
    src/devices/eeprom.cpp
    src/devices/mathdev.cpp
    src/devices/unknowndevice.cpp

    deps/mbedtls/library/aes.c
    deps/mbedtls/library/aesni.c
    deps/mbedtls/library/bignum.c
    deps/mbedtls/library/platform.c
    deps/mbedtls/library/sha1.c
    deps/mbedtls/library/sha256.c

    "${INSN_GEN_CPP}"
)

set_source_files_properties("${INSN_GEN_CPP}" PROPERTIES HEADER_FILE_ONLY TRUE)

add_library(mepulator_core STATIC ${MEPULATOR_CORE_SOURCES})

target_include_directories(mepulator_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/deps/mbedtls/include"
        "${CMAKE_CURRENT_BINARY_DIR}"
)

if(WIN32)
    target_compile_definitions(mepulator_core PUBLIC _CRT_SECURE_NO_WARNINGS NOMINMAX)
    target_link_libraries(mepulator_core PUBLIC ws2_32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(mepulator_core PUBLIC Threads::Threads)
endif()

if(MSVC)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" MEPULATOR_SRC_PREFIX_NATIVE)
    target_compile_options(mepulator_core PUBLIC
        "/d1trimfile:${MEPULATOR_SRC_PREFIX_NATIVE}"
    )
    add_link_options($<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
endif()

add_executable(mepulator src/main.cpp)
target_link_libraries(mepulator PRIVATE mepulator_core)

add_executable(mepulator_tests tests/mepulator_tests.cpp)
target_link_libraries(mepulator_tests PRIVATE mepulator_core)
enable_testing()
add_test(NAME mepulator_tests COMMAND mepulator_tests)

if(DEFINED ENV{IDA_SDK_DIR})
    set(_DEFAULT_IDA_SDK_DIR "$ENV{IDA_SDK_DIR}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
else()
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../ida-sdk-main/src")
endif()
set(IDA_SDK_DIR "${_DEFAULT_IDA_SDK_DIR}" CACHE PATH "Path to IDA SDK src directory")

set(_IDA_LIB_PATH "")
if(EXISTS "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
endif()

if(EXISTS "${IDA_SDK_DIR}/include/idd.hpp" AND _IDA_LIB_PATH)
    add_library(mepdbg SHARED src/ida_dbg_plugin.cpp)
    set_target_properties(mepdbg PROPERTIES
        PREFIX ""
        OUTPUT_NAME "mepdbg"
    )
    target_include_directories(mepdbg PRIVATE "${IDA_SDK_DIR}/include")
    target_compile_definitions(mepdbg PRIVATE
        __NT__
        __EA64__
        __X64__
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
    )
    target_link_libraries(mepdbg PRIVATE
        mepulator_core
        "${_IDA_LIB_PATH}"
    )
endif()
