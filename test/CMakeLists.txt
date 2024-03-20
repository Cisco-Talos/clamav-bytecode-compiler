# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# Paths to pass to our tests via environment variables
#
if(WIN32)
    file(TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}                            SOURCE)
    file(TO_NATIVE_PATH ${CMAKE_BINARY_DIR}                            BUILD)
    file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}                    TMP)

    file(TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}/clambcc/clambc-compiler.py CLAMBCC)
    file(TO_NATIVE_PATH ${clambc_EXECUTABLE} CLAMBC)
    file(TO_NATIVE_PATH ${clamscan_EXECUTABLE} CLAMSCAN)
    file(TO_NATIVE_PATH ${sigtool_EXECUTABLE} SIGTOOL)
    file(TO_NATIVE_PATH ${clambc_headers_DIRECTORY} HEADERS)
else()
    set(LD_LIBRARY_PATH    $<TARGET_FILE_DIR:ClamBCCommon>:$ENV{LD_LIBRARY_PATH})

    set(SOURCE             ${CMAKE_SOURCE_DIR})
    set(BUILD              ${CMAKE_BINARY_DIR})
    set(TMP                ${CMAKE_CURRENT_BINARY_DIR})

    set(CLAMBCC            ${CMAKE_SOURCE_DIR}/clambcc/clambc-compiler.py)
    set(CLAMBC             ${clambc_EXECUTABLE})
    set(CLAMSCAN           ${clamscan_EXECUTABLE})
    set(SIGTOOL            ${sigtool_EXECUTABLE})
    set(HEADERS            ${clambc_headers_DIRECTORY})
endif()

set(ENVIRONMENT
    PYTHONTRACEMALLOC=1 VERSION=${PROJECT_VERSION}${VERSION_SUFFIX}
    SOURCE=${SOURCE} BUILD=${BUILD} TMP=${TMP}
    LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
    CLAMBCC=${CLAMBCC}
    CLAMBC=${CLAMBC}
    CLAMSCAN=${CLAMSCAN}
    SIGTOOL=${SIGTOOL}
    HEADERS=${HEADERS}
)

#
# The Tests
# ~~~~~~~~~
#
# Run all tests with: `ctest`
#                 or: `ctest -V` for verbose output
#
# Run a specific test like this:
#                     `ctest -V -R 01`
#
add_test(NAME clambcc-compile-tests COMMAND ${Python3_EXECUTABLE} -m;${Python3_TEST_PACKAGE};01_basic_compile_test.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set_property(TEST clambcc-compile-tests PROPERTY ENVIRONMENT ${ENVIRONMENT})

add_test(NAME clambcc-runtime-test COMMAND ${Python3_EXECUTABLE} -m;${Python3_TEST_PACKAGE};02_basic_runtime_test.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set_property(TEST clambcc-runtime-test PROPERTY ENVIRONMENT ${ENVIRONMENT})

add_test(NAME clambcc-feature-test COMMAND ${Python3_EXECUTABLE} -m;${Python3_TEST_PACKAGE};03_feature_test.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set_property(TEST clambcc-feature-test PROPERTY ENVIRONMENT ${ENVIRONMENT})

if(WIN32)
    #
    # Prepare a test install, with all our DLL dependencies co-located with our EXEs and DLLs
    #
    # Generate GetLibs-$<CONFIG>.ctest which will collect all required DLL and EXE dependencies when `ctest` is run.
    #
    set(GEN_SCRIPT [[
        # Collect runtime DLL dependencies for our libs and apps
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:clambcc>
            RESOLVED_DEPENDENCIES_VAR _r_deps
            UNRESOLVED_DEPENDENCIES_VAR _u_deps
            DIRECTORIES
                $<TARGET_FILE_DIR:LLVM::LLVM>
            CONFLICTING_DEPENDENCIES_PREFIX CTEST_CONFLICTING_DEPENDENCIES
        )
        foreach(_file ${_r_deps})
            string(TOLOWER ${_file} _file_lower)
            if(NOT ${_file_lower} MATCHES "c:[\\/]windows[\\/]system32.*")
                message("Collecting DLL dependency: ${_file}")
                file(COPY ${_file} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
            endif()
        endforeach()

        # Collect our libs
        file(COPY $<TARGET_FILE:clambcc> DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
        file(COPY $<TARGET_FILE:clambc-compiler> DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    ]])

    file(GENERATE OUTPUT GetLibs-$<CONFIG>.ctest CONTENT ${GEN_SCRIPT})
    set_directory_properties(PROPERTIES TEST_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/Run-GetLibs.ctest)

endif()
