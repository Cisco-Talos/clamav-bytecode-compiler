# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

# The ifacegen executable.
add_executable(clambc-ifacegen)
target_sources(clambc-ifacegen
    PRIVATE
        ifacegen.cpp)
target_include_directories(clambc-ifacegen
    PRIVATE
        .
        ../libclambcc/Common # For ClamBCCommon.h
        ${CMAKE_BINARY_DIR}  # For config.h
        ${LLVM_INCLUDE_DIRS}
)
set_target_properties(clambc-ifacegen PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")
target_link_directories(clambc-ifacegen PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambc-ifacegen PRIVATE ${LLVM_LIBS} ${CLANG_LIBS})

if(WIN32)
    install(TARGETS clambc-ifacegen DESTINATION .)
    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            EXECUTABLES
                $<TARGET_FILE:clambc-ifacegen>
            RESOLVED_DEPENDENCIES_VAR _r_deps
            UNRESOLVED_DEPENDENCIES_VAR _u_deps
            DIRECTORIES
                ${LLVM_LIBRARY_DIRS}
                ${CLANG_LIBRARY_DIRS}
        )
        foreach(_file ${_r_deps})
            string(TOLOWER ${_file} _file_lower)
            if(NOT ${_file_lower} MATCHES "c:[\\/]windows[\\/]system32.*")
                file(INSTALL
                    DESTINATION "${CMAKE_INSTALL_PREFIX}"
                    TYPE SHARED_LIBRARY
                    FOLLOW_SYMLINK_CHAIN
                    FILES "${_file}"
                )
            endif()
        endforeach()
        #message("UNRESOLVED_DEPENDENCIES_VAR: ${_u_deps}")
    ]])
else()
    install(TARGETS clambc-ifacegen DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
