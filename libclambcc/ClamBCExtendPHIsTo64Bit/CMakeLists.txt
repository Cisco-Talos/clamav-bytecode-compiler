# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcextendphisto64bit object library
#
add_library(clambcextendphisto64bit_obj OBJECT)
target_sources(clambcextendphisto64bit_obj
    PRIVATE
        ClamBCExtendPHIsTo64Bit.cpp
)

target_include_directories(clambcextendphisto64bit_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        .                   # For Common/clambc.h
        ..                  # For clambc.h  #TODO: change all passes to use "Common" and then delete this line.
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcextendphisto64bit_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcextendphisto64bit_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcextendphisto64bit shared library.
#
add_library( clambcextendphisto64bit SHARED )
target_link_libraries( clambcextendphisto64bit
    PUBLIC
        clambcextendphisto64bit_obj )
set_target_properties( clambcextendphisto64bit PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcextendphisto64bit PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcextendphisto64bit PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS clambcextendphisto64bit DESTINATION .)

    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:clambcextendphisto64bit>
            RESOLVED_DEPENDENCIES_VAR _r_deps
            UNRESOLVED_DEPENDENCIES_VAR _u_deps
            DIRECTORIES
                ${LLVM_LIBRARY_DIRS}
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
    install(TARGETS clambcextendphisto64bit DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()



