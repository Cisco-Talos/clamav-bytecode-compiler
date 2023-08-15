# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambccommon object library
#
add_library(clambccommon_obj OBJECT)
target_sources(clambccommon_obj
    PRIVATE
        ClamBCDiagnostics.cpp
        ClamBCRegAlloc.cpp
        ClamBCUtilities.cpp
)

target_include_directories(clambccommon_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        .                   # For Common/clambc.h
        ..                  # For clambc.h  #TODO: change all passes to use "Common" and then delete this line.
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambccommon_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambccommon_obj -DLOG_BEFORE_AFTER=1)

#
# The clambccommon shared library.
#
add_library( clambccommon SHARED )
target_link_libraries( clambccommon
    PUBLIC
        clambccommon_obj )
set_target_properties( clambccommon PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambccommon PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambccommon PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS clambccommon DESTINATION .)

    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:clambccommon>
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
    install(TARGETS clambccommon DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()



