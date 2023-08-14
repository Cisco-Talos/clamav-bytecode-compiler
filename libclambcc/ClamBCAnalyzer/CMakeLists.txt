# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcanalyzer object library
#
add_library(clambcanalyzer_obj OBJECT)
target_sources(clambcanalyzer_obj
    PRIVATE
        ClamBCAnalyzer.cpp
)

target_include_directories(clambcanalyzer_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        .                   # For Common/clambc.h
        ..                  # For clambc.h  #TODO: change all passes to use "Common" and then delete this line.
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcanalyzer_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcanalyzer_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcanalyzer shared library.
#
add_library( clambcanalyzer SHARED )
target_link_libraries( clambcanalyzer
    PUBLIC
        clambcanalyzer_obj )
set_target_properties( clambcanalyzer PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcanalyzer PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcanalyzer PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS clambcanalyzer DESTINATION .)

    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:clambcanalyzer>
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
    install(TARGETS clambcanalyzer DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()



