# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcchangemallocargsize object library
#
add_library(clambcchangemallocargsize_obj OBJECT)
target_sources(clambcchangemallocargsize_obj
    PRIVATE
        ClamBCChangeMallocArgSize.cpp
)

target_include_directories(clambcchangemallocargsize_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        .                   # For Common/clambc.h
        ..                  # For clambc.h  #TODO: change all passes to use "Common" and then delete this line.
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcchangemallocargsize_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcchangemallocargsize_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcchangemallocargsize shared library.
#
add_library( clambcchangemallocargsize SHARED )
target_link_libraries( clambcchangemallocargsize
    PUBLIC
        clambcchangemallocargsize_obj )
set_target_properties( clambcchangemallocargsize PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcchangemallocargsize PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcchangemallocargsize PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS clambcchangemallocargsize DESTINATION .)

    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:clambcchangemallocargsize>
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
    install(TARGETS clambcchangemallocargsize DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()



