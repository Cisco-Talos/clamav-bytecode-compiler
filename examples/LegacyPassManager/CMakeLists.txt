# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The hello object library
#
add_library(hello_obj OBJECT)
target_sources(hello_obj
    PRIVATE
        HelloWorld/HelloWorld.cpp
)

target_include_directories(hello_obj
    PRIVATE
        ../libclambcc  # HACK: For Common/clambc.h
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(hello_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambc_obj -DLOG_BEFORE_AFTER=1)

#
# The hello shared library.
#
add_library( hello SHARED )
target_link_libraries( hello
    PUBLIC
        hello_obj )
set_target_properties( hello PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(hello_obj PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(hello_obj PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS hello DESTINATION .)

    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:hello>
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
    install(TARGETS hello DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
