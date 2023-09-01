# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcloweringf object library
#
add_library(clambcloweringf_obj OBJECT)
target_sources(clambcloweringf_obj
    PRIVATE
        ClamBCLowering.cpp
        ClamBCLoweringF.cpp
)

target_include_directories(clambcloweringf_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        .                   # For Common/clambc.h
        ..                  # For clambc.h  #TODO: change all passes to use "Common" and then delete this line.
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcloweringf_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcloweringf_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcloweringf shared library.
#
add_library( clambcloweringf SHARED )
target_link_libraries( clambcloweringf
    PUBLIC
        clambcloweringf_obj )
set_target_properties( clambcloweringf PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcloweringf PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcloweringf PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS clambcloweringf DESTINATION .)

    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:clambcloweringf>
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
    install(TARGETS clambcloweringf DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()







#
# The clambcloweringnf object library
#
add_library(clambcloweringnf_obj OBJECT)
target_sources(clambcloweringnf_obj
    PRIVATE
        ClamBCLowering.cpp
        ClamBCLoweringNF.cpp
)

target_include_directories(clambcloweringnf_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        .                   # For Common/clambc.h
        ..                  # For clambc.h  #TODO: change all passes to use "Common" and then delete this line.
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcloweringnf_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcloweringnf_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcloweringnf shared library.
#
add_library( clambcloweringnf SHARED )
target_link_libraries( clambcloweringnf
    PUBLIC
        clambcloweringnf_obj )
set_target_properties( clambcloweringnf PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcloweringnf PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcloweringnf PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS clambcloweringnf DESTINATION .)

    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:clambcloweringnf>
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
    install(TARGETS clambcloweringnf DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()





