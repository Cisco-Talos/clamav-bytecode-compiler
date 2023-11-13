# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambccommon object library
#
add_library(clambccommon_obj OBJECT)
target_sources(clambccommon_obj
    PRIVATE
        ClamBCDiagnostics.cpp
        ClamBCUtilities.cpp
        version.c
)

target_include_directories(clambccommon_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
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

install(TARGETS clambccommon DESTINATION ${CMAKE_INSTALL_LIBDIR})
