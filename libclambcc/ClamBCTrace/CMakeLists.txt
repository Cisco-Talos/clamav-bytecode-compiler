# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambctrace object library
#
add_library(clambctrace_obj OBJECT)
target_sources(clambctrace_obj
    PRIVATE
        ClamBCTrace.cpp
)

target_include_directories(clambctrace_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambctrace_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambctrace_obj -DLOG_BEFORE_AFTER=1)

#
# The clambctrace shared library.
#
add_library( clambctrace SHARED )
target_link_libraries( clambctrace
    PUBLIC
        clambctrace_obj )
set_target_properties( clambctrace PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambctrace PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambctrace PUBLIC ${LLVM_LIBS})

install(TARGETS clambctrace DESTINATION ${CMAKE_INSTALL_LIBDIR})


