# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcregalloc object library
#
add_library(clambcregalloc_obj OBJECT)
target_sources(clambcregalloc_obj
    PRIVATE
        ClamBCRegAlloc.cpp
)

target_include_directories(clambcregalloc_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcregalloc_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcregalloc_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcregalloc shared library.
#
add_library( clambcregalloc SHARED )
target_link_libraries( clambcregalloc
    PUBLIC
        clambcregalloc_obj )
set_target_properties( clambcregalloc PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcregalloc PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcregalloc PUBLIC ${LLVM_LIBS})

install(TARGETS clambcregalloc DESTINATION ${CMAKE_INSTALL_LIBDIR})


