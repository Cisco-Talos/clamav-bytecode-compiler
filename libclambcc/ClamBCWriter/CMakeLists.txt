# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcwriter object library
#
add_library(clambcwriter_obj OBJECT)
target_sources(clambcwriter_obj
    PRIVATE
        ClamBCWriter.cpp
)

target_include_directories(clambcwriter_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcwriter_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcwriter_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcwriter shared library.
#
add_library( clambcwriter SHARED )
target_link_libraries( clambcwriter
    PUBLIC
        clambcwriter_obj )
set_target_properties( clambcwriter PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcwriter PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcwriter PUBLIC ${LLVM_LIBS})

install(TARGETS clambcwriter DESTINATION ${CMAKE_INSTALL_LIBDIR})


