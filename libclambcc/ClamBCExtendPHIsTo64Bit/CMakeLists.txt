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
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
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

install(TARGETS clambcextendphisto64bit DESTINATION ${CMAKE_INSTALL_LIBDIR})



