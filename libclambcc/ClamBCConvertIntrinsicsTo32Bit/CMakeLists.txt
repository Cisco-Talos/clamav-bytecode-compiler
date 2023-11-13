# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcconvertintrinsicsto32bit object library
#
add_library(clambcconvertintrinsicsto32bit_obj OBJECT)
target_sources(clambcconvertintrinsicsto32bit_obj
    PRIVATE
        ClamBCConvertIntrinsicsTo32Bit.cpp
)

target_include_directories(clambcconvertintrinsicsto32bit_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcconvertintrinsicsto32bit_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcconvertintrinsicsto32bit_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcconvertintrinsicsto32bit shared library.
#
add_library( clambcconvertintrinsicsto32bit SHARED )
target_link_libraries( clambcconvertintrinsicsto32bit
    PUBLIC
        clambcconvertintrinsicsto32bit_obj )
set_target_properties( clambcconvertintrinsicsto32bit PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcconvertintrinsicsto32bit PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcconvertintrinsicsto32bit PUBLIC ${LLVM_LIBS})

install(TARGETS clambcconvertintrinsicsto32bit DESTINATION ${CMAKE_INSTALL_LIBDIR})


