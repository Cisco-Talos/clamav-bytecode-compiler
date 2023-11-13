# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcremoveunsupportedicmpintrinsics object library
#
add_library(clambcremoveunsupportedicmpintrinsics_obj OBJECT)
target_sources(clambcremoveunsupportedicmpintrinsics_obj
    PRIVATE
        ClamBCRemoveUnsupportedICMPIntrinsics.cpp
)

target_include_directories(clambcremoveunsupportedicmpintrinsics_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcremoveunsupportedicmpintrinsics_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcremoveunsupportedicmpintrinsics_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcremoveunsupportedicmpintrinsics shared library.
#
add_library( clambcremoveunsupportedicmpintrinsics SHARED )
target_link_libraries( clambcremoveunsupportedicmpintrinsics
    PUBLIC
        clambcremoveunsupportedicmpintrinsics_obj )
set_target_properties( clambcremoveunsupportedicmpintrinsics PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcremoveunsupportedicmpintrinsics PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcremoveunsupportedicmpintrinsics PUBLIC ${LLVM_LIBS})

install(TARGETS clambcremoveunsupportedicmpintrinsics DESTINATION ${CMAKE_INSTALL_LIBDIR})

