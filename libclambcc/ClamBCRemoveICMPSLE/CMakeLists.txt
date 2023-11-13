# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcremoveicmpsle object library
#
add_library(clambcremoveicmpsle_obj OBJECT)
target_sources(clambcremoveicmpsle_obj
    PRIVATE
        ClamBCRemoveICMPSLE.cpp
)

target_include_directories(clambcremoveicmpsle_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcremoveicmpsle_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcremoveicmpsle_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcremoveicmpsle shared library.
#
add_library( clambcremoveicmpsle SHARED )
target_link_libraries( clambcremoveicmpsle
    PUBLIC
        clambcremoveicmpsle_obj )
set_target_properties( clambcremoveicmpsle PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcremoveicmpsle PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcremoveicmpsle PUBLIC ${LLVM_LIBS})

install(TARGETS clambcremoveicmpsle DESTINATION ${CMAKE_INSTALL_LIBDIR})


