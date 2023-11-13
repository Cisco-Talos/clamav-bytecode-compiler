# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcremovefreezeinsts object library
#
add_library(clambcremovefreezeinsts_obj OBJECT)
target_sources(clambcremovefreezeinsts_obj
    PRIVATE
        ClamBCRemoveFreezeInsts.cpp
)

target_include_directories(clambcremovefreezeinsts_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcremovefreezeinsts_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcremovefreezeinsts_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcremovefreezeinsts shared library.
#
add_library( clambcremovefreezeinsts SHARED )
target_link_libraries( clambcremovefreezeinsts
    PUBLIC
        clambcremovefreezeinsts_obj )
set_target_properties( clambcremovefreezeinsts PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcremovefreezeinsts PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcremovefreezeinsts PUBLIC ${LLVM_LIBS})

install(TARGETS clambcremovefreezeinsts DESTINATION ${CMAKE_INSTALL_LIBDIR})


