# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcrebuild object library
#
add_library(clambcrebuild_obj OBJECT)
target_sources(clambcrebuild_obj
    PRIVATE
        ClamBCRebuild.cpp
)

target_include_directories(clambcrebuild_obj
    PRIVATE
        ${CMAKE_BINARY_DIR}                # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common           # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcrebuild_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcrebuild_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcrebuild shared library.
#
add_library( clambcrebuild SHARED )
target_link_libraries( clambcrebuild
    PUBLIC
        clambcrebuild_obj )
set_target_properties( clambcrebuild PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcrebuild PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcrebuild PUBLIC ${LLVM_LIBS})

install(TARGETS clambcrebuild DESTINATION ${CMAKE_INSTALL_LIBDIR})



