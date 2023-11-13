# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcchangemallocargsize object library
#
add_library(clambcchangemallocargsize_obj OBJECT)
target_sources(clambcchangemallocargsize_obj
    PRIVATE
        ClamBCChangeMallocArgSize.cpp
)

target_include_directories(clambcchangemallocargsize_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcchangemallocargsize_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcchangemallocargsize_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcchangemallocargsize shared library.
#
add_library( clambcchangemallocargsize SHARED )
target_link_libraries( clambcchangemallocargsize
    PUBLIC
        clambcchangemallocargsize_obj )
set_target_properties( clambcchangemallocargsize PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcchangemallocargsize PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcchangemallocargsize PUBLIC ${LLVM_LIBS})

install(TARGETS clambcchangemallocargsize DESTINATION ${CMAKE_INSTALL_LIBDIR})



