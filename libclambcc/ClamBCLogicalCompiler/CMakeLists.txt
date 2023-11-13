# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambclogicalcompiler object library
#
add_library(clambclogicalcompiler_obj OBJECT)
target_sources(clambclogicalcompiler_obj
    PRIVATE
        ClamBCLogicalCompiler.cpp
)

target_include_directories(clambclogicalcompiler_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambclogicalcompiler_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambclogicalcompiler_obj -DLOG_BEFORE_AFTER=1)

#
# The clambclogicalcompiler shared library.
#
add_library( clambclogicalcompiler SHARED )
target_link_libraries( clambclogicalcompiler
    PUBLIC
        clambclogicalcompiler_obj )
set_target_properties( clambclogicalcompiler PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambclogicalcompiler PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambclogicalcompiler PUBLIC ${LLVM_LIBS})

install(TARGETS clambclogicalcompiler DESTINATION ${CMAKE_INSTALL_LIBDIR})


