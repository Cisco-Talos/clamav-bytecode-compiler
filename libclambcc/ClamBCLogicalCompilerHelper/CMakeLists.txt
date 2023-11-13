# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambclogicalcompilerhelper object library
#
add_library(clambclogicalcompilerhelper_obj OBJECT)
target_sources(clambclogicalcompilerhelper_obj
    PRIVATE
        ClamBCLogicalCompilerHelper.cpp
)

target_include_directories(clambclogicalcompilerhelper_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambclogicalcompilerhelper_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambclogicalcompilerhelper_obj -DLOG_BEFORE_AFTER=1)

#
# The clambclogicalcompilerhelper shared library.
#
add_library( clambclogicalcompilerhelper SHARED )
target_link_libraries( clambclogicalcompilerhelper
    PUBLIC
        clambclogicalcompilerhelper_obj )
set_target_properties( clambclogicalcompilerhelper PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambclogicalcompilerhelper PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambclogicalcompilerhelper PUBLIC ${LLVM_LIBS})

install(TARGETS clambclogicalcompilerhelper DESTINATION ${CMAKE_INSTALL_LIBDIR})



