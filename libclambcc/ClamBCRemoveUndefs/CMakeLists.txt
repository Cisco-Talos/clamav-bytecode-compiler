# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcremoveundefs object library
#
add_library(clambcremoveundefs_obj OBJECT)
target_sources(clambcremoveundefs_obj
    PRIVATE
        ClamBCRemoveUndefs.cpp
)

target_include_directories(clambcremoveundefs_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcremoveundefs_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcremoveundefs_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcremoveundefs shared library.
#
add_library( clambcremoveundefs SHARED )
target_link_libraries( clambcremoveundefs
    PUBLIC
        clambcremoveundefs_obj )
set_target_properties( clambcremoveundefs PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcremoveundefs PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcremoveundefs PUBLIC ${LLVM_LIBS})

install(TARGETS clambcremoveundefs DESTINATION ${CMAKE_INSTALL_LIBDIR})

