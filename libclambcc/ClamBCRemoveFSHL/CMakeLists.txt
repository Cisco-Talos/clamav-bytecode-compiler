# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcremovefshl object library
#
add_library(clambcremovefshl_obj OBJECT)
target_sources(clambcremovefshl_obj
    PRIVATE
        ClamBCRemoveFSHL.cpp
)

target_include_directories(clambcremovefshl_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcremovefshl_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcremovefshl_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcremovefshl shared library.
#
add_library( clambcremovefshl SHARED )
target_link_libraries( clambcremovefshl
    PUBLIC
        clambcremovefshl_obj )
set_target_properties( clambcremovefshl PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcremovefshl PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcremovefshl PUBLIC ${LLVM_LIBS})

install(TARGETS clambcremovefshl DESTINATION ${CMAKE_INSTALL_LIBDIR})

