# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcpreserveabis object library
#
add_library(clambcpreserveabis_obj OBJECT)
target_sources(clambcpreserveabis_obj
    PRIVATE
        ClamBCPreserveABIs.cpp
)

target_include_directories(clambcpreserveabis_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcpreserveabis_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcpreserveabis_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcpreserveabis shared library.
#
add_library( clambcpreserveabis SHARED )
target_link_libraries( clambcpreserveabis
    PUBLIC
        clambcpreserveabis_obj )
set_target_properties( clambcpreserveabis PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcpreserveabis PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcpreserveabis PUBLIC ${LLVM_LIBS})

install(TARGETS clambcpreserveabis DESTINATION ${CMAKE_INSTALL_LIBDIR})


