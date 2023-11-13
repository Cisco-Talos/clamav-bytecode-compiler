# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcpreparegepsforwriter object library
#
add_library(clambcpreparegepsforwriter_obj OBJECT)
target_sources(clambcpreparegepsforwriter_obj
    PRIVATE
        ClamBCPrepareGEPsForWriter.cpp
)

target_include_directories(clambcpreparegepsforwriter_obj
    PRIVATE
        ${CMAKE_BINARY_DIR}                 # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcpreparegepsforwriter_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcpreparegepsforwriter_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcpreparegepsforwriter shared library.
#
add_library( clambcpreparegepsforwriter SHARED )
target_link_libraries( clambcpreparegepsforwriter
    PUBLIC
        clambcpreparegepsforwriter_obj )
set_target_properties( clambcpreparegepsforwriter PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcpreparegepsforwriter PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcpreparegepsforwriter PUBLIC ${LLVM_LIBS})

install(TARGETS clambcpreparegepsforwriter DESTINATION ${CMAKE_INSTALL_LIBDIR})



