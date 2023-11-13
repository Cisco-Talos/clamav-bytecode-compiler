# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcremoveusub object library
#
add_library(clambcremoveusub_obj OBJECT)
target_sources(clambcremoveusub_obj
    PRIVATE
        ClamBCRemoveUSUB.cpp
)

target_include_directories(clambcremoveusub_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcremoveusub_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcremoveusub_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcremoveusub shared library.
#
add_library( clambcremoveusub SHARED )
target_link_libraries( clambcremoveusub
    PUBLIC
        clambcremoveusub_obj )
set_target_properties( clambcremoveusub PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcremoveusub PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcremoveusub PUBLIC ${LLVM_LIBS})

install(TARGETS clambcremoveusub DESTINATION ${CMAKE_INSTALL_LIBDIR})



