# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcremovepointerphis object library
#
add_library(clambcremovepointerphis_obj OBJECT)
target_sources(clambcremovepointerphis_obj
    PRIVATE
        ClamBCRemovePointerPHIs.cpp
)

target_include_directories(clambcremovepointerphis_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcremovepointerphis_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcremovepointerphis_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcremovepointerphis shared library.
#
add_library( clambcremovepointerphis SHARED )
target_link_libraries( clambcremovepointerphis
    PUBLIC
        clambcremovepointerphis_obj )
set_target_properties( clambcremovepointerphis PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcremovepointerphis PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcremovepointerphis PUBLIC ${LLVM_LIBS})

install(TARGETS clambcremovepointerphis DESTINATION ${CMAKE_INSTALL_LIBDIR})


