# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcoutlineendiannesscalls object library
#
add_library(clambcoutlineendiannesscalls_obj OBJECT)
target_sources(clambcoutlineendiannesscalls_obj
    PRIVATE
        ClamBCOutlineEndiannessCalls.cpp
)

target_include_directories(clambcoutlineendiannesscalls_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcoutlineendiannesscalls_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcoutlineendiannesscalls_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcoutlineendiannesscalls shared library.
#
add_library( clambcoutlineendiannesscalls SHARED )
target_link_libraries( clambcoutlineendiannesscalls
    PUBLIC
        clambcoutlineendiannesscalls_obj )
set_target_properties( clambcoutlineendiannesscalls PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcoutlineendiannesscalls PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcoutlineendiannesscalls PUBLIC ${LLVM_LIBS})

install(TARGETS clambcoutlineendiannesscalls DESTINATION ${CMAKE_INSTALL_LIBDIR})




