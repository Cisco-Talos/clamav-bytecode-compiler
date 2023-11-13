# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcverifier object library
#
add_library(clambcverifier_obj OBJECT)
target_sources(clambcverifier_obj
    PRIVATE
        ClamBCVerifier.cpp
)

target_include_directories(clambcverifier_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcverifier_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcverifier_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcverifier shared library.
#
add_library( clambcverifier SHARED )
target_link_libraries( clambcverifier
    PUBLIC
        clambcverifier_obj )
set_target_properties( clambcverifier PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcverifier PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcverifier PUBLIC ${LLVM_LIBS})

install(TARGETS clambcverifier DESTINATION ${CMAKE_INSTALL_LIBDIR})


