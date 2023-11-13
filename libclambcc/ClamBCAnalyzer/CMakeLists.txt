# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcanalyzer object library
#
add_library(clambcanalyzer_obj OBJECT)
target_sources(clambcanalyzer_obj
    PRIVATE
        ClamBCAnalyzer.cpp
)

target_include_directories(clambcanalyzer_obj
    PRIVATE
        ${CMAKE_BINARY_DIR}                 # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcanalyzer_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcanalyzer_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcanalyzer shared library.
#
add_library( clambcanalyzer SHARED )
target_link_libraries( clambcanalyzer
    PUBLIC
        clambcanalyzer_obj )
set_target_properties( clambcanalyzer PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcanalyzer PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcanalyzer PUBLIC ${LLVM_LIBS})

install(TARGETS clambcanalyzer DESTINATION ${CMAKE_INSTALL_LIBDIR})



