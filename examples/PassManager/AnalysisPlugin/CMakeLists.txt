# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The analysisplugin object library
#
add_library(analysisplugin_obj OBJECT)
target_sources(analysisplugin_obj
    PRIVATE
        AnalysisPlugin.cpp
)

target_include_directories(analysisplugin_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        .                   # For Common/clambc.h
        ..                  # For clambc.h  #TODO: change all passes to use "Common" and then delete this line.
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(analysisplugin_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(analysisplugin_obj -DLOG_BEFORE_AFTER=1)

#
# The analysisplugin shared library.
#
add_library( analysisplugin SHARED )
target_link_libraries( analysisplugin
    PUBLIC
        analysisplugin_obj )
set_target_properties( analysisplugin PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(analysisplugin PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(analysisplugin PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS analysisplugin DESTINATION .)
else()
    install(TARGETS analysisplugin DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()



