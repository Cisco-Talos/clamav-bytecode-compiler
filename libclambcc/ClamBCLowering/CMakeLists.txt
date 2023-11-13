# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcloweringf object library
#
add_library(clambcloweringf_obj OBJECT)
target_sources(clambcloweringf_obj
    PRIVATE
        ClamBCLowering.cpp
        ClamBCLoweringF.cpp
)

target_include_directories(clambcloweringf_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcloweringf_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcloweringf_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcloweringf shared library.
#
add_library( clambcloweringf SHARED )
target_link_libraries( clambcloweringf
    PUBLIC
        clambcloweringf_obj )
set_target_properties( clambcloweringf PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcloweringf PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcloweringf PUBLIC ${LLVM_LIBS})

install(TARGETS clambcloweringf DESTINATION ${CMAKE_INSTALL_LIBDIR})





#
# The clambcloweringnf object library
#
add_library(clambcloweringnf_obj OBJECT)
target_sources(clambcloweringnf_obj
    PRIVATE
        ClamBCLowering.cpp
        ClamBCLoweringNF.cpp
)

target_include_directories(clambcloweringnf_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        ..
        ${CLAMBC_LIB_DIR}/Common            # For anything in 'Common'
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcloweringnf_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambcloweringnf_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcloweringnf shared library.
#
add_library( clambcloweringnf SHARED )
target_link_libraries( clambcloweringnf
    PUBLIC
        clambcloweringnf_obj )
set_target_properties( clambcloweringnf PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcloweringnf PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcloweringnf PUBLIC ${LLVM_LIBS})

install(TARGETS clambcloweringnf DESTINATION ${CMAKE_INSTALL_LIBDIR})


