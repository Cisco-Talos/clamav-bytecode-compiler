# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The clambcc object library
#
add_library(clambcc_obj OBJECT)
target_sources(clambcc_obj
    PRIVATE
        ClamBCLowering/ClamBCLowering.cpp
        ClamBCVerifier/ClamBCVerifier.cpp
        ClamBCLogicalCompiler/ClamBCLogicalCompiler.cpp
        ClamBCCopyrightHandler/ClamBCCopyrightHandler.cpp
        ClamBCRebuild/ClamBCRebuild.cpp
        ClamBCTrace/ClamBCTrace.cpp
        ClamBCModule/ClamBCModule.cpp
        ClamBCWriter/ClamBCWriter.cpp
        ClamBCAnalyzer/ClamBCAnalyzer.cpp
        Common/ClamBCDiagnostics.cpp
        Common/ClamBCUtilities.cpp
        Common/ClamBCRegAlloc.cpp
        Common/version.c
        ClamBCPrepareGEPsForWriter/ClamBCPrepareGEPsForWriter.cpp
        ClamBCRemoveSelectInsts/ClamBCRemoveSelectInsts.cpp
        ClamBCOutlineEndiannessCalls/ClamBCOutlineEndiannessCalls.cpp
        ClamBCChangeMallocArgSize/ClamBCChangeMallocArgSize.cpp
        ClamBCRemovePointerPHIs/ClamBCRemovePointerPHIs.cpp
        ClamBCConvertIntrinsics/ClamBCConvertIntrinsics.cpp
        ClamBCRemoveUndefs/ClamBCRemoveUndefs.cpp
        ClamBCPreserveABIs/ClamBCPreserveABIs.cpp
        ClamBCExtendPHIsTo64Bit/ClamBCExtendPHIsTo64Bit.cpp
)

target_include_directories(clambcc_obj
    PRIVATE
        ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
        .                   # For Common/clambc.h
        Common              # For clambc.h  #TODO: change all passes to use "Common" and then delete this line.
        ${LLVM_INCLUDE_DIRS}
)

set_target_properties(clambcc_obj PROPERTIES COMPILE_FLAGS "${WARNCXXFLAGS}")

#
# For testing
#
#target_compile_definitions(clambc_obj -DLOG_BEFORE_AFTER=1)

#
# The clambcc shared library.
#
add_library( clambcc SHARED )
target_link_libraries( clambcc
    PUBLIC
        clambcc_obj )
set_target_properties( clambcc PROPERTIES
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION} )

target_link_directories(clambcc PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(clambcc PUBLIC ${LLVM_LIBS})

if(WIN32)
    install(TARGETS clambcc DESTINATION .)

    # Also install shared library (DLL) dependencies
    install(CODE [[
        file(GET_RUNTIME_DEPENDENCIES
            LIBRARIES
                $<TARGET_FILE:clambcc>
            RESOLVED_DEPENDENCIES_VAR _r_deps
            UNRESOLVED_DEPENDENCIES_VAR _u_deps
            DIRECTORIES
                ${LLVM_LIBRARY_DIRS}
        )
        foreach(_file ${_r_deps})
            string(TOLOWER ${_file} _file_lower)
            if(NOT ${_file_lower} MATCHES "c:[\\/]windows[\\/]system32.*")
                file(INSTALL
                    DESTINATION "${CMAKE_INSTALL_PREFIX}"
                    TYPE SHARED_LIBRARY
                    FOLLOW_SYMLINK_CHAIN
                    FILES "${_file}"
                )
            endif()
        endforeach()
        #message("UNRESOLVED_DEPENDENCIES_VAR: ${_u_deps}")
    ]])
else()
    install(TARGETS clambcc DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
