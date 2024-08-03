# Copyright (C) 2021-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# The common shared library.
#
add_library(ClamBCCommon SHARED
    ClamBCDiagnostics.cpp
    ClamBCUtilities.cpp
    version.c)
target_include_directories(ClamBCCommon PRIVATE
    ${CMAKE_BINARY_DIR} # For clambc-version.h (generated file)
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCCommon PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCCommon -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCCommon PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCCommon PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCCommon DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCAnalyzer shared library.
#
add_library(ClamBCAnalyzer SHARED
    ClamBCAnalyzer.cpp)
target_include_directories(ClamBCAnalyzer PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCAnalyzer PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCAnalyzer -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCAnalyzer PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCAnalyzer PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCAnalyzer DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCConvertIntrinsicsTo32Bit shared library.
#
add_library(ClamBCConvertIntrinsicsTo32Bit SHARED
    ClamBCConvertIntrinsicsTo32Bit.cpp)
target_include_directories(ClamBCConvertIntrinsicsTo32Bit PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCConvertIntrinsicsTo32Bit PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCConvertIntrinsicsTo32Bit -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCConvertIntrinsicsTo32Bit PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCConvertIntrinsicsTo32Bit PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCConvertIntrinsicsTo32Bit DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCExtendPHIsTo64Bit shared library.
#
add_library(ClamBCExtendPHIsTo64Bit SHARED
    ClamBCExtendPHIsTo64Bit.cpp)
target_include_directories(ClamBCExtendPHIsTo64Bit PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCExtendPHIsTo64Bit PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCExtendPHIsTo64Bit -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCExtendPHIsTo64Bit PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCExtendPHIsTo64Bit PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCExtendPHIsTo64Bit DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCLogicalCompiler shared library.
#
add_library(ClamBCLogicalCompiler SHARED
    ClamBCLogicalCompiler.cpp)
target_include_directories(ClamBCLogicalCompiler PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCLogicalCompiler PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCLogicalCompiler -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCLogicalCompiler PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCLogicalCompiler PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCLogicalCompiler DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCLogicalCompilerHelper shared library.
#
add_library(ClamBCLogicalCompilerHelper SHARED
    ClamBCLogicalCompilerHelper.cpp)
target_include_directories(ClamBCLogicalCompilerHelper PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCLogicalCompilerHelper PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCLogicalCompilerHelper -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCLogicalCompilerHelper PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCLogicalCompilerHelper PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCLogicalCompilerHelper DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCLoweringF shared library.
#
add_library(ClamBCLoweringF SHARED
    ClamBCLowering.cpp
    ClamBCLoweringF.cpp)
target_include_directories(ClamBCLoweringF PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCLoweringF PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCLoweringF -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCLoweringF PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCLoweringF PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCLoweringF DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCLoweringNF shared library.
#
add_library(ClamBCLoweringNF SHARED
    ClamBCLowering.cpp
    ClamBCLoweringNF.cpp)
target_include_directories(ClamBCLoweringNF PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCLoweringNF PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCLoweringNF -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCLoweringNF PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCLoweringNF PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCLoweringNF DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCOutlineEndiannessCalls shared library.
#
add_library(ClamBCOutlineEndiannessCalls SHARED
    ClamBCOutlineEndiannessCalls.cpp)
target_include_directories(ClamBCOutlineEndiannessCalls PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCOutlineEndiannessCalls PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCOutlineEndiannessCalls -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCOutlineEndiannessCalls PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCOutlineEndiannessCalls PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCOutlineEndiannessCalls DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCPrepareGEPsForWriter shared library.
#
add_library(ClamBCPrepareGEPsForWriter SHARED
    ClamBCPrepareGEPsForWriter.cpp)
target_include_directories(ClamBCPrepareGEPsForWriter PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCPrepareGEPsForWriter PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCPrepareGEPsForWriter -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCPrepareGEPsForWriter PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCPrepareGEPsForWriter PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCPrepareGEPsForWriter DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCPreserveABIs shared library.
#
add_library(ClamBCPreserveABIs SHARED
    ClamBCPreserveABIs.cpp)
target_include_directories(ClamBCPreserveABIs PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCPreserveABIs PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCPreserveABIs -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCPreserveABIs PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCPreserveABIs PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCPreserveABIs DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCRebuild shared library.
#
add_library(ClamBCRebuild SHARED
    ClamBCRebuild.cpp)
target_include_directories(ClamBCRebuild PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCRebuild PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCRebuild -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCRebuild PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCRebuild PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCRebuild DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCRegAlloc shared library.
#
add_library(ClamBCRegAlloc SHARED
    ClamBCRegAlloc.cpp)
target_include_directories(ClamBCRegAlloc PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCRegAlloc PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCRegAlloc -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCRegAlloc PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCRegAlloc PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCRegAlloc DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCRemoveFreezeInsts shared library.
#
add_library(ClamBCRemoveFreezeInsts SHARED
    ClamBCRemoveFreezeInsts.cpp)
target_include_directories(ClamBCRemoveFreezeInsts PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCRemoveFreezeInsts PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCRemoveFreezeInsts -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCRemoveFreezeInsts PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCRemoveFreezeInsts PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCRemoveFreezeInsts DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCRemoveFSHL shared library.
#
add_library(ClamBCRemoveFSHL SHARED
    ClamBCRemoveFSHL.cpp)
target_include_directories(ClamBCRemoveFSHL PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCRemoveFSHL PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCRemoveFSHL -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCRemoveFSHL PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCRemoveFSHL PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCRemoveFSHL DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCRemoveICMPSLE shared library.
#
add_library(ClamBCRemoveICMPSLE SHARED
    ClamBCRemoveICMPSLE.cpp)
target_include_directories(ClamBCRemoveICMPSLE PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCRemoveICMPSLE PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCRemoveICMPSLE -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCRemoveICMPSLE PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCRemoveICMPSLE PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCRemoveICMPSLE DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCRemovePointerPHIs shared library.
#
add_library(ClamBCRemovePointerPHIs SHARED
ClamBCRemovePointerPHIs.cpp)
target_include_directories(ClamBCRemovePointerPHIs PRIVATE
${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCRemovePointerPHIs PROPERTIES
COMPILE_FLAGS "${WARNCXXFLAGS}"
VERSION ${LIBCLAMBC_VERSION}
SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCRemovePointerPHIs -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCRemovePointerPHIs PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCRemovePointerPHIs PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCRemovePointerPHIs DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCRemoveUnsupportedICMPIntrinsics shared library.
#
add_library(ClamBCRemoveUnsupportedICMPIntrinsics SHARED
    ClamBCRemoveUnsupportedICMPIntrinsics.cpp)
target_include_directories(ClamBCRemoveUnsupportedICMPIntrinsics PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCRemoveUnsupportedICMPIntrinsics PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCRemoveUnsupportedICMPIntrinsics -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCRemoveUnsupportedICMPIntrinsics PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCRemoveUnsupportedICMPIntrinsics PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCRemoveUnsupportedICMPIntrinsics DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCRemoveUSUB shared library.
#
add_library(ClamBCRemoveUSUB SHARED
    ClamBCRemoveUSUB.cpp)
target_include_directories(ClamBCRemoveUSUB PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCRemoveUSUB PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCRemoveUSUB -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCRemoveUSUB PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCRemoveUSUB PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCRemoveUSUB DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCTrace shared library.
#
add_library(ClamBCTrace SHARED
    ClamBCTrace.cpp)
target_include_directories(ClamBCTrace PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCTrace PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCTrace -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCTrace PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCTrace PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCTrace DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCVerifier shared library.
#
add_library(ClamBCVerifier SHARED
    ClamBCVerifier.cpp)
target_include_directories(ClamBCVerifier PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCVerifier PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCVerifier -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCVerifier PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCVerifier PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCVerifier DESTINATION ${CMAKE_INSTALL_LIBDIR})

#
# The ClamBCWriter shared library.
#
add_library(ClamBCWriter SHARED
    ClamBCWriter.cpp)
target_include_directories(ClamBCWriter PRIVATE
    ${LLVM_INCLUDE_DIRS})
set_target_properties(ClamBCWriter PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    VERSION ${LIBCLAMBC_VERSION}
    SOVERSION ${LIBCLAMBC_SOVERSION})
#target_compile_definitions(ClamBCWriter -DLOG_BEFORE_AFTER=1) # For testing
target_link_directories(ClamBCWriter PRIVATE ${LLVM_LIBRARY_DIRS})
target_link_libraries(ClamBCWriter PUBLIC ${LLVM_LIBS})
install(TARGETS ClamBCWriter DESTINATION ${CMAKE_INSTALL_LIBDIR})

