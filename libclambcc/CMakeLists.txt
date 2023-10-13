# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.


add_subdirectory(ClamBCLogicalCompiler)
add_subdirectory(ClamBCLogicalCompilerHelper)
add_subdirectory(ClamBCRemoveUndefs)
add_subdirectory(ClamBCPreserveABIs)
add_subdirectory(ClamBCAnalyzer)
add_subdirectory(Common)
add_subdirectory(ClamBCVerifier)
add_subdirectory(ClamBCRemovePointerPHIs)
add_subdirectory(ClamBCLowering)
add_subdirectory(ClamBCRemoveFreezeInsts)
add_subdirectory(ClamBCOutlineEndiannessCalls)
add_subdirectory(ClamBCChangeMallocArgSize)
add_subdirectory(ClamBCExtendPHIsTo64Bit)

