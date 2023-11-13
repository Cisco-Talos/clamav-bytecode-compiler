# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.


#'PassManager' is using the 'new' passmanager.  This was added
#for the upgrade to llvm 16, although the 'new' pass manager
#has been around a while.

add_subdirectory(LegacyPassManager)
add_subdirectory(PassManager)
