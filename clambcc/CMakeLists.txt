# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

configure_file(clambc-compiler.py clambc-compiler)

install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/clambc-compiler"
    DESTINATION bin
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
)
