
# ClamAV Bytecode Compiler

<p align="center">
  <img width="250" height="250" src="https://raw.githubusercontent.com/Cisco-Talos/clamav/main/logo.png" alt='Maeve, the ClamAV mascot'>
</p>

<p align="center">
  The ClamAV® Bytecode Compiler is a tool to build cross-platform advanced
  malware detection plugins for the ClamAV® open source antivirus engine.
  We call these plugins "bytecode signatures". Bytecode signatures are are
  executed by a ClamAV using either an LLVM JIT runtime or an interpreter
  runtime. These signatures extend ClamAV's file format support and provide
  detection capabilities above and beyond the limitations of content-based
  logical signatures.
</p>

<p align="center">
  <a href="https://github.com/Cisco-Talos/clamav-bytecode-compiler/actions"><img src="https://github.com/Cisco-Talos/clamav-bytecode-compiler/workflows/CMake%20Build/badge.svg" height="18"></a>
  <a href="https://discord.gg/6vNAqWnVgw"><img src="https://img.shields.io/discord/636023333074370595.svg?logo=discord" height="18"/></a>
  <a href="https://twitter.com/clamav"><img src="https://abs.twimg.com/favicons/twitter.ico" width="18" height="18"></a>
</p>

## Documentation

At present the [pdf documentation](docs/user/clambc-user.pdf) is dated.
Specifically, the instructions for building the compiler or no longer correct.
The documentation will be updated as time permits.

The PDF documentation still provides valuable instructions for writing and
compiling signatures, and documents features of the bytecode signature API.

## Quick Start

### Getting the bytecode compiler repository

```bash
git clone git://github.com/Cisco-Talos/clamav-bytecode-compiler
```

### Quick start for building & installing

#### Requirements

- LLVM and Clang, version 8 or newer
  - LLVM and Clang versions **must** match.
  - Version 8 is preferred, tested. Newer versions are not guaranteed to work correctly.
  - LLVM is required to build the bytecode compiler.
  - Clang is required to run the bytecode compiler.

- Python 3.6 or newer.
  - Python is required to run the unit tests, and to run the bytecode compiler.

#### Build & Install

Configure:
```bash
mkdir build && cd build

cmake .. \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_INSTALL_PREFIX=<install path>
```

Build:
```bash
cmake --build .
```

Test:
```bash
ctest -V
```

Install:
```bash
cmake --build . --target install
```

#### Additional Build Examples

Build with a specific LLVM version and specific ClamAV install that installs to
local directory:
```bash
cmake .. \
  -D CMAKE_INSTALL_PREFIX=install \
  -D ENABLE_TESTS=ON \
  -D LLVM_ROOT=/usr/lib/llvm-8 \
  -D ClamAV_HOME=$HOME/clams/0.105.0

make -j12

ctest -V

make install
```

## Change Log

For information about the features in this and prior releases, read
[the news](NEWS.md).

## Join the ClamAV Community

The best way to get in touch with the ClamAV community is to join our
[mailing lists](https://www.clamav.net/documents/mailing-lists-faq) and to
join us on [Discord](https://discord.gg/6vNAqWnVgw).

## Want to make a contribution?

The ClamAV development team welcomes
[code contributions](https://github.com/Cisco-Talos/clamav-bytecode-compiler).
Thanks for joining us!

## Licensing

ClamAV is licensed for public/open source use under the GNU General Public
License, Version 2 (GPLv2).

See `COPYING/COPYING.txt` for a copy of the license.

### 3rd Party Code

ClamAV contains a number of components that include code copied in part or in
whole from 3rd party projects and whose code is not owned by Cisco and which
are licensed differently than ClamAV. These include:

- LLVM, Clang:
  - < 9.0.0: Illinois Open Source License (BSD-like)
  - >= 9.0.0: Apache License 2.0 with LLVM Exceptions

See the `COPYING` directory for a copy of the 3rd party project licenses.
