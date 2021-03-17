
# ClamAV Bytecode Compiler

<p align="center">
  <img width="250" height="250" src="https://raw.githubusercontent.com/Cisco-Talos/clamav-devel/dev/0.104/logo.png" alt='Maeve, the ClamAV mascot'>
</p>

<p align="center">
  The ClamAV® Bytecode Compiler is a tool to build cross-platform advanced
  malware detection plugins for the ClamAV® open source antivirus engine.
  We call these plugins "bytecode signatures". Bytecode signatures are are
  executed by a ClamAV using either an LLVM JIT runtime or an interpeter
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

See [the documentation, chapter 1 "Installation".](docs/user/clambc-user.pdf)

## Quick Start

### Getting the bytecode compiler repository

```bash
git clone git://github.com/Cisco-Talos/clamav-bytecode-compiler
```

### Quick start for building & installing

1. Ensure that you have LLVM 8 and Clang 8 installed.

2. Ensure that you have Python 3.6 or newer.

3. Run:

```bash
mkdir build && cd build

cmake .. \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_INSTALL_PREFIX=<install path>

cmake --build .

ctest -V

ctest install
```

See [the documentation, section "1.3 Building" if build fails](docs/user/clambc-user.pdf)

### Staying up-to-date

```bash
git pull
```

### Using a specific release

```bash
$ git tag | grep clambc
clambc-0.10
clambc-0.102.0
clambc-0.102.0-2
clambc-0.103.0
clambc-0.11
clambc-0.97.3a
clambc-0.98.1rc1
clambc-0.98.1rc2
clambc-0.98.5rc1
clambc-0.98.7
clambc-0.99.2

$ git checkout clambc-0.102.0-2
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
