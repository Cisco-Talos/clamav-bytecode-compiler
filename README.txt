(* OASIS_START *)
(* DO NOT EDIT (digest: 7ac29abb152fc115a875462d3069c43d) *)
This is the README file for the ClamAV Bytecode Compiler distribution.

(C) 2010 Sourcefire Inc.

Compiles a C-like language to ClamAV 0.97+ bytecode

Clam AntiVirus Bytecode Compiler compiles a C-like language into ClamAV
bytecode (.cbc files), that libclamav can load and run. It uses Clang as a
frontend, and a custom LLVM backend.

Uses of bytecode: - write more complicated heuristic/algorithmic detections
that would tipically require a pe.c update - write unpackers - write
(limited) emulators - workarounds bugs in libclamav (in some limited cases)

Features of compiler: - preincluded headers - it accepts a C-like language
like input (but not the full language) - bounds and div - generates
endian-independent and portable code - fixed size integers and pointers -
thread safe: no global state - no external/libc calls, only a safe list of
libclamav APIs are available - error in bytecode doesn't abort whole program
- rejects unsafe / non-portable code conservatively

Planned features: - write regular expressions matchers - DSL for matching
regular expressions and file formats

Bytecodes are usually written specifically for the language that this
compiler supports, including other C code usually requires porting (if
possible at all).

See the files INSTALL.txt for building and installation instructions. See the
file COPYING for copying conditions. 

Home page: http://www.clamav.net


(* OASIS_STOP *)
