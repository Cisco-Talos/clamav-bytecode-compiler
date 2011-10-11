/*
 *  Copyright (C) 2009 Sourcefire, Inc.
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __EXECS_H
#define __EXECS_H



#include "bcfeatures.h"

/** @file */
/** Section of executable file.
  \group_pe
*/
struct cli_exe_section {
    uint32_t rva;/**< Relative VirtualAddress */
    uint32_t vsz;/**< VirtualSize */
    uint32_t raw;/**< Raw offset (in file) */
    uint32_t rsz;/**< Raw size (in file) */
    uint32_t chr;/**< Section characteristics */
    uint32_t urva; /**< PE - unaligned VirtualAddress */
    uint32_t uvsz; /**< PE - unaligned VirtualSize */
    uint32_t uraw; /**< PE - unaligned PointerToRawData */
    uint32_t ursz; /**< PE - unaligned SizeOfRawData */
};

/** Executable file information
  \group_pe
*/
struct cli_exe_info {
    /** Information about all the sections of this file. 
     * This array has \p nsection elements */
    struct cli_exe_section *section;
    /** Offset where this executable start in file (nonzero if embedded) */
    uint32_t offset;
    /** Entrypoint of executable */
    uint32_t ep;
    /** Number of sections*/
    uint16_t nsections;
    void *dummy;/* for compat - preserve offset */
    /** Resrources RVA - PE ONLY */
    uint32_t res_addr;
    /** Address size - PE ONLY */
    uint32_t hdr_size;
    /** Hashset for versioninfo matching */
};

#endif
