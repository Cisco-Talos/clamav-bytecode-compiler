/*
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *  Copyright (C) 2014 Cisco Systems, Inc. and/or its affiliates.
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

#ifndef __PE_H
#define __PE_H

#include "bytecode_pe_structs.h"

struct cli_pe_hook_data {
    uint32_t offset;
    uint32_t ep;                          /**< EntryPoint as file offset */
    uint16_t nsections;                   /**< Number of sections */
    uint16_t dummy;                       /* align */
    struct pe_image_file_hdr file_hdr;    /**< Header for this PE file */
    struct pe_image_optional_hdr32 opt32; /**< 32-bit PE optional header */
    /** Our opt32 no longer includes DataDirectory[16], but the one in the
     * bytecode compiler source still does.  Add this here as a placeholder (and
     * it gets used, so we need to populate it also */
    struct pe_image_data_dir opt32_dirs[16];
    uint32_t dummy2;                         /* align */
    struct pe_image_optional_hdr64 opt64;    /**< 64-bit PE optional header */
    struct pe_image_data_dir opt64_dirs[16]; /** See note about opt32_dirs */
    struct pe_image_data_dir dirs[16];       /**< PE data directory header */
    uint32_t e_lfanew;                       /**< address of new exe header */
    uint32_t overlays;                       /**< number of overlays */
    int32_t overlays_sz;                     /**< size of overlays */
    uint32_t hdr_size;                       /**< internally needed by rawaddr */
};

#endif
