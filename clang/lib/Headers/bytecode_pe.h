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

#ifndef __PE_H
#define __PE_H

/** @file */
/** Header for this PE file
  \group_pe */
struct pe_image_file_hdr {
    uint32_t Magic;  /**< PE magic header: PE\\0\\0 */
    uint16_t Machine;/**< CPU this executable runs on, see libclamav/pe.c for possible values */
    uint16_t NumberOfSections;/**< Number of sections in this executable */
    uint32_t TimeDateStamp;   /**< Unreliable */
    uint32_t PointerToSymbolTable;	    /**< debug */
    uint32_t NumberOfSymbols;		    /**< debug */
    uint16_t SizeOfOptionalHeader;	    /**< == 224 */
    uint16_t Characteristics;
};

/** PE data directory header
  \group_pe */
struct pe_image_data_dir {
    uint32_t VirtualAddress;
    uint32_t Size;
};

/** 32-bit PE optional header
  \group_pe */
struct pe_image_optional_hdr32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;		    /**< unreliable */
    uint8_t  MinorLinkerVersion;		    /**< unreliable */
    uint32_t SizeOfCode;			    /**< unreliable */
    uint32_t SizeOfInitializedData;		    /**< unreliable */
    uint32_t SizeOfUninitializedData;		    /**< unreliable */
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;				    /**< multiple of 64 KB */
    uint32_t SectionAlignment;			    /**< usually 32 or 4096 */
    uint32_t FileAlignment;			    /**< usually 32 or 512 */
    uint16_t MajorOperatingSystemVersion;	    /**< not used */
    uint16_t MinorOperatingSystemVersion;	    /**< not used */
    uint16_t MajorImageVersion;			    /**< unreliable */
    uint16_t MinorImageVersion;			    /**< unreliable */
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;			    /*< ? */
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;				    /**< NT drivers only */
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;			    /*< ? */
    uint32_t NumberOfRvaAndSizes;		    /**< unreliable */
    struct pe_image_data_dir DataDirectory[16];
};

/** PE 64-bit optional header
  \group_pe */
struct pe_image_optional_hdr64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;		    /**< unreliable */
    uint8_t  MinorLinkerVersion;		    /**< unreliable */
    uint32_t SizeOfCode;			    /**< unreliable */
    uint32_t SizeOfInitializedData;		    /**< unreliable */
    uint32_t SizeOfUninitializedData;		    /**< unreliable */
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;				    /**< multiple of 64 KB */
    uint32_t SectionAlignment;			    /**< usually 32 or 4096 */
    uint32_t FileAlignment;			    /**< usually 32 or 512 */
    uint16_t MajorOperatingSystemVersion;	    /**< not used */
    uint16_t MinorOperatingSystemVersion;	    /**< not used */
    uint16_t MajorImageVersion;			    /**< unreliable */
    uint16_t MinorImageVersion;			    /**< unreliable */
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;			    /* ? */
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;				    /**< NT drivers only */
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;			    /* ? */
    uint32_t NumberOfRvaAndSizes;		    /**< unreliable */
    struct pe_image_data_dir DataDirectory[16];
};

/** PE section header
  \group_pe */
struct pe_image_section_hdr {
    uint8_t Name[8];			    /**< may not end with NULL */
    /*
    union {
	uint32_t PhysicalAddress;
	uint32_t VirtualSize;
    } AddrSize;
    */
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;		    /**< multiple of FileAlignment */
    uint32_t PointerToRawData;		    /**< offset to the section's data */
    uint32_t PointerToRelocations;	    /**< object files only */
    uint32_t PointerToLinenumbers;	    /**< object files only */
    uint16_t NumberOfRelocations;	    /**< object files only */
    uint16_t NumberOfLinenumbers;	    /**< object files only */
    uint32_t Characteristics;
};

/** Data for the bytecode PE hook
  \group_pe */
struct cli_pe_hook_data {
  uint32_t offset;
  uint32_t ep; /**< EntryPoint as file offset */
  uint16_t nsections;/**< Number of sections */
  uint16_t dummy; /* align */
  struct pe_image_file_hdr file_hdr;/**< Header for this PE file */
  struct pe_image_optional_hdr32 opt32; /**< 32-bit PE optional header */
  uint32_t dummy2; /* align */
  struct pe_image_optional_hdr64 opt64;/**< 64-bit PE optional header */
  struct pe_image_data_dir dirs[16]; /**< PE data directory header */
  uint32_t e_lfanew;/**< address of new exe header */
  uint32_t overlays;/**< number of overlays */
  int32_t overlays_sz;/**< size of overlays */
  uint32_t hdr_size;/**< internally needed by rawaddr */
};




#endif
