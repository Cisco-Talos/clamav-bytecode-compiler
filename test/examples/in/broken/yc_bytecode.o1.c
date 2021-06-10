/* --- This is libclamav/yc.c hacked to compile with the bytecode compiler */

/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Ivan Zlatev
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

/* Decrypts files, protected by Y0da Cryptor 1.3 */

/* aCaB:
 * 13/01/2006 - merged standalone unpacker into libclamav
 * 14/01/2006 - major rewrite and bugfix
 */

#define CLI_ROL(a,b) a = ( a << (b % (sizeof(a)<<3) ))  |  (a >> (  (sizeof(a)<<3)  -  (b % (sizeof(a)<<3 )) ) )
#define CLI_ROR(a,b) a = ( a >> (b % (sizeof(a)<<3) ))  |  (a << (  (sizeof(a)<<3)  -  (b % (sizeof(a)<<3 )) ) )
#define cli_dbgmsg(...)

#define EC16(x) le16_to_host(x) /* Convert little endian to host */

/* ========================================================================== */
/* "Emulates" the poly decryptors */

static inline  __attribute__((always_inline)) int yc_poly_emulator(char* decryptor_offset, char* code, unsigned int ecx)
{
  /* 
     This is the instruction set of the poly code.
     Numbers stand for example only.

     2C 05            SUB AL,5
     2AC1             SUB AL,CL
     34 10            XOR AL,10
     32C1             XOR AL,CL
     FEC8             DEC AL
     04 10            ADD AL,10
     02C1             ADD AL,CL
     C0C0 06          ROL AL,6
     C0C8 05          ROR AL,5
     D2C8             ROR AL,CL
     D2C0             ROL AL,CL

  */
  unsigned char al;
  unsigned char cl = ecx & 0xff;
  unsigned int j,i;

  for(i=0;i<ecx;i++) /* Byte looper - Decrypts every byte and write it back */
    {
      al = code[i];

      for(j=0;j<0x30;j++)   /* Poly Decryptor "Emulator" */
	{
	  switch(decryptor_offset[j])
	    {

	    case '\xEB':	/* JMP short */
	      j++;
	      j = j + decryptor_offset[j];
	      break;

	    case '\xFE':	/* DEC  AL */
	      al--;
	      j++;
	      break;

	    case '\x2A':	/* SUB AL,CL */
	      al = al - cl;
	      j++;
	      break;

	    case '\x02':	/* ADD AL,CL */
	      al = al + cl;
	      j++;
	      break
		;
	    case '\x32':	/* XOR AL,CL */
	      al = al ^ cl;
	      j++;
	      break;
	      ;
	    case '\x04':	/* ADD AL,num */
	      j++;
	      al = al + decryptor_offset[j];
	      break;
	      ;
	    case '\x34':	/* XOR AL,num */
	      j++;
	      al = al ^ decryptor_offset[j];
	      break;

	    case '\x2C':	/* SUB AL,num */
	      j++;
	      al = al - decryptor_offset[j];
	      break;

	    case '\xC0':
	      j++;
	      if(decryptor_offset[j]=='\xC0') /* ROL AL,num */
		{
		  j++;
		  CLI_ROL(al,decryptor_offset[j]);
		}
	      else			/* ROR AL,num */
		{
		  j++;
		  CLI_ROR(al,decryptor_offset[j]);
		}
	      break;

	    case '\xD2':
	      j++;
	      if(decryptor_offset[j]=='\xC8') /* ROR AL,CL */
		{
		  j++;
		  CLI_ROR(al,cl);
		}
	      else			/* ROL AL,CL */
		{
		  j++;
		  CLI_ROL(al,cl);
		}
	      break;

	    case '\x90':
	    case '\xf8':
	    case '\xf9':
	      break;

	    default:
	      cli_dbgmsg("yC: Unhandled opcode %x\n", (unsigned char)decryptor_offset[j]);
	      break;
	    }
	}
      cl--;
      code[i] = al;
    }
  return 0;

}

/* ========================================================================== */
/* Main routine which calls all others */
static force_inline int yc_decrypt(char *fbuf, unsigned int filesize, unsigned int sectcount, uint32_t peoffset, uint32_t ecx, unsigned offset)
{
  struct cli_exe_section section;
  get_pe_section(&section, sectcount);
  uint32_t ycsect = section.raw+offset;
  unsigned int i;
  struct pe_image_file_hdr *pe = (struct pe_image_file_hdr*) (fbuf + peoffset);
  char *sname = (char *)pe + EC16(pe->SizeOfOptionalHeader) + 0x18;
  debug(sectcount);
  debug(peoffset);
  debug(ecx);
  debug(offset);
  /* 

  First layer (decryptor of the section decryptor) in last section 

  Start offset for analyze: Start of yC Section + 0x93
  End offset for analyze: Start of yC Section + 0xC3
  Lenght to decrypt - ECX = 0xB97

  */
  cli_dbgmsg("yC: offset: %x, length: %x\n", offset, ecx);
  cli_dbgmsg("yC: decrypting decryptor on sect %d\n", sectcount);
/*  if (ycsect >= filesize - 0xc6 - 0x30)
      return -1;*/
  if (yc_poly_emulator(fbuf + ycsect + 0x93, fbuf + ycsect + 0xc6, ecx))
    return 1;
  filesize-=section.ursz;

  /* 

  Second layer (decryptor of the sections) in last section 

  Start offset for analyze: Start of yC Section + 0x457
  End offset for analyze: Start of yC Section + 0x487
  Lenght to decrypt - ECX = Raw Size of Section

  */


  /* Loop through all sections and decrypt them... */
  for(i=0;i<sectcount;i++)
    {
      get_pe_section(&section, i);
      uint32_t name = (uint32_t) cli_readint32(sname+i*0x28);
      if ( !section.raw ||
	   !section.rsz ||
	   name == 0x63727372 || /* rsrc */
	   name == 0x7273722E || /* .rsr */
	   name == 0x6F6C6572 || /* relo */
	   name == 0x6C65722E || /* .rel */
	   name == 0x6164652E || /* .eda */
	   name == 0x6164722E || /* .rda */
	   name == 0x6164692E || /* .ida */
	   name == 0x736C742E || /* .tls */
	   (name&0xffff) == 0x4379  /* yC */
	) continue;
      cli_dbgmsg("yC: decrypting sect%d\n",i);
      if (yc_poly_emulator(fbuf + ycsect + (offset == -0x18 ? 0x3ea : 0x457), fbuf + section.raw, section.ursz))
	return 1;
    }

  /* Remove yC section */
  pe->NumberOfSections=EC16(sectcount);

  /* Remove IMPORT_DIRECTORY information */
  memset((char *)pe + sizeof(struct pe_image_file_hdr) + 0x68, 0, 8);

  /* OEP resolving */
  /* OEP = DWORD PTR [ Start of yC section+ A0F] */
  cli_writeint32((char *)pe + sizeof(struct pe_image_file_hdr) + 16, cli_readint32(fbuf + ycsect + 0xa0f));

  /* Fix SizeOfImage */
  cli_writeint32((char *)pe + sizeof(struct pe_image_file_hdr) + 0x38, cli_readint32((char *)pe + sizeof(struct pe_image_file_hdr) + 0x38) - section.vsz);

  if (write(fbuf, filesize) == -1) {
    debug("yC: Cannot write unpacked file\n");
    return 1;
  }
  return 0;
}

VIRUSNAME_PREFIX("Trojan.Foo")
VIRUSNAMES("A", "B")
TARGET(1)
PE_UNPACKER_DECLARE
uint32_t entrypoint()
{
    char fbuf[1024*1024];
    char epbuff[4096];
    unsigned filesize = seek(0, SEEK_END);
    uint16_t n = getNumberOfSections();
    if (n <= 1 || getVirtualEntryPoint() != getSectionRVA(n-1)+0x60) {
	debug(getVirtualEntryPoint());
	debug(getSectionRVA(n-1));
	debug("yC returning early\n");
	return 0;
    }
    uint32_t ecx = 0;
    int16_t offset;

    seek(getEntryPoint(), SEEK_SET);
    if (read(epbuff, sizeof(epbuff)) == -1) {
	debug("yC: unable to read @EP\n");
	return -1;
    }

    /* yC 1.3 */
    if (!memcmp(epbuff, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED", 15) &&
	!memcmp(epbuff+0x26, "\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 13) &&
	((uint8_t)epbuff[0x13] == 0xB9) &&
	((uint16_t)(cli_readint16(epbuff+0x18)) == 0xE981) &&
	!memcmp(epbuff+0x1e,"\x8B\xD5\x81\xC2", 4)) {
	debug("yC 1.3 matched\n");

	offset = 0;
	if (0x6c - cli_readint32(epbuff+0xf) + cli_readint32(epbuff+0x22) == 0xC6)
	    ecx = cli_readint32(epbuff+0x14) - cli_readint32(epbuff+0x1a);
    }

    /* yC 1.3 variant */
    if (!ecx && !memcmp(epbuff, "\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57", 9) &&
	!memcmp(epbuff+0x17, "\xe8\x00\x00\x00\x00\x5d\x81\xed", 8) &&
	((uint8_t)epbuff[0x23] == 0xB9)) {

	debug("yC 1.3 variant matched\n");
	offset = 0x10;
	if (0x6c - cli_readint32(epbuff+0x1f) + cli_readint32(epbuff+0x32) == 0xC6)
	    ecx = cli_readint32(epbuff+0x24) - cli_readint32(epbuff+0x2a);
    }

    /* yC 1.x/modified */
    if (!ecx && !memcmp(epbuff, "\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",9) &&
	((uint8_t)epbuff[0xd] == 0xb9) &&
	((uint16_t)cli_readint16(epbuff + 0x12)== 0xbd8d) &&
	!memcmp(epbuff+0x18, "\x8b\xf7\xac", 3)) {
	debug("yC 1.x/modified matched\n");

	offset = -0x18;
	if (0x66 - cli_readint32(epbuff+0x9) + cli_readint32(epbuff+0x14) == 0xae)
	    ecx = cli_readint32(epbuff+0xe);
    }
    if (ecx <= 0x800 || ecx >= 0x2000 ||
	memcmp(epbuff+0x63+offset, "\xaa\xe2\xcc", 3)) {
	debug("yC check failed\n");
	return 0;
    }

    struct cli_exe_section section;
    get_pe_section(&section, n-1);
    if (filesize <= section.raw + 0xC6 + ecx + offset) {
	debug("filesize check failed\n");
	return 0;
    }
    debug("yC: detected yC file\n");
    if (filesize > 1024*1024) {
	debug("yC: FIXME dynamically allocate buffer");
	return -1;
    }
    n--;
    seek(0, SEEK_SET);
    if (read(fbuf, sizeof(fbuf)) == -1) {
	debug("yC: unable to read\n");
	return -1;
    }

    return yc_decrypt(fbuf, filesize, n, getPELFANew(), ecx,offset);
}
