VIRUSNAME_PREFIX("")
VIRUSNAMES("ClamAV-Test-File-detected-via-bytecode")
TARGET(1)

/* This is all dummy stuff */
SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(MZfromBOF)
DECLARE_SIGNATURE(MZfromEOF)
DECLARE_SIGNATURE(MZfromS0)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(MZfromBOF,       "0:4d5a50000200000004000f00ffff0000")
DEFINE_SIGNATURE(MZfromEOF, "EOF-544:4d5a50000200000004000f00ffff0000")
DEFINE_SIGNATURE(MZfromS0,     "S0+0:4d5a50000200000004000f00ffff0000")
SIGNATURES_END

PE_UNPACKER_DECLARE

bool logical_trigger(void)
{
    return matches(Signatures.MZfromBOF) && matches(Signatures.MZfromEOF) && matches(Signatures.MZfromS0);
}
/* Dummy stuff ends here */

int entrypoint() {
    // Get the offset of the EP
    uint32_t ep = getEntryPoint(), cur;

    // Disassemble one instruction at EP
    struct DIS_fixed instr;
    cur = DisassembleAt(&instr, ep, *__clambc_filesize - ep);
    if(cur == ep) // Failed to disasm
	return 0;

    // Check if it's "mov ebx, value"
    if(instr.x86_opcode != OP_MOV || // Not a MOV
       instr.arg[0].access_type != ACCESS_REG || // Left arg is not a register
       instr.arg[0].u.reg != X86_REG_EBX || // Left arg is not EBX
       instr.arg[1].access_type != ACCESS_IMM // Right arg is not an immediate value
       ) {
	return 0;
    }

    // Take the argument of mov ebx, ... which is the VA of the cyphertext
    uint32_t va_of_cyphertext = instr.arg[1].u.other;
    debug("VA of cyphertext is ");debug(va_of_cyphertext);

    // Make the VA an RVA - that is subtract the imagebase from it
    uint32_t rva_of_cyphertext = va_of_cyphertext -  __clambc_pedata.opt32.ImageBase;
    debug("RVA of cyphertext is ");debug(rva_of_cyphertext);

    // Turn the RVA of the cyphertext into a file (raw) offset
    uint32_t offset_of_cyphertext = pe_rawaddr(rva_of_cyphertext);

    // If the offset is bad, bail out
    if(offset_of_cyphertext == PE_INVALID_RVA) {
	debug("Can't locate the phisical offset of the cyphertext");
	return 0;
    }
    debug("Cyphertext starts at ");debug(offset_of_cyphertext);

    // Move to the cyphertext in the file
    seek(offset_of_cyphertext, SEEK_SET);

    // Make room for the cyphertext to be read - 10 bytes that is "HELLO WORM" plus one byte for the terminator
    uint8_t cyphertext[11];

    // Read the cyphertext from file into "cyphertext"
    if(read(cyphertext, 10)!=10) {
	debug("Can't read 10 bytes of cyphertext\n");
	return 0;
    }

    // The "decryption" loop - turns the cyphertext into playintext
    uint8_t current_position, key = 0x29;
    for(current_position=0; current_position<10; current_position++) {
	key++;
	cyphertext[current_position] ^= key;
	key = cyphertext[current_position];
    }

    // Compare the (now) plaintext with the reference ("HELLO WORM")
    if(!memcmp(cyphertext, "HELLO WORM", 10)) {
	cyphertext[10] = 0; // Add a string terminator
	debug((char *)cyphertext); // Print it, just for fun
	foundVirus("ClamAV-Test-File-detected-via-bytecode"); // Set the virus name!
    }
    return 0;
}
