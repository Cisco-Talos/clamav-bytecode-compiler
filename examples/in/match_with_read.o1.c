VIRUSNAME_PREFIX("ClamAV-Test-File-detected-via-bytecode")
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
	// Get the entry point OFFSET
	uint32_t ep = getEntryPoint();
	debug("EP: "); debug(ep);

	// Move to the entry point offset in the file
	seek(ep, SEEK_SET);

	/* Here we look for mov ebx, value
	   The disassembler is however not yet integrated in the bc so for now we check
	   manually if it's a mov. In hex it should be bb33221100 for mov ebx, 00112233 
	   that is 5 bytes overall.
	*/
	// Make room for the 5 bytes to be read
	uint8_t first_op[5];
	// Read 5 bytes
	if(read(first_op, 5)!=5) {
		debug("Couldn't read 5 bytes @EP\n");
		return 0;
	}

	// Check if the first byte (aka first_op[0]) is bb
	if(first_op[0] != 0xbb) {
		debug("No 'mov ebx, cyphertext' found at entrypoint\n");
		return 0;
	}

	// Take the argument of mov ebx, ... which is the VA of the cyphertext
	uint32_t va_of_cyphertext = cli_readint32((uint32_t *)(first_op+1));
	debug("VA of cyphertext is ");debug(va_of_cyphertext);

	// Make the VA an RVA - that is subtract the imagebase from it
	uint32_t rva_of_cyphertext = va_of_cyphertext - getImageBase();
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
                uint8_t in = cyphertext[current_position];
		key++;
		cyphertext[current_position] ^= key;
		key = cyphertext[current_position];
	}

	// Compare the (now) plaintext with the reference ("HELLO WORM")
	if(!memcmp(cyphertext, "HELLO WORM", 10)) {
		cyphertext[10] = 0; // Add a string terminator
		debug((char *)cyphertext); // Print it, just for fun
		foundVirus(); // Virus found!
	}
	return 0;
}


