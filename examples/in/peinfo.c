VIRUSNAME_PREFIX("")
VIRUSNAMES("peinfo")
TARGET(1)

PE_UNPACKER_DECLARE

int entrypoint()
{
  unsigned i;
  debug("HasExeInfo:");
  debug(hasExeInfo());

  debug("isPE64:");
  debug(isPE64());

  debug("MajorLinkerVersion:");
  debug(getPEMajorLinkerVersion());

  debug("MinorLinkerVersion:");
  debug(getPEMinorLinkerVersion());

  debug("SizeOfCode:");
  debug(getPESizeOfCode());

  debug("SizeOfInitializedData");
  debug(getPESizeOfInitializedData());

  debug("SizeOfUninitializedData");
  debug(getPESizeOfUninitializedData());

  debug("BaseOfCode:");
  debug(getPEBaseOfCode());

  debug("BaseOfData:");
  debug(getPEBaseOfData());

  debug("ImageBase:");
  debug(getPEImageBase());

  debug("SectionAlignment:");
  debug(getPESectionAlignment());

  debug("FileAlignment:");
  debug(getPEFileAlignment());

  debug("MajorOperatingSystemVersion:");
  debug(getPEMajorOperatingSystemVersion());

  debug("MinorOperatingSystemVersion:");
  debug(getPEMinorOperatingSystemVersion());

  debug("MajorImageVersion:");
  debug(getPEMajorImageVersion());

  debug("MinorImageVersion:");
  debug(getPEMinorImageVersion());

  debug("MajorSubsystemVersion:");
  debug(getPEMajorSubsystemVersion());

  debug("MinorSubsystemVersion:");
  debug(getPEMinorSubsystemVersion());

  debug("Win32Version:");
  debug(getPEWin32VersionValue());

  debug("SizeOfImage:");
  debug(getPESizeOfImage());

  debug("SizeOfHeaders:");
  debug(getPESizeOfHeaders());

  debug("PECheckSum:");
  debug(getPECheckSum());

  debug("PESubsystem:");
  debug(getPESubsystem());

  debug("PEDllCharacteristics:");
  debug(getPEDllCharacteristics());

  debug("PESizeOfStackReserve:");
  debug(getPESizeOfStackReserve());

  debug("SizeOfStackCommit:");
  debug(getPESizeOfStackCommit());

  debug("SizeOfHeapReserve:");
  debug(getPESizeOfHeapReserve());

  debug("SizeOfHeapCommit:");
  debug(getPESizeOfHeapCommit());

  debug("LoaderFlags:");
  debug(getPELoaderFlags());

  debug("Machine:");
  debug(getPEMachine());

  debug("TimeDateStamp:");
  debug(getPETimeDateStamp());

  debug("PointerToSymbolTable:");
  debug(getPEPointerToSymbolTable());

  debug("NumberOfSymbols:");
  debug(getPENumberOfSymbols());

  debug("SizeOfOptionalHeader:");
  debug(getPESizeOfOptionalHeader());

  debug("Characteristics:");
  debug(getPECharacteristics());

  for (i=0;i<16;i++) {
    debug("ImageData VirtualAddress:");
    debug(getPEDataDirRVA(i));
    debug("ImageData Size:");
    debug(getPEDataDirSize(i));
  }

  debug("Number of sections:");
  debug(getNumberOfSections());

  debug("LFANew");
  debug(getPELFANew());

  debug("EntryPoint:");
  debug(getEntryPoint());

  debug("ExeOffset:");
  debug(getExeOffset());

  debug("ImageBase:");
  debug(getImageBase());

  debug("VirtualEntryPoint:");
  debug(getVirtualEntryPoint());
  debug("Sections:");
  for (i=0;i<getNumberOfSections();i++) {
    char Name[8];
    debug(i);
    readPESectionName(Name, i);
    Name[8] = 0;
    debug_print_str(Name, 8);
    debug("RVA:");
    debug(getSectionRVA(i));
    debug("VirtualSize:");
    debug(getSectionVirtualSize(i));
  }
  return 0;
}
