VIRUSNAME_PREFIX("BC.Win32.Patched.User32")
// Author: aCaB, Török Edvin
// Detects a patched user32.dll.
TARGET(1)

// 0.96 has too many bugs
FUNCTIONALITY_LEVEL_MIN(FUNC_LEVEL_096_dev)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(USER32)
DECLARE_SIGNATURE(MSCORP)
DECLARE_SIGNATURE(APPINIT)
DECLARE_SIGNATURE(LOADAPPINIT)
DECLARE_SIGNATURE(WINVER5x)
DECLARE_SIGNATURE(WINVER60)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(USER32, "VI:49006e007400650072006e0061006c004e0061006d006500000075007300650072003300")
DEFINE_SIGNATURE(MSCORP, "VI:43006f006d00700061006e0079004e0061006d006500000000004d006900630072006f0073006f0066007400200043006f00720070006f007200610074006900")
DEFINE_SIGNATURE(WINVER5x, "VI:460069006c006500560065007200730069006f006e000000000035002e00")
DEFINE_SIGNATURE(WINVER60, "VI:460069006c006500560065007200730069006f006e000000000036002e003000")
DEFINE_SIGNATURE(APPINIT, "*:41007000700049006e00690074005f0044004c004c0073")
DEFINE_SIGNATURE(LOADAPPINIT, "*:4c006f006100640041007000700049006e00690074005f0044004c004c00730000")
SIGNATURES_END

PE_UNPACKER_DECLARE

bool logical_trigger(void) {
  if (!matches(Signatures.USER32) || !matches(Signatures.MSCORP))
    return false;
  // Dealing with user32.dll
  if (matches(Signatures.WINVER5x)) {
    // Win2k - WinXP, versions 5.x -> must have AppInit_DLLs key
    // although for win95 we'd never get here because USER32 sig doesn't match
    if (matches(Signatures.APPINIT))
      return false;
  } else if (matches(Signatures.WINVER60)) {
    // Vista has 2 keys
    // AppInit matches twice (since its a substring of LoadAppInit)
    if (count_match(Signatures.APPINIT) == 2 && matches(Signatures.LOADAPPINIT))
      return false;
  } else {
    // Win7 has moved this to kernel32.dll, so nothing to check here
    return false;
  }
  // user32.dll looks patched
  return true;
}

int entrypoint() {
  // use an 0.96.1 API here
  if (engine_functionality_level() < FUNC_LEVEL_096_dev)
    return 0;
  if(!(getPECharacteristics() & 0x2000)) {
    /*debug("Not a dll");*/
    return 0;
  }
  uint32_t exp_rva = getPEDataDirRVA(0);
  if(!exp_rva || getPEDataDirSize(0) < 16) {
    /*debug("No exports #1");*/
    return 0;
  }
  exp_rva += 12;
  if(!readRVA(exp_rva, &exp_rva, 4)) {
    /*debug("No exports #2");*/
    return 0;
  }

  exp_rva = le32_to_host(exp_rva);
  const uint8_t ref[] = "USER\x13\x12.DLL";
  uint8_t match[sizeof(ref)];
  if(!readRVA(exp_rva, match, sizeof(match))) {
    /*debug("No dll name");*/
    return 0;
  }
  uint8_t i;
  for(i=0; i<sizeof(ref); i++) {
    if(ref[i] == (match[i] | ~0x20))
      break;
  }
  if (i == sizeof(ref)) {
    foundVirus("");
  }
  return 0;
}

