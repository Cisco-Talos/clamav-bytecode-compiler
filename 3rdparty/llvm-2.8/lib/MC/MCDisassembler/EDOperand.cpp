//===-- EDOperand.cpp - LLVM Enhanced Disassembler ------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
// 
//===----------------------------------------------------------------------===//
//
// This file implements the Enhanced Disassembly library's operand class.  The
// operand is responsible for allowing evaluation given a particular register 
// context.
//
//===----------------------------------------------------------------------===//

#include "EDOperand.h"
#include "EDDisassembler.h"
#include "EDInst.h"
#include "llvm/MC/EDInstInfo.h"
#include "llvm/MC/MCInst.h"
using namespace llvm;

EDOperand::EDOperand(const EDDisassembler &disassembler,
                     const EDInst &inst,
                     unsigned int opIndex,
                     unsigned int &mcOpIndex) :
  Disassembler(disassembler),
  Inst(inst),
  OpIndex(opIndex),
  MCOpIndex(mcOpIndex) {
  unsigned int numMCOperands = 0;
    
  if (Disassembler.Key.Arch == Triple::x86 ||
      Disassembler.Key.Arch == Triple::x86_64) {
    uint8_t operandType = inst.ThisInstInfo->operandTypes[opIndex];
    
    switch (operandType) {
    default:
      break;
    case kOperandTypeImmediate:
      numMCOperands = 1;
      break;
    case kOperandTypeRegister:
      numMCOperands = 1;
      break;
    case kOperandTypeX86Memory:
      numMCOperands = 5;
      break;
    case kOperandTypeX86EffectiveAddress:
      numMCOperands = 4;
      break;
    case kOperandTypeX86PCRelative:
      numMCOperands = 1;
      break;
    }
  }
  else if (Disassembler.Key.Arch == Triple::arm ||
           Disassembler.Key.Arch == Triple::thumb) {
    uint8_t operandType = inst.ThisInstInfo->operandTypes[opIndex];
    
    switch (operandType) {
    default:
    case kOperandTypeARMRegisterList:
      break;
    case kOperandTypeImmediate:
    case kOperandTypeRegister:
    case kOperandTypeARMBranchTarget:
    case kOperandTypeARMSoImm:
    case kOperandTypeThumb2SoImm:
    case kOperandTypeARMSoImm2Part:
    case kOperandTypeARMPredicate:
    case kOperandTypeThumbITMask:
    case kOperandTypeThumb2AddrModeImm8Offset:
    case kOperandTypeARMTBAddrMode:
    case kOperandTypeThumb2AddrModeImm8s4Offset:
      numMCOperands = 1;
      break;
    case kOperandTypeThumb2SoReg:
    case kOperandTypeARMAddrMode2Offset:
    case kOperandTypeARMAddrMode3Offset:
    case kOperandTypeARMAddrMode4:
    case kOperandTypeARMAddrMode5:
    case kOperandTypeARMAddrModePC:
    case kOperandTypeThumb2AddrModeImm8:
    case kOperandTypeThumb2AddrModeImm12:
    case kOperandTypeThumb2AddrModeImm8s4:
    case kOperandTypeThumbAddrModeRR:
    case kOperandTypeThumbAddrModeSP:
      numMCOperands = 2;
      break;
    case kOperandTypeARMSoReg:
    case kOperandTypeARMAddrMode2:
    case kOperandTypeARMAddrMode3:
    case kOperandTypeThumb2AddrModeSoReg:
    case kOperandTypeThumbAddrModeS1:
    case kOperandTypeThumbAddrModeS2:
    case kOperandTypeThumbAddrModeS4:
    case kOperandTypeARMAddrMode6Offset:
      numMCOperands = 3;
      break;
    case kOperandTypeARMAddrMode6:
      numMCOperands = 4;
      break;
    }
  }
    
  mcOpIndex += numMCOperands;
}

EDOperand::~EDOperand() {
}

int EDOperand::evaluate(uint64_t &result,
                        EDRegisterReaderCallback callback,
                        void *arg) {
  uint8_t operandType = Inst.ThisInstInfo->operandTypes[OpIndex];
  
  switch (Disassembler.Key.Arch) {
  default:
    return -1;  
  case Triple::x86:
  case Triple::x86_64:    
    switch (operandType) {
    default:
      return -1;
    case kOperandTypeImmediate:
      result = Inst.Inst->getOperand(MCOpIndex).getImm();
      return 0;
    case kOperandTypeRegister:
    {
      unsigned reg = Inst.Inst->getOperand(MCOpIndex).getReg();
      return callback(&result, reg, arg);
    }
    case kOperandTypeX86PCRelative:
    {
      int64_t displacement = Inst.Inst->getOperand(MCOpIndex).getImm();
        
      uint64_t ripVal;
        
      // TODO fix how we do this
        
      if (callback(&ripVal, Disassembler.registerIDWithName("RIP"), arg))
        return -1;
        
      result = ripVal + displacement;
      return 0;
    }
    case kOperandTypeX86Memory:
    case kOperandTypeX86EffectiveAddress:  
    {
      unsigned baseReg = Inst.Inst->getOperand(MCOpIndex).getReg();
      uint64_t scaleAmount = Inst.Inst->getOperand(MCOpIndex+1).getImm();
      unsigned indexReg = Inst.Inst->getOperand(MCOpIndex+2).getReg();
      int64_t displacement = Inst.Inst->getOperand(MCOpIndex+3).getImm();
      //unsigned segmentReg = Inst.Inst->getOperand(MCOpIndex+4).getReg();
      
      uint64_t addr = 0;
        
      if (baseReg) {
        uint64_t baseVal;
        if (callback(&baseVal, baseReg, arg))
          return -1;
        addr += baseVal;
      }
        
      if (indexReg) {
        uint64_t indexVal;
        if (callback(&indexVal, indexReg, arg))
          return -1;
        addr += (scaleAmount * indexVal);
      }
       
      addr += displacement;
       
      result = addr;
      return 0;
    }
    }
    break;
  case Triple::arm:
  case Triple::thumb:
    switch (operandType) {
    default:
      return -1;
    case kOperandTypeImmediate:
      result = Inst.Inst->getOperand(MCOpIndex).getImm();
      return 0;
    case kOperandTypeRegister:
    {
      unsigned reg = Inst.Inst->getOperand(MCOpIndex).getReg();
      return callback(&result, reg, arg);
    }
    case kOperandTypeARMBranchTarget:
    {
      int64_t displacement = Inst.Inst->getOperand(MCOpIndex).getImm();
      
      uint64_t pcVal;
      
      if (callback(&pcVal, Disassembler.registerIDWithName("PC"), arg))
        return -1;
      
      result = pcVal + displacement;
      return 0;
    }
    }
  }
  
  return -1;
}

int EDOperand::isRegister() {
  return(Inst.ThisInstInfo->operandFlags[OpIndex] == kOperandTypeRegister);
}

unsigned EDOperand::regVal() {
  return Inst.Inst->getOperand(MCOpIndex).getReg(); 
}

int EDOperand::isImmediate() {
  return(Inst.ThisInstInfo->operandFlags[OpIndex] == kOperandTypeImmediate);
}

uint64_t EDOperand::immediateVal() {
  return Inst.Inst->getOperand(MCOpIndex).getImm();
}

int EDOperand::isMemory() {
  uint8_t operandType = Inst.ThisInstInfo->operandTypes[OpIndex];
    
  switch (operandType) {
  default:
    return 0;
  case kOperandTypeX86Memory:
  case kOperandTypeX86PCRelative:
  case kOperandTypeX86EffectiveAddress:
  case kOperandTypeARMSoReg:
  case kOperandTypeARMSoImm:
  case kOperandTypeARMAddrMode2:
  case kOperandTypeARMAddrMode2Offset:
  case kOperandTypeARMAddrMode3:
  case kOperandTypeARMAddrMode3Offset:
  case kOperandTypeARMAddrMode4:
  case kOperandTypeARMAddrMode5:
  case kOperandTypeARMAddrMode6:
  case kOperandTypeARMAddrModePC:
  case kOperandTypeARMBranchTarget:
  case kOperandTypeThumbAddrModeS1:
  case kOperandTypeThumbAddrModeS2:
  case kOperandTypeThumbAddrModeS4:
  case kOperandTypeThumbAddrModeRR:
  case kOperandTypeThumbAddrModeSP:
  case kOperandTypeThumb2SoImm:
  case kOperandTypeThumb2AddrModeImm8:
  case kOperandTypeThumb2AddrModeImm8Offset:
  case kOperandTypeThumb2AddrModeImm12:
  case kOperandTypeThumb2AddrModeSoReg:
  case kOperandTypeThumb2AddrModeImm8s4:
    return 1;
  }
}

#ifdef __BLOCKS__
struct RegisterReaderWrapper {
  EDOperand::EDRegisterBlock_t regBlock;
};

int readerWrapperCallback(uint64_t *value, 
                          unsigned regID, 
                          void *arg) {
  struct RegisterReaderWrapper *wrapper = (struct RegisterReaderWrapper *)arg;
  return wrapper->regBlock(value, regID);
}

int EDOperand::evaluate(uint64_t &result,
                        EDRegisterBlock_t regBlock) {
  struct RegisterReaderWrapper wrapper;
  wrapper.regBlock = regBlock;
  return evaluate(result, 
                  readerWrapperCallback, 
                  (void*)&wrapper);
}
#endif
