//===-- SlotIndexes.cpp - Slot Indexes Pass  ------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "slotindexes"

#include "llvm/CodeGen/SlotIndexes.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Target/TargetInstrInfo.h"

using namespace llvm;


// Yep - these are thread safe. See the header for details. 
namespace {


  class EmptyIndexListEntry : public IndexListEntry {
  public:
    EmptyIndexListEntry() : IndexListEntry(EMPTY_KEY) {}
  };

  class TombstoneIndexListEntry : public IndexListEntry {
  public:
    TombstoneIndexListEntry() : IndexListEntry(TOMBSTONE_KEY) {}
  };

  // The following statics are thread safe. They're read only, and you
  // can't step from them to any other list entries.
  ManagedStatic<EmptyIndexListEntry> IndexListEntryEmptyKey;
  ManagedStatic<TombstoneIndexListEntry> IndexListEntryTombstoneKey;
}

char SlotIndexes::ID = 0;
static RegisterPass<SlotIndexes> X("slotindexes", "Slot index numbering");

IndexListEntry* IndexListEntry::getEmptyKeyEntry() {
  return &*IndexListEntryEmptyKey;
}

IndexListEntry* IndexListEntry::getTombstoneKeyEntry() {
  return &*IndexListEntryTombstoneKey;
}


void SlotIndexes::getAnalysisUsage(AnalysisUsage &au) const {
  au.setPreservesAll();
  MachineFunctionPass::getAnalysisUsage(au);
}

void SlotIndexes::releaseMemory() {
  mi2iMap.clear();
  mbb2IdxMap.clear();
  idx2MBBMap.clear();
  terminatorGaps.clear();
  clearList();
}

bool SlotIndexes::runOnMachineFunction(MachineFunction &fn) {

  // Compute numbering as follows:
  // Grab an iterator to the start of the index list.
  // Iterate over all MBBs, and within each MBB all MIs, keeping the MI
  // iterator in lock-step (though skipping it over indexes which have
  // null pointers in the instruction field).
  // At each iteration assert that the instruction pointed to in the index
  // is the same one pointed to by the MI iterator. This 

  // FIXME: This can be simplified. The mi2iMap_, Idx2MBBMap, etc. should
  // only need to be set up once after the first numbering is computed.

  mf = &fn;
  initList();

  // Check that the list contains only the sentinal.
  assert(indexListHead->getNext() == 0 &&
         "Index list non-empty at initial numbering?");
  assert(idx2MBBMap.empty() &&
         "Index -> MBB mapping non-empty at initial numbering?");
  assert(mbb2IdxMap.empty() &&
         "MBB -> Index mapping non-empty at initial numbering?");
  assert(mi2iMap.empty() &&
         "MachineInstr -> Index mapping non-empty at initial numbering?");

  functionSize = 0;
  unsigned index = 0;

  push_back(createEntry(0, index));

  // Iterate over the function.
  for (MachineFunction::iterator mbbItr = mf->begin(), mbbEnd = mf->end();
       mbbItr != mbbEnd; ++mbbItr) {
    MachineBasicBlock *mbb = &*mbbItr;

    // Insert an index for the MBB start.
    SlotIndex blockStartIndex(back(), SlotIndex::LOAD);

    index += SlotIndex::NUM;

    for (MachineBasicBlock::iterator miItr = mbb->begin(), miEnd = mbb->end();
         miItr != miEnd; ++miItr) {
      MachineInstr *mi = miItr;
      if (mi->isDebugValue())
        continue;

      if (miItr == mbb->getFirstTerminator()) {
        push_back(createEntry(0, index));
        terminatorGaps.insert(
          std::make_pair(mbb, SlotIndex(back(), SlotIndex::PHI_BIT)));
        index += SlotIndex::NUM;
      }

      // Insert a store index for the instr.
      push_back(createEntry(mi, index));

      // Save this base index in the maps.
      mi2iMap.insert(
        std::make_pair(mi, SlotIndex(back(), SlotIndex::LOAD)));
 
      ++functionSize;

      unsigned Slots = mi->getDesc().getNumDefs();
      if (Slots == 0)
        Slots = 1;

      index += (Slots + 1) * SlotIndex::NUM;
    }

    if (mbb->getFirstTerminator() == mbb->end()) {
      push_back(createEntry(0, index));
      terminatorGaps.insert(
        std::make_pair(mbb, SlotIndex(back(), SlotIndex::PHI_BIT)));
      index += SlotIndex::NUM;
    }

    // One blank instruction at the end.
    push_back(createEntry(0, index));    

    SlotIndex blockEndIndex(back(), SlotIndex::LOAD);
    mbb2IdxMap.insert(
      std::make_pair(mbb, std::make_pair(blockStartIndex, blockEndIndex)));

    idx2MBBMap.push_back(IdxMBBPair(blockStartIndex, mbb));
  }

  // Sort the Idx2MBBMap
  std::sort(idx2MBBMap.begin(), idx2MBBMap.end(), Idx2MBBCompare());

  DEBUG(dump());

  // And we're done!
  return false;
}

void SlotIndexes::renumberIndexes() {

  // Renumber updates the index of every element of the index list.
  // If all instrs in the function have been allocated an index (which has been
  // placed in the index list in the order of instruction iteration) then the
  // resulting numbering will match what would have been generated by the
  // pass during the initial numbering of the function if the new instructions
  // had been present.

  functionSize = 0;
  unsigned index = 0;

  for (IndexListEntry *curEntry = front(); curEntry != getTail();
       curEntry = curEntry->getNext()) {

    curEntry->setIndex(index);

    if (curEntry->getInstr() == 0) {
      // MBB start entry or terminator gap. Just step index by 1.
      index += SlotIndex::NUM;
    }
    else {
      ++functionSize;
      unsigned Slots = curEntry->getInstr()->getDesc().getNumDefs();
      if (Slots == 0)
        Slots = 1;

      index += (Slots + 1) * SlotIndex::NUM;
    }
  }
}

void SlotIndexes::dump() const {
  for (const IndexListEntry *itr = front(); itr != getTail();
       itr = itr->getNext()) {
    dbgs() << itr->getIndex() << " ";

    if (itr->getInstr() != 0) {
      dbgs() << *itr->getInstr();
    } else {
      dbgs() << "\n";
    }
  }

  for (MBB2IdxMap::const_iterator itr = mbb2IdxMap.begin();
       itr != mbb2IdxMap.end(); ++itr) {
    dbgs() << "MBB " << itr->first->getNumber() << " (" << itr->first << ") - ["
           << itr->second.first << ", " << itr->second.second << "]\n";
  }
}

// Print a SlotIndex to a raw_ostream.
void SlotIndex::print(raw_ostream &os) const {
  os << getIndex();
  if (isPHI())
    os << "*";
}

// Dump a SlotIndex to stderr.
void SlotIndex::dump() const {
  print(dbgs());
  dbgs() << "\n";
}

