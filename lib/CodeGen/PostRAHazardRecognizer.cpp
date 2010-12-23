//===----- PostRAHazardRecognizer.cpp - hazard recognizer -------- ---------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This implements a hazard recognizer using the instructions itineraries
// defined for the current target.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "post-RA-sched"
#include "llvm/CodeGen/PostRAHazardRecognizer.h"
#include "llvm/CodeGen/ScheduleDAG.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetInstrItineraries.h"

using namespace llvm;

PostRAHazardRecognizer::
PostRAHazardRecognizer(const InstrItineraryData &LItinData) :
  ScheduleHazardRecognizer(), ItinData(LItinData) {
  // Determine the maximum depth of any itinerary. This determines the
  // depth of the scoreboard. We always make the scoreboard at least 1
  // cycle deep to avoid dealing with the boundary condition.
  unsigned ScoreboardDepth = 1;
  if (!ItinData.isEmpty()) {
    for (unsigned idx = 0; ; ++idx) {
      if (ItinData.isEndMarker(idx))
        break;

      const InstrStage *IS = ItinData.beginStage(idx);
      const InstrStage *E = ItinData.endStage(idx);
      unsigned ItinDepth = 0;
      for (; IS != E; ++IS)
        ItinDepth += IS->getCycles();

      ScoreboardDepth = std::max(ScoreboardDepth, ItinDepth);
    }
  }

  ReservedScoreboard.reset(ScoreboardDepth);
  RequiredScoreboard.reset(ScoreboardDepth);

  DEBUG(dbgs() << "Using post-ra hazard recognizer: ScoreboardDepth = " 
               << ScoreboardDepth << '\n');
}

void PostRAHazardRecognizer::Reset() {
  RequiredScoreboard.reset();
  ReservedScoreboard.reset();
}

void PostRAHazardRecognizer::ScoreBoard::dump() const {
  dbgs() << "Scoreboard:\n";

  unsigned last = Depth - 1;
  while ((last > 0) && ((*this)[last] == 0))
    last--;

  for (unsigned i = 0; i <= last; i++) {
    unsigned FUs = (*this)[i];
    dbgs() << "\t";
    for (int j = 31; j >= 0; j--)
      dbgs() << ((FUs & (1 << j)) ? '1' : '0');
    dbgs() << '\n';
  }
}

ScheduleHazardRecognizer::HazardType
PostRAHazardRecognizer::getHazardType(SUnit *SU) {
  if (ItinData.isEmpty())
    return NoHazard;

  unsigned cycle = 0;

  // Use the itinerary for the underlying instruction to check for
  // free FU's in the scoreboard at the appropriate future cycles.
  unsigned idx = SU->getInstr()->getDesc().getSchedClass();
  for (const InstrStage *IS = ItinData.beginStage(idx),
         *E = ItinData.endStage(idx); IS != E; ++IS) {
    // We must find one of the stage's units free for every cycle the
    // stage is occupied. FIXME it would be more accurate to find the
    // same unit free in all the cycles.
    for (unsigned int i = 0; i < IS->getCycles(); ++i) {
      assert(((cycle + i) < RequiredScoreboard.getDepth()) &&
             "Scoreboard depth exceeded!");

      unsigned freeUnits = IS->getUnits();
      switch (IS->getReservationKind()) {
      default:
       assert(0 && "Invalid FU reservation");
      case InstrStage::Required:
        // Required FUs conflict with both reserved and required ones
        freeUnits &= ~ReservedScoreboard[cycle + i];
        // FALLTHROUGH
      case InstrStage::Reserved:
        // Reserved FUs can conflict only with required ones.
        freeUnits &= ~RequiredScoreboard[cycle + i];
        break;
      }

      if (!freeUnits) {
        DEBUG(dbgs() << "*** Hazard in cycle " << (cycle + i) << ", ");
        DEBUG(dbgs() << "SU(" << SU->NodeNum << "): ");
        DEBUG(SU->getInstr()->dump());
        return Hazard;
      }
    }

    // Advance the cycle to the next stage.
    cycle += IS->getNextCycles();
  }

  return NoHazard;
}

void PostRAHazardRecognizer::EmitInstruction(SUnit *SU) {
  if (ItinData.isEmpty())
    return;

  unsigned cycle = 0;

  // Use the itinerary for the underlying instruction to reserve FU's
  // in the scoreboard at the appropriate future cycles.
  unsigned idx = SU->getInstr()->getDesc().getSchedClass();
  for (const InstrStage *IS = ItinData.beginStage(idx),
         *E = ItinData.endStage(idx); IS != E; ++IS) {
    // We must reserve one of the stage's units for every cycle the
    // stage is occupied. FIXME it would be more accurate to reserve
    // the same unit free in all the cycles.
    for (unsigned int i = 0; i < IS->getCycles(); ++i) {
      assert(((cycle + i) < RequiredScoreboard.getDepth()) &&
             "Scoreboard depth exceeded!");

      unsigned freeUnits = IS->getUnits();
      switch (IS->getReservationKind()) {
      default:
       assert(0 && "Invalid FU reservation");
      case InstrStage::Required:
        // Required FUs conflict with both reserved and required ones
        freeUnits &= ~ReservedScoreboard[cycle + i];
        // FALLTHROUGH
      case InstrStage::Reserved:
        // Reserved FUs can conflict only with required ones.
        freeUnits &= ~RequiredScoreboard[cycle + i];
        break;
      }

      // reduce to a single unit
      unsigned freeUnit = 0;
      do {
        freeUnit = freeUnits;
        freeUnits = freeUnit & (freeUnit - 1);
      } while (freeUnits);

      assert(freeUnit && "No function unit available!");
      if (IS->getReservationKind() == InstrStage::Required)
        RequiredScoreboard[cycle + i] |= freeUnit;
      else
        ReservedScoreboard[cycle + i] |= freeUnit;
    }

    // Advance the cycle to the next stage.
    cycle += IS->getNextCycles();
  }

  DEBUG(ReservedScoreboard.dump());
  DEBUG(RequiredScoreboard.dump());
}

void PostRAHazardRecognizer::AdvanceCycle() {
  ReservedScoreboard[0] = 0; ReservedScoreboard.advance();
  RequiredScoreboard[0] = 0; RequiredScoreboard.advance();
}
