//===--- SourceManager.cpp - Track and cache source files -----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file implements the SourceManager interface.
//
//===----------------------------------------------------------------------===//

#include "clang/Basic/SourceManager.h"
#include "clang/Basic/SourceManagerInternals.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/FileManager.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/Path.h"
#include <algorithm>
#include <string>
#include <cstring>

using namespace clang;
using namespace SrcMgr;
using llvm::MemoryBuffer;

//===----------------------------------------------------------------------===//
// SourceManager Helper Classes
//===----------------------------------------------------------------------===//

ContentCache::~ContentCache() {
  if (shouldFreeBuffer())
    delete Buffer.getPointer();
}

/// getSizeBytesMapped - Returns the number of bytes actually mapped for
///  this ContentCache.  This can be 0 if the MemBuffer was not actually
///  instantiated.
unsigned ContentCache::getSizeBytesMapped() const {
  return Buffer.getPointer() ? Buffer.getPointer()->getBufferSize() : 0;
}

/// getSize - Returns the size of the content encapsulated by this ContentCache.
///  This can be the size of the source file or the size of an arbitrary
///  scratch buffer.  If the ContentCache encapsulates a source file, that
///  file is not lazily brought in from disk to satisfy this query.
unsigned ContentCache::getSize() const {
  return Buffer.getPointer() ? (unsigned) Buffer.getPointer()->getBufferSize()
                             : (unsigned) Entry->getSize();
}

void ContentCache::replaceBuffer(const llvm::MemoryBuffer *B,
                                 bool DoNotFree) {
  assert(B != Buffer.getPointer());
  
  if (shouldFreeBuffer())
    delete Buffer.getPointer();
  Buffer.setPointer(B);
  Buffer.setInt(DoNotFree? DoNotFreeFlag : 0);
}

const llvm::MemoryBuffer *ContentCache::getBuffer(Diagnostic &Diag,
                                                  const SourceManager &SM,
                                                  SourceLocation Loc,
                                                  bool *Invalid) const {
  if (Invalid)
    *Invalid = false;
      
  // Lazily create the Buffer for ContentCaches that wrap files.
  if (!Buffer.getPointer() && Entry) {
    std::string ErrorStr;
    struct stat FileInfo;
    Buffer.setPointer(MemoryBuffer::getFile(Entry->getName(), &ErrorStr,
                                            Entry->getSize(), &FileInfo));
    
    // If we were unable to open the file, then we are in an inconsistent
    // situation where the content cache referenced a file which no longer
    // exists. Most likely, we were using a stat cache with an invalid entry but
    // the file could also have been removed during processing. Since we can't
    // really deal with this situation, just create an empty buffer.
    //
    // FIXME: This is definitely not ideal, but our immediate clients can't
    // currently handle returning a null entry here. Ideally we should detect
    // that we are in an inconsistent situation and error out as quickly as
    // possible.
    if (!Buffer.getPointer()) {
      const llvm::StringRef FillStr("<<<MISSING SOURCE FILE>>>\n");
      Buffer.setPointer(MemoryBuffer::getNewMemBuffer(Entry->getSize(), 
                                                      "<invalid>"));
      char *Ptr = const_cast<char*>(Buffer.getPointer()->getBufferStart());
      for (unsigned i = 0, e = Entry->getSize(); i != e; ++i)
        Ptr[i] = FillStr[i % FillStr.size()];

      if (Diag.isDiagnosticInFlight())
        Diag.SetDelayedDiagnostic(diag::err_cannot_open_file, 
                                  Entry->getName(), ErrorStr);
      else 
        Diag.Report(FullSourceLoc(Loc, SM), diag::err_cannot_open_file)
          << Entry->getName() << ErrorStr;

      Buffer.setInt(Buffer.getInt() | InvalidFlag);

    // FIXME: This conditionalization is horrible, but we see spurious failures
    // in the test suite due to this warning and no one has had time to hunt it
    // down. So for now, we just don't emit this diagnostic on Win32, and hope
    // nothing bad happens.
    //
    // PR6812.
#if !defined(LLVM_ON_WIN32)
    } else if (FileInfo.st_size != Entry->getSize() ||
               FileInfo.st_mtime != Entry->getModificationTime()) {
      // Check that the file's size and modification time are the same
      // as in the file entry (which may have come from a stat cache).
      if (Diag.isDiagnosticInFlight())
        Diag.SetDelayedDiagnostic(diag::err_file_modified,
                                  Entry->getName());
      else
        Diag.Report(FullSourceLoc(Loc, SM), diag::err_file_modified)
          << Entry->getName();

      Buffer.setInt(Buffer.getInt() | InvalidFlag);
#endif
    }
    
    // If the buffer is valid, check to see if it has a UTF Byte Order Mark
    // (BOM).  We only support UTF-8 without a BOM right now.  See
    // http://en.wikipedia.org/wiki/Byte_order_mark for more information.
    if (!isBufferInvalid()) {
      llvm::StringRef BufStr = Buffer.getPointer()->getBuffer();
      const char *BOM = 0;
      if (BufStr.startswith("\xFE\xBB\xBF"))
        BOM = "UTF-8";
      else if (BufStr.startswith("\xFE\xFF"))
        BOM = "UTF-16 (BE)";
      else if (BufStr.startswith("\xFF\xFE"))
        BOM = "UTF-16 (LE)";
      else if (BufStr.startswith(llvm::StringRef("\x00\x00\xFE\xFF", 4)))
        BOM = "UTF-32 (BE)";
      else if (BufStr.startswith(llvm::StringRef("\xFF\xFE\x00\x00", 4)))
        BOM = "UTF-32 (LE)";
      else if (BufStr.startswith("\x2B\x2F\x76"))
        BOM = "UTF-7";
      else if (BufStr.startswith("\xF7\x64\x4C"))
        BOM = "UTF-1";
      else if (BufStr.startswith("\xDD\x73\x66\x73"))
        BOM = "UTF-EBCDIC";
      else if (BufStr.startswith("\x0E\xFE\xFF"))
        BOM = "SDSU";
      else if (BufStr.startswith("\xFB\xEE\x28"))
        BOM = "BOCU-1";
      else if (BufStr.startswith("\x84\x31\x95\x33"))
        BOM = "BOCU-1";
      
      if (BOM) {
        Diag.Report(FullSourceLoc(Loc, SM), diag::err_unsupported_bom)
          << BOM << Entry->getName();
        Buffer.setInt(1);
      }
    }
  }
  
  if (Invalid)
    *Invalid = isBufferInvalid();
  
  return Buffer.getPointer();
}

unsigned LineTableInfo::getLineTableFilenameID(const char *Ptr, unsigned Len) {
  // Look up the filename in the string table, returning the pre-existing value
  // if it exists.
  llvm::StringMapEntry<unsigned> &Entry =
    FilenameIDs.GetOrCreateValue(Ptr, Ptr+Len, ~0U);
  if (Entry.getValue() != ~0U)
    return Entry.getValue();

  // Otherwise, assign this the next available ID.
  Entry.setValue(FilenamesByID.size());
  FilenamesByID.push_back(&Entry);
  return FilenamesByID.size()-1;
}

/// AddLineNote - Add a line note to the line table that indicates that there
/// is a #line at the specified FID/Offset location which changes the presumed
/// location to LineNo/FilenameID.
void LineTableInfo::AddLineNote(unsigned FID, unsigned Offset,
                                unsigned LineNo, int FilenameID) {
  std::vector<LineEntry> &Entries = LineEntries[FID];

  assert((Entries.empty() || Entries.back().FileOffset < Offset) &&
         "Adding line entries out of order!");

  SrcMgr::CharacteristicKind Kind = SrcMgr::C_User;
  unsigned IncludeOffset = 0;

  if (!Entries.empty()) {
    // If this is a '#line 4' after '#line 42 "foo.h"', make sure to remember
    // that we are still in "foo.h".
    if (FilenameID == -1)
      FilenameID = Entries.back().FilenameID;

    // If we are after a line marker that switched us to system header mode, or
    // that set #include information, preserve it.
    Kind = Entries.back().FileKind;
    IncludeOffset = Entries.back().IncludeOffset;
  }

  Entries.push_back(LineEntry::get(Offset, LineNo, FilenameID, Kind,
                                   IncludeOffset));
}

/// AddLineNote This is the same as the previous version of AddLineNote, but is
/// used for GNU line markers.  If EntryExit is 0, then this doesn't change the
/// presumed #include stack.  If it is 1, this is a file entry, if it is 2 then
/// this is a file exit.  FileKind specifies whether this is a system header or
/// extern C system header.
void LineTableInfo::AddLineNote(unsigned FID, unsigned Offset,
                                unsigned LineNo, int FilenameID,
                                unsigned EntryExit,
                                SrcMgr::CharacteristicKind FileKind) {
  assert(FilenameID != -1 && "Unspecified filename should use other accessor");

  std::vector<LineEntry> &Entries = LineEntries[FID];

  assert((Entries.empty() || Entries.back().FileOffset < Offset) &&
         "Adding line entries out of order!");

  unsigned IncludeOffset = 0;
  if (EntryExit == 0) {  // No #include stack change.
    IncludeOffset = Entries.empty() ? 0 : Entries.back().IncludeOffset;
  } else if (EntryExit == 1) {
    IncludeOffset = Offset-1;
  } else if (EntryExit == 2) {
    assert(!Entries.empty() && Entries.back().IncludeOffset &&
       "PPDirectives should have caught case when popping empty include stack");

    // Get the include loc of the last entries' include loc as our include loc.
    IncludeOffset = 0;
    if (const LineEntry *PrevEntry =
          FindNearestLineEntry(FID, Entries.back().IncludeOffset))
      IncludeOffset = PrevEntry->IncludeOffset;
  }

  Entries.push_back(LineEntry::get(Offset, LineNo, FilenameID, FileKind,
                                   IncludeOffset));
}


/// FindNearestLineEntry - Find the line entry nearest to FID that is before
/// it.  If there is no line entry before Offset in FID, return null.
const LineEntry *LineTableInfo::FindNearestLineEntry(unsigned FID,
                                                     unsigned Offset) {
  const std::vector<LineEntry> &Entries = LineEntries[FID];
  assert(!Entries.empty() && "No #line entries for this FID after all!");

  // It is very common for the query to be after the last #line, check this
  // first.
  if (Entries.back().FileOffset <= Offset)
    return &Entries.back();

  // Do a binary search to find the maximal element that is still before Offset.
  std::vector<LineEntry>::const_iterator I =
    std::upper_bound(Entries.begin(), Entries.end(), Offset);
  if (I == Entries.begin()) return 0;
  return &*--I;
}

/// \brief Add a new line entry that has already been encoded into
/// the internal representation of the line table.
void LineTableInfo::AddEntry(unsigned FID,
                             const std::vector<LineEntry> &Entries) {
  LineEntries[FID] = Entries;
}

/// getLineTableFilenameID - Return the uniqued ID for the specified filename.
///
unsigned SourceManager::getLineTableFilenameID(const char *Ptr, unsigned Len) {
  if (LineTable == 0)
    LineTable = new LineTableInfo();
  return LineTable->getLineTableFilenameID(Ptr, Len);
}


/// AddLineNote - Add a line note to the line table for the FileID and offset
/// specified by Loc.  If FilenameID is -1, it is considered to be
/// unspecified.
void SourceManager::AddLineNote(SourceLocation Loc, unsigned LineNo,
                                int FilenameID) {
  std::pair<FileID, unsigned> LocInfo = getDecomposedInstantiationLoc(Loc);

  const SrcMgr::FileInfo &FileInfo = getSLocEntry(LocInfo.first).getFile();

  // Remember that this file has #line directives now if it doesn't already.
  const_cast<SrcMgr::FileInfo&>(FileInfo).setHasLineDirectives();

  if (LineTable == 0)
    LineTable = new LineTableInfo();
  LineTable->AddLineNote(LocInfo.first.ID, LocInfo.second, LineNo, FilenameID);
}

/// AddLineNote - Add a GNU line marker to the line table.
void SourceManager::AddLineNote(SourceLocation Loc, unsigned LineNo,
                                int FilenameID, bool IsFileEntry,
                                bool IsFileExit, bool IsSystemHeader,
                                bool IsExternCHeader) {
  // If there is no filename and no flags, this is treated just like a #line,
  // which does not change the flags of the previous line marker.
  if (FilenameID == -1) {
    assert(!IsFileEntry && !IsFileExit && !IsSystemHeader && !IsExternCHeader &&
           "Can't set flags without setting the filename!");
    return AddLineNote(Loc, LineNo, FilenameID);
  }

  std::pair<FileID, unsigned> LocInfo = getDecomposedInstantiationLoc(Loc);
  const SrcMgr::FileInfo &FileInfo = getSLocEntry(LocInfo.first).getFile();

  // Remember that this file has #line directives now if it doesn't already.
  const_cast<SrcMgr::FileInfo&>(FileInfo).setHasLineDirectives();

  if (LineTable == 0)
    LineTable = new LineTableInfo();

  SrcMgr::CharacteristicKind FileKind;
  if (IsExternCHeader)
    FileKind = SrcMgr::C_ExternCSystem;
  else if (IsSystemHeader)
    FileKind = SrcMgr::C_System;
  else
    FileKind = SrcMgr::C_User;

  unsigned EntryExit = 0;
  if (IsFileEntry)
    EntryExit = 1;
  else if (IsFileExit)
    EntryExit = 2;

  LineTable->AddLineNote(LocInfo.first.ID, LocInfo.second, LineNo, FilenameID,
                         EntryExit, FileKind);
}

LineTableInfo &SourceManager::getLineTable() {
  if (LineTable == 0)
    LineTable = new LineTableInfo();
  return *LineTable;
}

//===----------------------------------------------------------------------===//
// Private 'Create' methods.
//===----------------------------------------------------------------------===//

SourceManager::~SourceManager() {
  delete LineTable;

  // Delete FileEntry objects corresponding to content caches.  Since the actual
  // content cache objects are bump pointer allocated, we just have to run the
  // dtors, but we call the deallocate method for completeness.
  for (unsigned i = 0, e = MemBufferInfos.size(); i != e; ++i) {
    MemBufferInfos[i]->~ContentCache();
    ContentCacheAlloc.Deallocate(MemBufferInfos[i]);
  }
  for (llvm::DenseMap<const FileEntry*, SrcMgr::ContentCache*>::iterator
       I = FileInfos.begin(), E = FileInfos.end(); I != E; ++I) {
    I->second->~ContentCache();
    ContentCacheAlloc.Deallocate(I->second);
  }
}

void SourceManager::clearIDTables() {
  MainFileID = FileID();
  SLocEntryTable.clear();
  LastLineNoFileIDQuery = FileID();
  LastLineNoContentCache = 0;
  LastFileIDLookup = FileID();

  if (LineTable)
    LineTable->clear();

  // Use up FileID #0 as an invalid instantiation.
  NextOffset = 0;
  createInstantiationLoc(SourceLocation(),SourceLocation(),SourceLocation(), 1);
}

/// getOrCreateContentCache - Create or return a cached ContentCache for the
/// specified file.
const ContentCache *
SourceManager::getOrCreateContentCache(const FileEntry *FileEnt) {
  assert(FileEnt && "Didn't specify a file entry to use?");

  // Do we already have information about this file?
  ContentCache *&Entry = FileInfos[FileEnt];
  if (Entry) return Entry;

  // Nope, create a new Cache entry.  Make sure it is at least 8-byte aligned
  // so that FileInfo can use the low 3 bits of the pointer for its own
  // nefarious purposes.
  unsigned EntryAlign = llvm::AlignOf<ContentCache>::Alignment;
  EntryAlign = std::max(8U, EntryAlign);
  Entry = ContentCacheAlloc.Allocate<ContentCache>(1, EntryAlign);
  new (Entry) ContentCache(FileEnt);
  return Entry;
}


/// createMemBufferContentCache - Create a new ContentCache for the specified
///  memory buffer.  This does no caching.
const ContentCache*
SourceManager::createMemBufferContentCache(const MemoryBuffer *Buffer) {
  // Add a new ContentCache to the MemBufferInfos list and return it.  Make sure
  // it is at least 8-byte aligned so that FileInfo can use the low 3 bits of
  // the pointer for its own nefarious purposes.
  unsigned EntryAlign = llvm::AlignOf<ContentCache>::Alignment;
  EntryAlign = std::max(8U, EntryAlign);
  ContentCache *Entry = ContentCacheAlloc.Allocate<ContentCache>(1, EntryAlign);
  new (Entry) ContentCache();
  MemBufferInfos.push_back(Entry);
  Entry->setBuffer(Buffer);
  return Entry;
}

void SourceManager::PreallocateSLocEntries(ExternalSLocEntrySource *Source,
                                           unsigned NumSLocEntries,
                                           unsigned NextOffset) {
  ExternalSLocEntries = Source;
  this->NextOffset = NextOffset;
  unsigned CurPrealloc = SLocEntryLoaded.size();
  // If we've ever preallocated, we must not count the dummy entry.
  if (CurPrealloc) --CurPrealloc;
  SLocEntryLoaded.resize(NumSLocEntries + 1);
  SLocEntryLoaded[0] = true;
  SLocEntryTable.resize(SLocEntryTable.size() + NumSLocEntries - CurPrealloc);
}

void SourceManager::ClearPreallocatedSLocEntries() {
  unsigned I = 0;
  for (unsigned N = SLocEntryLoaded.size(); I != N; ++I)
    if (!SLocEntryLoaded[I])
      break;

  // We've already loaded all preallocated source location entries.
  if (I == SLocEntryLoaded.size())
    return;

  // Remove everything from location I onward.
  SLocEntryTable.resize(I);
  SLocEntryLoaded.clear();
  ExternalSLocEntries = 0;
}


//===----------------------------------------------------------------------===//
// Methods to create new FileID's and instantiations.
//===----------------------------------------------------------------------===//

/// createFileID - Create a new FileID for the specified ContentCache and
/// include position.  This works regardless of whether the ContentCache
/// corresponds to a file or some other input source.
FileID SourceManager::createFileID(const ContentCache *File,
                                   SourceLocation IncludePos,
                                   SrcMgr::CharacteristicKind FileCharacter,
                                   unsigned PreallocatedID,
                                   unsigned Offset) {
  if (PreallocatedID) {
    // If we're filling in a preallocated ID, just load in the file
    // entry and return.
    assert(PreallocatedID < SLocEntryLoaded.size() &&
           "Preallocate ID out-of-range");
    assert(!SLocEntryLoaded[PreallocatedID] &&
           "Source location entry already loaded");
    assert(Offset && "Preallocate source location cannot have zero offset");
    SLocEntryTable[PreallocatedID]
      = SLocEntry::get(Offset, FileInfo::get(IncludePos, File, FileCharacter));
    SLocEntryLoaded[PreallocatedID] = true;
    FileID FID = FileID::get(PreallocatedID);
    return FID;
  }

  SLocEntryTable.push_back(SLocEntry::get(NextOffset,
                                          FileInfo::get(IncludePos, File,
                                                        FileCharacter)));
  unsigned FileSize = File->getSize();
  assert(NextOffset+FileSize+1 > NextOffset && "Ran out of source locations!");
  NextOffset += FileSize+1;

  // Set LastFileIDLookup to the newly created file.  The next getFileID call is
  // almost guaranteed to be from that file.
  FileID FID = FileID::get(SLocEntryTable.size()-1);
  return LastFileIDLookup = FID;
}

/// createInstantiationLoc - Return a new SourceLocation that encodes the fact
/// that a token from SpellingLoc should actually be referenced from
/// InstantiationLoc.
SourceLocation SourceManager::createInstantiationLoc(SourceLocation SpellingLoc,
                                                     SourceLocation ILocStart,
                                                     SourceLocation ILocEnd,
                                                     unsigned TokLength,
                                                     unsigned PreallocatedID,
                                                     unsigned Offset) {
  InstantiationInfo II = InstantiationInfo::get(ILocStart,ILocEnd, SpellingLoc);
  if (PreallocatedID) {
    // If we're filling in a preallocated ID, just load in the
    // instantiation entry and return.
    assert(PreallocatedID < SLocEntryLoaded.size() &&
           "Preallocate ID out-of-range");
    assert(!SLocEntryLoaded[PreallocatedID] &&
           "Source location entry already loaded");
    assert(Offset && "Preallocate source location cannot have zero offset");
    SLocEntryTable[PreallocatedID] = SLocEntry::get(Offset, II);
    SLocEntryLoaded[PreallocatedID] = true;
    return SourceLocation::getMacroLoc(Offset);
  }
  SLocEntryTable.push_back(SLocEntry::get(NextOffset, II));
  assert(NextOffset+TokLength+1 > NextOffset && "Ran out of source locations!");
  NextOffset += TokLength+1;
  return SourceLocation::getMacroLoc(NextOffset-(TokLength+1));
}

const llvm::MemoryBuffer *
SourceManager::getMemoryBufferForFile(const FileEntry *File,
                                      bool *Invalid) {
  const SrcMgr::ContentCache *IR = getOrCreateContentCache(File);
  assert(IR && "getOrCreateContentCache() cannot return NULL");
  return IR->getBuffer(Diag, *this, SourceLocation(), Invalid);
}

bool SourceManager::overrideFileContents(const FileEntry *SourceFile,
                                         const llvm::MemoryBuffer *Buffer,
                                         bool DoNotFree) {
  const SrcMgr::ContentCache *IR = getOrCreateContentCache(SourceFile);
  if (IR == 0)
    return true;

  const_cast<SrcMgr::ContentCache *>(IR)->replaceBuffer(Buffer, DoNotFree);
  return false;
}

llvm::StringRef SourceManager::getBufferData(FileID FID, bool *Invalid) const {
  bool MyInvalid = false;
  const llvm::MemoryBuffer *Buf = getBuffer(FID, &MyInvalid);
  if (Invalid)
    *Invalid = MyInvalid;

  if (MyInvalid)
    return "";
  
  return Buf->getBuffer();
}

//===----------------------------------------------------------------------===//
// SourceLocation manipulation methods.
//===----------------------------------------------------------------------===//

/// getFileIDSlow - Return the FileID for a SourceLocation.  This is a very hot
/// method that is used for all SourceManager queries that start with a
/// SourceLocation object.  It is responsible for finding the entry in
/// SLocEntryTable which contains the specified location.
///
FileID SourceManager::getFileIDSlow(unsigned SLocOffset) const {
  assert(SLocOffset && "Invalid FileID");

  // After the first and second level caches, I see two common sorts of
  // behavior: 1) a lot of searched FileID's are "near" the cached file location
  // or are "near" the cached instantiation location.  2) others are just
  // completely random and may be a very long way away.
  //
  // To handle this, we do a linear search for up to 8 steps to catch #1 quickly
  // then we fall back to a less cache efficient, but more scalable, binary
  // search to find the location.

  // See if this is near the file point - worst case we start scanning from the
  // most newly created FileID.
  std::vector<SrcMgr::SLocEntry>::const_iterator I;

  if (SLocEntryTable[LastFileIDLookup.ID].getOffset() < SLocOffset) {
    // Neither loc prunes our search.
    I = SLocEntryTable.end();
  } else {
    // Perhaps it is near the file point.
    I = SLocEntryTable.begin()+LastFileIDLookup.ID;
  }

  // Find the FileID that contains this.  "I" is an iterator that points to a
  // FileID whose offset is known to be larger than SLocOffset.
  unsigned NumProbes = 0;
  while (1) {
    --I;
    if (ExternalSLocEntries)
      getSLocEntry(FileID::get(I - SLocEntryTable.begin()));
    if (I->getOffset() <= SLocOffset) {
#if 0
      printf("lin %d -> %d [%s] %d %d\n", SLocOffset,
             I-SLocEntryTable.begin(),
             I->isInstantiation() ? "inst" : "file",
             LastFileIDLookup.ID,  int(SLocEntryTable.end()-I));
#endif
      FileID Res = FileID::get(I-SLocEntryTable.begin());

      // If this isn't an instantiation, remember it.  We have good locality
      // across FileID lookups.
      if (!I->isInstantiation())
        LastFileIDLookup = Res;
      NumLinearScans += NumProbes+1;
      return Res;
    }
    if (++NumProbes == 8)
      break;
  }

  // Convert "I" back into an index.  We know that it is an entry whose index is
  // larger than the offset we are looking for.
  unsigned GreaterIndex = I-SLocEntryTable.begin();
  // LessIndex - This is the lower bound of the range that we're searching.
  // We know that the offset corresponding to the FileID is is less than
  // SLocOffset.
  unsigned LessIndex = 0;
  NumProbes = 0;
  while (1) {
    unsigned MiddleIndex = (GreaterIndex-LessIndex)/2+LessIndex;
    unsigned MidOffset = getSLocEntry(FileID::get(MiddleIndex)).getOffset();

    ++NumProbes;

    // If the offset of the midpoint is too large, chop the high side of the
    // range to the midpoint.
    if (MidOffset > SLocOffset) {
      GreaterIndex = MiddleIndex;
      continue;
    }

    // If the middle index contains the value, succeed and return.
    if (isOffsetInFileID(FileID::get(MiddleIndex), SLocOffset)) {
#if 0
      printf("bin %d -> %d [%s] %d %d\n", SLocOffset,
             I-SLocEntryTable.begin(),
             I->isInstantiation() ? "inst" : "file",
             LastFileIDLookup.ID, int(SLocEntryTable.end()-I));
#endif
      FileID Res = FileID::get(MiddleIndex);

      // If this isn't an instantiation, remember it.  We have good locality
      // across FileID lookups.
      if (!I->isInstantiation())
        LastFileIDLookup = Res;
      NumBinaryProbes += NumProbes;
      return Res;
    }

    // Otherwise, move the low-side up to the middle index.
    LessIndex = MiddleIndex;
  }
}

SourceLocation SourceManager::
getInstantiationLocSlowCase(SourceLocation Loc) const {
  do {
    // Note: If Loc indicates an offset into a token that came from a macro
    // expansion (e.g. the 5th character of the token) we do not want to add
    // this offset when going to the instantiation location.  The instatiation
    // location is the macro invocation, which the offset has nothing to do
    // with.  This is unlike when we get the spelling loc, because the offset
    // directly correspond to the token whose spelling we're inspecting.
    Loc = getSLocEntry(getFileID(Loc)).getInstantiation()
                   .getInstantiationLocStart();
  } while (!Loc.isFileID());

  return Loc;
}

SourceLocation SourceManager::getSpellingLocSlowCase(SourceLocation Loc) const {
  do {
    std::pair<FileID, unsigned> LocInfo = getDecomposedLoc(Loc);
    Loc = getSLocEntry(LocInfo.first).getInstantiation().getSpellingLoc();
    Loc = Loc.getFileLocWithOffset(LocInfo.second);
  } while (!Loc.isFileID());
  return Loc;
}


std::pair<FileID, unsigned>
SourceManager::getDecomposedInstantiationLocSlowCase(const SrcMgr::SLocEntry *E,
                                                     unsigned Offset) const {
  // If this is an instantiation record, walk through all the instantiation
  // points.
  FileID FID;
  SourceLocation Loc;
  do {
    Loc = E->getInstantiation().getInstantiationLocStart();

    FID = getFileID(Loc);
    E = &getSLocEntry(FID);
    Offset += Loc.getOffset()-E->getOffset();
  } while (!Loc.isFileID());

  return std::make_pair(FID, Offset);
}

std::pair<FileID, unsigned>
SourceManager::getDecomposedSpellingLocSlowCase(const SrcMgr::SLocEntry *E,
                                                unsigned Offset) const {
  // If this is an instantiation record, walk through all the instantiation
  // points.
  FileID FID;
  SourceLocation Loc;
  do {
    Loc = E->getInstantiation().getSpellingLoc();

    FID = getFileID(Loc);
    E = &getSLocEntry(FID);
    Offset += Loc.getOffset()-E->getOffset();
  } while (!Loc.isFileID());

  return std::make_pair(FID, Offset);
}

/// getImmediateSpellingLoc - Given a SourceLocation object, return the
/// spelling location referenced by the ID.  This is the first level down
/// towards the place where the characters that make up the lexed token can be
/// found.  This should not generally be used by clients.
SourceLocation SourceManager::getImmediateSpellingLoc(SourceLocation Loc) const{
  if (Loc.isFileID()) return Loc;
  std::pair<FileID, unsigned> LocInfo = getDecomposedLoc(Loc);
  Loc = getSLocEntry(LocInfo.first).getInstantiation().getSpellingLoc();
  return Loc.getFileLocWithOffset(LocInfo.second);
}


/// getImmediateInstantiationRange - Loc is required to be an instantiation
/// location.  Return the start/end of the instantiation information.
std::pair<SourceLocation,SourceLocation>
SourceManager::getImmediateInstantiationRange(SourceLocation Loc) const {
  assert(Loc.isMacroID() && "Not an instantiation loc!");
  const InstantiationInfo &II = getSLocEntry(getFileID(Loc)).getInstantiation();
  return II.getInstantiationLocRange();
}

/// getInstantiationRange - Given a SourceLocation object, return the
/// range of tokens covered by the instantiation in the ultimate file.
std::pair<SourceLocation,SourceLocation>
SourceManager::getInstantiationRange(SourceLocation Loc) const {
  if (Loc.isFileID()) return std::make_pair(Loc, Loc);

  std::pair<SourceLocation,SourceLocation> Res =
    getImmediateInstantiationRange(Loc);

  // Fully resolve the start and end locations to their ultimate instantiation
  // points.
  while (!Res.first.isFileID())
    Res.first = getImmediateInstantiationRange(Res.first).first;
  while (!Res.second.isFileID())
    Res.second = getImmediateInstantiationRange(Res.second).second;
  return Res;
}



//===----------------------------------------------------------------------===//
// Queries about the code at a SourceLocation.
//===----------------------------------------------------------------------===//

/// getCharacterData - Return a pointer to the start of the specified location
/// in the appropriate MemoryBuffer.
const char *SourceManager::getCharacterData(SourceLocation SL,
                                            bool *Invalid) const {
  // Note that this is a hot function in the getSpelling() path, which is
  // heavily used by -E mode.
  std::pair<FileID, unsigned> LocInfo = getDecomposedSpellingLoc(SL);

  // Note that calling 'getBuffer()' may lazily page in a source file.
  bool CharDataInvalid = false;
  const llvm::MemoryBuffer *Buffer
    = getSLocEntry(LocInfo.first).getFile().getContentCache()
    ->getBuffer(Diag, *this, SourceLocation(), &CharDataInvalid);
  if (Invalid)
    *Invalid = CharDataInvalid;
  return Buffer->getBufferStart() + (CharDataInvalid? 0 : LocInfo.second);
}


/// getColumnNumber - Return the column # for the specified file position.
/// this is significantly cheaper to compute than the line number.
unsigned SourceManager::getColumnNumber(FileID FID, unsigned FilePos,
                                        bool *Invalid) const {
  bool MyInvalid = false;
  const char *Buf = getBuffer(FID, &MyInvalid)->getBufferStart();
  if (Invalid)
    *Invalid = MyInvalid;

  if (MyInvalid)
    return 1;

  unsigned LineStart = FilePos;
  while (LineStart && Buf[LineStart-1] != '\n' && Buf[LineStart-1] != '\r')
    --LineStart;
  return FilePos-LineStart+1;
}

unsigned SourceManager::getSpellingColumnNumber(SourceLocation Loc,
                                                bool *Invalid) const {
  if (Loc.isInvalid()) return 0;
  std::pair<FileID, unsigned> LocInfo = getDecomposedSpellingLoc(Loc);
  return getColumnNumber(LocInfo.first, LocInfo.second, Invalid);
}

unsigned SourceManager::getInstantiationColumnNumber(SourceLocation Loc,
                                                     bool *Invalid) const {
  if (Loc.isInvalid()) return 0;
  std::pair<FileID, unsigned> LocInfo = getDecomposedInstantiationLoc(Loc);
  return getColumnNumber(LocInfo.first, LocInfo.second, Invalid);
}

static DISABLE_INLINE void
ComputeLineNumbers(Diagnostic &Diag, ContentCache *FI,
                   llvm::BumpPtrAllocator &Alloc,
                   const SourceManager &SM, bool &Invalid);
static void ComputeLineNumbers(Diagnostic &Diag, ContentCache *FI, 
                               llvm::BumpPtrAllocator &Alloc,
                               const SourceManager &SM, bool &Invalid) {
  // Note that calling 'getBuffer()' may lazily page in the file.
  const MemoryBuffer *Buffer = FI->getBuffer(Diag, SM, SourceLocation(),
                                             &Invalid);
  if (Invalid)
    return;

  // Find the file offsets of all of the *physical* source lines.  This does
  // not look at trigraphs, escaped newlines, or anything else tricky.
  std::vector<unsigned> LineOffsets;

  // Line #1 starts at char 0.
  LineOffsets.push_back(0);

  const unsigned char *Buf = (const unsigned char *)Buffer->getBufferStart();
  const unsigned char *End = (const unsigned char *)Buffer->getBufferEnd();
  unsigned Offs = 0;
  while (1) {
    // Skip over the contents of the line.
    // TODO: Vectorize this?  This is very performance sensitive for programs
    // with lots of diagnostics and in -E mode.
    const unsigned char *NextBuf = (const unsigned char *)Buf;
    while (*NextBuf != '\n' && *NextBuf != '\r' && *NextBuf != '\0')
      ++NextBuf;
    Offs += NextBuf-Buf;
    Buf = NextBuf;

    if (Buf[0] == '\n' || Buf[0] == '\r') {
      // If this is \n\r or \r\n, skip both characters.
      if ((Buf[1] == '\n' || Buf[1] == '\r') && Buf[0] != Buf[1])
        ++Offs, ++Buf;
      ++Offs, ++Buf;
      LineOffsets.push_back(Offs);
    } else {
      // Otherwise, this is a null.  If end of file, exit.
      if (Buf == End) break;
      // Otherwise, skip the null.
      ++Offs, ++Buf;
    }
  }

  // Copy the offsets into the FileInfo structure.
  FI->NumLines = LineOffsets.size();
  FI->SourceLineCache = Alloc.Allocate<unsigned>(LineOffsets.size());
  std::copy(LineOffsets.begin(), LineOffsets.end(), FI->SourceLineCache);
}

/// getLineNumber - Given a SourceLocation, return the spelling line number
/// for the position indicated.  This requires building and caching a table of
/// line offsets for the MemoryBuffer, so this is not cheap: use only when
/// about to emit a diagnostic.
unsigned SourceManager::getLineNumber(FileID FID, unsigned FilePos, 
                                      bool *Invalid) const {
  ContentCache *Content;
  if (LastLineNoFileIDQuery == FID)
    Content = LastLineNoContentCache;
  else
    Content = const_cast<ContentCache*>(getSLocEntry(FID)
                                        .getFile().getContentCache());

  // If this is the first use of line information for this buffer, compute the
  /// SourceLineCache for it on demand.
  if (Content->SourceLineCache == 0) {
    bool MyInvalid = false;
    ComputeLineNumbers(Diag, Content, ContentCacheAlloc, *this, MyInvalid);
    if (Invalid)
      *Invalid = MyInvalid;
    if (MyInvalid)
      return 1;
  } else if (Invalid)
    *Invalid = false;

  // Okay, we know we have a line number table.  Do a binary search to find the
  // line number that this character position lands on.
  unsigned *SourceLineCache = Content->SourceLineCache;
  unsigned *SourceLineCacheStart = SourceLineCache;
  unsigned *SourceLineCacheEnd = SourceLineCache + Content->NumLines;

  unsigned QueriedFilePos = FilePos+1;

  // FIXME: I would like to be convinced that this code is worth being as
  // complicated as it is, binary search isn't that slow.
  //
  // If it is worth being optimized, then in my opinion it could be more
  // performant, simpler, and more obviously correct by just "galloping" outward
  // from the queried file position. In fact, this could be incorporated into a
  // generic algorithm such as lower_bound_with_hint.
  //
  // If someone gives me a test case where this matters, and I will do it! - DWD

  // If the previous query was to the same file, we know both the file pos from
  // that query and the line number returned.  This allows us to narrow the
  // search space from the entire file to something near the match.
  if (LastLineNoFileIDQuery == FID) {
    if (QueriedFilePos >= LastLineNoFilePos) {
      // FIXME: Potential overflow?
      SourceLineCache = SourceLineCache+LastLineNoResult-1;

      // The query is likely to be nearby the previous one.  Here we check to
      // see if it is within 5, 10 or 20 lines.  It can be far away in cases
      // where big comment blocks and vertical whitespace eat up lines but
      // contribute no tokens.
      if (SourceLineCache+5 < SourceLineCacheEnd) {
        if (SourceLineCache[5] > QueriedFilePos)
          SourceLineCacheEnd = SourceLineCache+5;
        else if (SourceLineCache+10 < SourceLineCacheEnd) {
          if (SourceLineCache[10] > QueriedFilePos)
            SourceLineCacheEnd = SourceLineCache+10;
          else if (SourceLineCache+20 < SourceLineCacheEnd) {
            if (SourceLineCache[20] > QueriedFilePos)
              SourceLineCacheEnd = SourceLineCache+20;
          }
        }
      }
    } else {
      if (LastLineNoResult < Content->NumLines)
        SourceLineCacheEnd = SourceLineCache+LastLineNoResult+1;
    }
  }

  // If the spread is large, do a "radix" test as our initial guess, based on
  // the assumption that lines average to approximately the same length.
  // NOTE: This is currently disabled, as it does not appear to be profitable in
  // initial measurements.
  if (0 && SourceLineCacheEnd-SourceLineCache > 20) {
    unsigned FileLen = Content->SourceLineCache[Content->NumLines-1];

    // Take a stab at guessing where it is.
    unsigned ApproxPos = Content->NumLines*QueriedFilePos / FileLen;

    // Check for -10 and +10 lines.
    unsigned LowerBound = std::max(int(ApproxPos-10), 0);
    unsigned UpperBound = std::min(ApproxPos+10, FileLen);

    // If the computed lower bound is less than the query location, move it in.
    if (SourceLineCache < SourceLineCacheStart+LowerBound &&
        SourceLineCacheStart[LowerBound] < QueriedFilePos)
      SourceLineCache = SourceLineCacheStart+LowerBound;

    // If the computed upper bound is greater than the query location, move it.
    if (SourceLineCacheEnd > SourceLineCacheStart+UpperBound &&
        SourceLineCacheStart[UpperBound] >= QueriedFilePos)
      SourceLineCacheEnd = SourceLineCacheStart+UpperBound;
  }

  unsigned *Pos
    = std::lower_bound(SourceLineCache, SourceLineCacheEnd, QueriedFilePos);
  unsigned LineNo = Pos-SourceLineCacheStart;

  LastLineNoFileIDQuery = FID;
  LastLineNoContentCache = Content;
  LastLineNoFilePos = QueriedFilePos;
  LastLineNoResult = LineNo;
  return LineNo;
}

unsigned SourceManager::getInstantiationLineNumber(SourceLocation Loc, 
                                                   bool *Invalid) const {
  if (Loc.isInvalid()) return 0;
  std::pair<FileID, unsigned> LocInfo = getDecomposedInstantiationLoc(Loc);
  return getLineNumber(LocInfo.first, LocInfo.second);
}
unsigned SourceManager::getSpellingLineNumber(SourceLocation Loc, 
                                              bool *Invalid) const {
  if (Loc.isInvalid()) return 0;
  std::pair<FileID, unsigned> LocInfo = getDecomposedSpellingLoc(Loc);
  return getLineNumber(LocInfo.first, LocInfo.second);
}

/// getFileCharacteristic - return the file characteristic of the specified
/// source location, indicating whether this is a normal file, a system
/// header, or an "implicit extern C" system header.
///
/// This state can be modified with flags on GNU linemarker directives like:
///   # 4 "foo.h" 3
/// which changes all source locations in the current file after that to be
/// considered to be from a system header.
SrcMgr::CharacteristicKind
SourceManager::getFileCharacteristic(SourceLocation Loc) const {
  assert(!Loc.isInvalid() && "Can't get file characteristic of invalid loc!");
  std::pair<FileID, unsigned> LocInfo = getDecomposedInstantiationLoc(Loc);
  const SrcMgr::FileInfo &FI = getSLocEntry(LocInfo.first).getFile();

  // If there are no #line directives in this file, just return the whole-file
  // state.
  if (!FI.hasLineDirectives())
    return FI.getFileCharacteristic();

  assert(LineTable && "Can't have linetable entries without a LineTable!");
  // See if there is a #line directive before the location.
  const LineEntry *Entry =
    LineTable->FindNearestLineEntry(LocInfo.first.ID, LocInfo.second);

  // If this is before the first line marker, use the file characteristic.
  if (!Entry)
    return FI.getFileCharacteristic();

  return Entry->FileKind;
}

/// Return the filename or buffer identifier of the buffer the location is in.
/// Note that this name does not respect #line directives.  Use getPresumedLoc
/// for normal clients.
const char *SourceManager::getBufferName(SourceLocation Loc, 
                                         bool *Invalid) const {
  if (Loc.isInvalid()) return "<invalid loc>";

  return getBuffer(getFileID(Loc), Invalid)->getBufferIdentifier();
}


/// getPresumedLoc - This method returns the "presumed" location of a
/// SourceLocation specifies.  A "presumed location" can be modified by #line
/// or GNU line marker directives.  This provides a view on the data that a
/// user should see in diagnostics, for example.
///
/// Note that a presumed location is always given as the instantiation point
/// of an instantiation location, not at the spelling location.
PresumedLoc SourceManager::getPresumedLoc(SourceLocation Loc) const {
  if (Loc.isInvalid()) return PresumedLoc();

  // Presumed locations are always for instantiation points.
  std::pair<FileID, unsigned> LocInfo = getDecomposedInstantiationLoc(Loc);

  const SrcMgr::FileInfo &FI = getSLocEntry(LocInfo.first).getFile();
  const SrcMgr::ContentCache *C = FI.getContentCache();

  // To get the source name, first consult the FileEntry (if one exists)
  // before the MemBuffer as this will avoid unnecessarily paging in the
  // MemBuffer.
  const char *Filename;
  if (C->Entry)
    Filename = C->Entry->getName();
  else
    Filename = C->getBuffer(Diag, *this)->getBufferIdentifier();
  unsigned LineNo = getLineNumber(LocInfo.first, LocInfo.second);
  unsigned ColNo  = getColumnNumber(LocInfo.first, LocInfo.second);
  SourceLocation IncludeLoc = FI.getIncludeLoc();

  // If we have #line directives in this file, update and overwrite the physical
  // location info if appropriate.
  if (FI.hasLineDirectives()) {
    assert(LineTable && "Can't have linetable entries without a LineTable!");
    // See if there is a #line directive before this.  If so, get it.
    if (const LineEntry *Entry =
          LineTable->FindNearestLineEntry(LocInfo.first.ID, LocInfo.second)) {
      // If the LineEntry indicates a filename, use it.
      if (Entry->FilenameID != -1)
        Filename = LineTable->getFilename(Entry->FilenameID);

      // Use the line number specified by the LineEntry.  This line number may
      // be multiple lines down from the line entry.  Add the difference in
      // physical line numbers from the query point and the line marker to the
      // total.
      unsigned MarkerLineNo = getLineNumber(LocInfo.first, Entry->FileOffset);
      LineNo = Entry->LineNo + (LineNo-MarkerLineNo-1);

      // Note that column numbers are not molested by line markers.

      // Handle virtual #include manipulation.
      if (Entry->IncludeOffset) {
        IncludeLoc = getLocForStartOfFile(LocInfo.first);
        IncludeLoc = IncludeLoc.getFileLocWithOffset(Entry->IncludeOffset);
      }
    }
  }

  return PresumedLoc(Filename, LineNo, ColNo, IncludeLoc);
}

//===----------------------------------------------------------------------===//
// Other miscellaneous methods.
//===----------------------------------------------------------------------===//

/// \brief Get the source location for the given file:line:col triplet.
///
/// If the source file is included multiple times, the source location will
/// be based upon the first inclusion.
SourceLocation SourceManager::getLocation(const FileEntry *SourceFile,
                                          unsigned Line, unsigned Col) const {
  assert(SourceFile && "Null source file!");
  assert(Line && Col && "Line and column should start from 1!");

  fileinfo_iterator FI = FileInfos.find(SourceFile);
  if (FI == FileInfos.end())
    return SourceLocation();
  ContentCache *Content = FI->second;

  // If this is the first use of line information for this buffer, compute the
  /// SourceLineCache for it on demand.
  if (Content->SourceLineCache == 0) {
    bool MyInvalid = false;
    ComputeLineNumbers(Diag, Content, ContentCacheAlloc, *this, MyInvalid);
    if (MyInvalid)
      return SourceLocation();
  }

  // Find the first file ID that corresponds to the given file.
  FileID FirstFID;

  // First, check the main file ID, since it is common to look for a
  // location in the main file.
  if (!MainFileID.isInvalid()) {
    const SLocEntry &MainSLoc = getSLocEntry(MainFileID);
    if (MainSLoc.isFile() && MainSLoc.getFile().getContentCache() == Content)
      FirstFID = MainFileID;
  }

  if (FirstFID.isInvalid()) {
    // The location we're looking for isn't in the main file; look
    // through all of the source locations.
    for (unsigned I = 0, N = sloc_entry_size(); I != N; ++I) {
      const SLocEntry &SLoc = getSLocEntry(I);
      if (SLoc.isFile() && SLoc.getFile().getContentCache() == Content) {
        FirstFID = FileID::get(I);
        break;
      }
    }
  }
    
  if (FirstFID.isInvalid())
    return SourceLocation();

  if (Line > Content->NumLines) {
    unsigned Size = Content->getBuffer(Diag, *this)->getBufferSize();
    if (Size > 0)
      --Size;
    return getLocForStartOfFile(FirstFID).getFileLocWithOffset(Size);
  }

  unsigned FilePos = Content->SourceLineCache[Line - 1];
  const char *Buf = Content->getBuffer(Diag, *this)->getBufferStart() + FilePos;
  unsigned BufLength = Content->getBuffer(Diag, *this)->getBufferEnd() - Buf;
  unsigned i = 0;

  // Check that the given column is valid.
  while (i < BufLength-1 && i < Col-1 && Buf[i] != '\n' && Buf[i] != '\r')
    ++i;
  if (i < Col-1)
    return getLocForStartOfFile(FirstFID).getFileLocWithOffset(FilePos + i);

  return getLocForStartOfFile(FirstFID).getFileLocWithOffset(FilePos + Col - 1);
}

/// Given a decomposed source location, move it up the include/instantiation
/// stack to the parent source location.  If this is possible, return the
/// decomposed version of the parent in Loc and return false.  If Loc is the
/// top-level entry, return true and don't modify it.
static bool MoveUpIncludeHierarchy(std::pair<FileID, unsigned> &Loc,
                                   const SourceManager &SM) {
  SourceLocation UpperLoc;
  const SrcMgr::SLocEntry &Entry = SM.getSLocEntry(Loc.first);
  if (Entry.isInstantiation())
    UpperLoc = Entry.getInstantiation().getInstantiationLocStart();
  else
    UpperLoc = Entry.getFile().getIncludeLoc();
  
  if (UpperLoc.isInvalid())
    return true; // We reached the top.
  
  Loc = SM.getDecomposedLoc(UpperLoc);
  return false;
}
  

/// \brief Determines the order of 2 source locations in the translation unit.
///
/// \returns true if LHS source location comes before RHS, false otherwise.
bool SourceManager::isBeforeInTranslationUnit(SourceLocation LHS,
                                              SourceLocation RHS) const {
  assert(LHS.isValid() && RHS.isValid() && "Passed invalid source location!");
  if (LHS == RHS)
    return false;

  std::pair<FileID, unsigned> LOffs = getDecomposedLoc(LHS);
  std::pair<FileID, unsigned> ROffs = getDecomposedLoc(RHS);

  // If the source locations are in the same file, just compare offsets.
  if (LOffs.first == ROffs.first)
    return LOffs.second < ROffs.second;

  // If we are comparing a source location with multiple locations in the same
  // file, we get a big win by caching the result.
  if (IsBeforeInTUCache.isCacheValid(LOffs.first, ROffs.first))
    return IsBeforeInTUCache.getCachedResult(LOffs.second, ROffs.second);

  // Okay, we missed in the cache, start updating the cache for this query.
  IsBeforeInTUCache.setQueryFIDs(LOffs.first, ROffs.first);

  // "Traverse" the include/instantiation stacks of both locations and try to
  // find a common "ancestor".  FileIDs build a tree-like structure that
  // reflects the #include hierarchy, and this algorithm needs to find the
  // nearest common ancestor between the two locations.  For example, if you
  // have a.c that includes b.h and c.h, and are comparing a location in b.h to
  // a location in c.h, we need to find that their nearest common ancestor is
  // a.c, and compare the locations of the two #includes to find their relative
  // ordering.
  //
  // SourceManager assigns FileIDs in order of parsing.  This means that an
  // includee always has a larger FileID than an includer.  While you might
  // think that we could just compare the FileID's here, that doesn't work to
  // compare a point at the end of a.c with a point within c.h.  Though c.h has
  // a larger FileID, we have to compare the include point of c.h to the
  // location in a.c.
  //
  // Despite not being able to directly compare FileID's, we can tell that a
  // larger FileID is necessarily more deeply nested than a lower one and use
  // this information to walk up the tree to the nearest common ancestor.
  do {
    // If LOffs is larger than ROffs, then LOffs must be more deeply nested than
    // ROffs, walk up the #include chain.
    if (LOffs.first.ID > ROffs.first.ID) {
      if (MoveUpIncludeHierarchy(LOffs, *this))
        break; // We reached the top.
      
    } else {
      // Otherwise, ROffs is larger than LOffs, so ROffs must be more deeply
      // nested than LOffs, walk up the #include chain.
      if (MoveUpIncludeHierarchy(ROffs, *this))
        break; // We reached the top.
    }
  } while (LOffs.first != ROffs.first);

  // If we exited because we found a nearest common ancestor, compare the
  // locations within the common file and cache them.
  if (LOffs.first == ROffs.first) {
    IsBeforeInTUCache.setCommonLoc(LOffs.first, LOffs.second, ROffs.second);
    return IsBeforeInTUCache.getCachedResult(LOffs.second, ROffs.second);
  }

  // There is no common ancestor, most probably because one location is in the
  // predefines buffer or an AST file.
  // FIXME: We should rearrange the external interface so this simply never
  // happens; it can't conceptually happen. Also see PR5662.
  IsBeforeInTUCache.setQueryFIDs(FileID(), FileID()); // Don't try caching.

  // Zip both entries up to the top level record.
  while (!MoveUpIncludeHierarchy(LOffs, *this)) /*empty*/;
  while (!MoveUpIncludeHierarchy(ROffs, *this)) /*empty*/;
  
  // If exactly one location is a memory buffer, assume it preceeds the other.
  
  // Strip off macro instantation locations, going up to the top-level File
  // SLocEntry.
  bool LIsMB = getFileEntryForID(LOffs.first) == 0;
  bool RIsMB = getFileEntryForID(ROffs.first) == 0;
  if (LIsMB != RIsMB)
    return LIsMB;

  // Otherwise, just assume FileIDs were created in order.
  return LOffs.first < ROffs.first;
}

/// PrintStats - Print statistics to stderr.
///
void SourceManager::PrintStats() const {
  llvm::errs() << "\n*** Source Manager Stats:\n";
  llvm::errs() << FileInfos.size() << " files mapped, " << MemBufferInfos.size()
               << " mem buffers mapped.\n";
  llvm::errs() << SLocEntryTable.size() << " SLocEntry's allocated, "
               << NextOffset << "B of Sloc address space used.\n";

  unsigned NumLineNumsComputed = 0;
  unsigned NumFileBytesMapped = 0;
  for (fileinfo_iterator I = fileinfo_begin(), E = fileinfo_end(); I != E; ++I){
    NumLineNumsComputed += I->second->SourceLineCache != 0;
    NumFileBytesMapped  += I->second->getSizeBytesMapped();
  }

  llvm::errs() << NumFileBytesMapped << " bytes of files mapped, "
               << NumLineNumsComputed << " files with line #'s computed.\n";
  llvm::errs() << "FileID scans: " << NumLinearScans << " linear, "
               << NumBinaryProbes << " binary.\n";
}

ExternalSLocEntrySource::~ExternalSLocEntrySource() { }
