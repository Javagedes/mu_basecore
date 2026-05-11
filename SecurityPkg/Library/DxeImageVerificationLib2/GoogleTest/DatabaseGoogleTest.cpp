/** @file
  Unit tests for the signature-database helpers in
  DxeImageVerificationLib (Database.c): IsKnownImageHashGuid,
  WalkSignatureDatabase, and GetDatabaseHashAlgorithms.

  WalkSignatureDatabase is exercised against synthetic in-memory
  EFI_SIGNATURE_LIST buffers built by helpers in this file.
  GetDatabaseHashAlgorithms is exercised against a mocked GetVariable2
  so the exact db/dbx contents are controlled per-test.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockUefiLib.h>

#include <vector>
#include <map>
#include <string>
#include <cstring>

extern "C" {
  #include <Uefi.h>
  #include <Guid/ImageAuthentication.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include "../Database.h"
}

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrEq;

// ---------------------------------------------------------------------------
// Helpers for constructing signature-list buffers.
// ---------------------------------------------------------------------------

//
// Append one EFI_SIGNATURE_LIST containing SignatureCount entries of
// EntrySize bytes each (entry payloads are zero-initialized) to Buffer.
// Returns the offset of the new list within Buffer.
//
static size_t
AppendSignatureList (
  std::vector<UINT8>  &Buffer,
  const EFI_GUID      &SignatureType,
  UINT32              SignatureHeaderSize,
  UINT32              EntrySize,
  UINT32              SignatureCount
  )
{
  const size_t  PayloadBytes = (size_t)EntrySize * (size_t)SignatureCount;
  const size_t  ListBytes    = sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + PayloadBytes;
  const size_t  Offset       = Buffer.size ();

  Buffer.resize (Offset + ListBytes, 0);

  EFI_SIGNATURE_LIST  *List = (EFI_SIGNATURE_LIST *)(Buffer.data () + Offset);

  CopyMem (&List->SignatureType, &SignatureType, sizeof (EFI_GUID));
  List->SignatureListSize   = (UINT32)ListBytes;
  List->SignatureHeaderSize = SignatureHeaderSize;
  List->SignatureSize       = EntrySize;

  return Offset;
}

//
// Walk callback that simply counts invocations and records the
// per-list SignatureType GUIDs in visit order.
//
struct CallbackRecorder {
  UINTN                    Count;
  std::vector<EFI_GUID>    SeenTypes;
  RETURN_STATUS            ReturnAt;     // RETURN_SUCCESS to keep going
  UINTN                    AbortAfter;   // applies when ReturnAt != SUCCESS
};

extern "C" EFI_STATUS EFIAPI
RecorderCallback (
  IN CONST EFI_SIGNATURE_LIST  *List,
  IN VOID                      *Context  OPTIONAL
  )
{
  CallbackRecorder  *Rec = (CallbackRecorder *)Context;

  Rec->Count++;
  Rec->SeenTypes.push_back (List->SignatureType);

  if ((Rec->ReturnAt != EFI_SUCCESS) && (Rec->Count >= Rec->AbortAfter)) {
    return Rec->ReturnAt;
  }

  return EFI_SUCCESS;
}

// SHA-256 entry size: 16-byte owner GUID + 32-byte digest.
static constexpr UINT32  kSha256EntrySize = sizeof (EFI_GUID) + 32;
static constexpr UINT32  kSha384EntrySize = sizeof (EFI_GUID) + 48;

// ---------------------------------------------------------------------------
// IsKnownImageHashGuid
// ---------------------------------------------------------------------------

TEST (IsKnownImageHashGuidTest, NullGuid_ReturnsFalse) {
  EXPECT_FALSE (IsKnownImageHashGuid (NULL));
}

TEST (IsKnownImageHashGuidTest, KnownHashGuids_ReturnTrue) {
  EXPECT_TRUE (IsKnownImageHashGuid (&gEfiCertSha1Guid));
  EXPECT_TRUE (IsKnownImageHashGuid (&gEfiCertSha256Guid));
  EXPECT_TRUE (IsKnownImageHashGuid (&gEfiCertSha384Guid));
  EXPECT_TRUE (IsKnownImageHashGuid (&gEfiCertSha512Guid));
}

TEST (IsKnownImageHashGuidTest, X509Guids_ReturnFalse) {
  // X509-with-hash variants are intentionally excluded.
  EXPECT_FALSE (IsKnownImageHashGuid (&gEfiCertX509Guid));
  EXPECT_FALSE (IsKnownImageHashGuid (&gEfiCertX509Sha256Guid));
  EXPECT_FALSE (IsKnownImageHashGuid (&gEfiCertX509Sha384Guid));
  EXPECT_FALSE (IsKnownImageHashGuid (&gEfiCertX509Sha512Guid));
}

TEST (IsKnownImageHashGuidTest, ArbitraryGuid_ReturnsFalse) {
  EFI_GUID  Junk = { 0x12345678, 0x1234, 0x5678,
                     { 0x9a,     0xbc,   0xde,  0xf0,0x12, 0x34, 0x56, 0x78 }
  };

  EXPECT_FALSE (IsKnownImageHashGuid (&Junk));
}

// ---------------------------------------------------------------------------
// WalkSignatureDatabase
// ---------------------------------------------------------------------------

class WalkSignatureDatabaseTest : public ::testing::Test {
protected:
  CallbackRecorder Rec{ };

  void
  SetUp (
    ) override
  {
    Rec.Count      = 0;
    Rec.ReturnAt   = EFI_SUCCESS;
    Rec.AbortAfter = 0;
    Rec.SeenTypes.clear ();
  }
};

TEST_F (WalkSignatureDatabaseTest, NullBuffer_ReturnsInvalidParameter) {
  EXPECT_EQ (
    WalkSignatureDatabase (NULL, 0, RecorderCallback, &Rec),
    EFI_INVALID_PARAMETER
    );
  EXPECT_EQ (Rec.Count, 0u);
}

TEST_F (WalkSignatureDatabaseTest, NullCallback_ReturnsInvalidParameter) {
  UINT8  Dummy = 0;

  EXPECT_EQ (
    WalkSignatureDatabase (&Dummy, 1, NULL, &Rec),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (WalkSignatureDatabaseTest, EmptyBuffer_ReturnsSuccessNoInvocations) {
  UINT8  Dummy = 0;

  EXPECT_EQ (
    WalkSignatureDatabase (&Dummy, 0, RecorderCallback, &Rec),
    EFI_SUCCESS
    );
  EXPECT_EQ (Rec.Count, 0u);
}

TEST_F (WalkSignatureDatabaseTest, SingleList_InvokesCallbackOnce) {
  std::vector<UINT8>  Buf;

  AppendSignatureList (Buf, gEfiCertSha256Guid, 0, kSha256EntrySize, 2);

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_SUCCESS
    );
  EXPECT_EQ (Rec.Count, 1u);
  ASSERT_EQ (Rec.SeenTypes.size (), 1u);
  EXPECT_EQ (CompareGuid (&Rec.SeenTypes[0], &gEfiCertSha256Guid), TRUE);
}

TEST_F (WalkSignatureDatabaseTest, MultipleLists_InvokedInOrder) {
  std::vector<UINT8>  Buf;

  AppendSignatureList (Buf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  AppendSignatureList (Buf, gEfiCertSha384Guid, 0, kSha384EntrySize, 3);
  AppendSignatureList (Buf, gEfiCertX509Guid, 0, sizeof (EFI_GUID) + 8, 1);

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_SUCCESS
    );
  ASSERT_EQ (Rec.SeenTypes.size (), 3u);
  EXPECT_EQ (CompareGuid (&Rec.SeenTypes[0], &gEfiCertSha256Guid), TRUE);
  EXPECT_EQ (CompareGuid (&Rec.SeenTypes[1], &gEfiCertSha384Guid), TRUE);
  EXPECT_EQ (CompareGuid (&Rec.SeenTypes[2], &gEfiCertX509Guid), TRUE);
}

TEST_F (WalkSignatureDatabaseTest, ListSizeBelowHeader_ReturnsCorrupted) {
  std::vector<UINT8>  Buf (sizeof (EFI_SIGNATURE_LIST), 0);
  EFI_SIGNATURE_LIST  *List = (EFI_SIGNATURE_LIST *)Buf.data ();

  CopyGuid (&List->SignatureType, &gEfiCertSha256Guid);
  List->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) - 1;  // bad
  List->SignatureHeaderSize = 0;
  List->SignatureSize       = kSha256EntrySize;

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_VOLUME_CORRUPTED
    );
  EXPECT_EQ (Rec.Count, 0u);
}

TEST_F (WalkSignatureDatabaseTest, ListSizeExceedsBuffer_ReturnsCorrupted) {
  std::vector<UINT8>  Buf;

  AppendSignatureList (Buf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  // Inflate the declared size past Buf.size().
  ((EFI_SIGNATURE_LIST *)Buf.data ())->SignatureListSize = (UINT32)(Buf.size () + 1);

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_VOLUME_CORRUPTED
    );
  EXPECT_EQ (Rec.Count, 0u);
}

TEST_F (WalkSignatureDatabaseTest, SignatureSizeBelowGuidSize_ReturnsCorrupted) {
  std::vector<UINT8>  Buf;

  AppendSignatureList (Buf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  ((EFI_SIGNATURE_LIST *)Buf.data ())->SignatureSize = sizeof (EFI_GUID) - 1;

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_VOLUME_CORRUPTED
    );
}

TEST_F (WalkSignatureDatabaseTest, HeaderSizeOverflowsList_ReturnsCorrupted) {
  std::vector<UINT8>  Buf;

  AppendSignatureList (Buf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  // SignatureHeaderSize larger than the per-list payload region.
  ((EFI_SIGNATURE_LIST *)Buf.data ())->SignatureHeaderSize =
    ((EFI_SIGNATURE_LIST *)Buf.data ())->SignatureListSize;

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_VOLUME_CORRUPTED
    );
}

TEST_F (WalkSignatureDatabaseTest, PayloadNotMultipleOfEntry_ReturnsCorrupted) {
  std::vector<UINT8>  Buf;

  AppendSignatureList (Buf, gEfiCertSha256Guid, 0, kSha256EntrySize, 2);

  // Bump the entry size so payload no longer divides evenly.
  ((EFI_SIGNATURE_LIST *)Buf.data ())->SignatureSize = kSha256EntrySize + 1;

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_VOLUME_CORRUPTED
    );
}

TEST_F (WalkSignatureDatabaseTest, TrailingBytes_ReturnsCorrupted) {
  std::vector<UINT8>  Buf;

  AppendSignatureList (Buf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  // Append a partial header that's smaller than EFI_SIGNATURE_LIST.
  Buf.push_back (0xAA);

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_VOLUME_CORRUPTED
    );
  EXPECT_EQ (Rec.Count, 1u);  // first list was visited before trailing-byte check
}

TEST_F (WalkSignatureDatabaseTest, CallbackAborts_PropagatesStatus) {
  std::vector<UINT8>  Buf;

  AppendSignatureList (Buf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  AppendSignatureList (Buf, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);
  AppendSignatureList (Buf, gEfiCertSha512Guid, 0, sizeof (EFI_GUID) + 64, 1);

  Rec.ReturnAt   = EFI_ABORTED;
  Rec.AbortAfter = 2;

  EXPECT_EQ (
    WalkSignatureDatabase (Buf.data (), Buf.size (), RecorderCallback, &Rec),
    EFI_ABORTED
    );
  EXPECT_EQ (Rec.Count, 2u);  // third list never visited
}

// ---------------------------------------------------------------------------
// GetDatabaseHashAlgorithms (uses MockUefiLib::GetVariable2)
// ---------------------------------------------------------------------------

//
// Per-database fake payloads owned by the test fixture. Returned to
// the SUT via AllocateCopyPool from the GetVariable2 mock so the SUT
// can FreePool them like real data.
//
struct FakeVariable {
  EFI_STATUS            Status;
  std::vector<UINT8>    Bytes;
};

class GetDatabaseHashAlgorithmsTest : public ::testing::Test {
protected:
  MockUefiLib UefiLibMock;
  std::map<std::u16string, FakeVariable> Vars;

  void
  SetUp (
    ) override
  {
    // Default: both variables missing.
    Vars[u"db"] = { EFI_NOT_FOUND, { }
    };
    Vars[u"dbx"] = { EFI_NOT_FOUND, { }
    };

    ON_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
      .WillByDefault (
         Invoke (
           [this] (
                   IN CONST CHAR16    *Name,
                   IN CONST EFI_GUID  *Guid,
                   OUT      VOID      **Value,
                   OUT      UINTN     *Size
           ) -> EFI_STATUS {
      (VOID)Guid;
      // CHAR16 is 16-bit; std::u16string also stores 16-bit code units.
      auto  it = Vars.find (std::u16string ((const char16_t *)Name));
      if (it == Vars.end ()) {
        return EFI_NOT_FOUND;
      }

      if (it->second.Status != EFI_SUCCESS) {
        return it->second.Status;
      }

      *Value = AllocateCopyPool (it->second.Bytes.size (), it->second.Bytes.data ());
      if (Size != NULL) {
        *Size = it->second.Bytes.size ();
      }

      return EFI_SUCCESS;
    }
           )
         );

    EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _)).Times (testing::AnyNumber ());
  }

  void
  SetVariable (
    const std::u16string  &Name,
    std::vector<UINT8>    Bytes
    )
  {
    Vars[Name] = { EFI_SUCCESS, std::move (Bytes) };
  }
};

TEST_F (GetDatabaseHashAlgorithmsTest, NullArg_ReturnsInvalidParameter) {
  EXPECT_EQ (GetDatabaseHashAlgorithms (NULL), EFI_INVALID_PARAMETER);
}

TEST_F (GetDatabaseHashAlgorithmsTest, BothVariablesMissing_EmptySet) {
  HASH_ALGORITHM_SET  Set;

  ZeroMem (&Set, sizeof (Set));

  EXPECT_EQ (GetDatabaseHashAlgorithms (&Set), EFI_SUCCESS);
  EXPECT_EQ (Set.Count, 0u);
}

TEST_F (GetDatabaseHashAlgorithmsTest, OnlyDb_HashType_Reported) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  SetVariable (u"db", std::move (Db));

  HASH_ALGORITHM_SET  Set;

  EXPECT_EQ (GetDatabaseHashAlgorithms (&Set), EFI_SUCCESS);
  ASSERT_EQ (Set.Count, 1u);
  EXPECT_EQ (CompareGuid (&Set.Guids[0], &gEfiCertSha256Guid), TRUE);
}

TEST_F (GetDatabaseHashAlgorithmsTest, OnlyDbx_HashType_Reported) {
  std::vector<UINT8>  Dbx;

  AppendSignatureList (Dbx, gEfiCertSha384Guid, 0, kSha384EntrySize, 2);
  SetVariable (u"dbx", std::move (Dbx));

  HASH_ALGORITHM_SET  Set;

  EXPECT_EQ (GetDatabaseHashAlgorithms (&Set), EFI_SUCCESS);
  ASSERT_EQ (Set.Count, 1u);
  EXPECT_EQ (CompareGuid (&Set.Guids[0], &gEfiCertSha384Guid), TRUE);
}

TEST_F (GetDatabaseHashAlgorithmsTest, BothPresent_Union) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Dbx;

  AppendSignatureList (Dbx, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);
  SetVariable (u"dbx", std::move (Dbx));

  HASH_ALGORITHM_SET  Set;

  EXPECT_EQ (GetDatabaseHashAlgorithms (&Set), EFI_SUCCESS);
  EXPECT_EQ (Set.Count, 2u);
}

TEST_F (GetDatabaseHashAlgorithmsTest, DuplicateAcrossDbAndDbx_Deduplicated) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Dbx;

  AppendSignatureList (Dbx, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  SetVariable (u"dbx", std::move (Dbx));

  HASH_ALGORITHM_SET  Set;

  EXPECT_EQ (GetDatabaseHashAlgorithms (&Set), EFI_SUCCESS);
  ASSERT_EQ (Set.Count, 1u);
  EXPECT_EQ (CompareGuid (&Set.Guids[0], &gEfiCertSha256Guid), TRUE);
}

TEST_F (GetDatabaseHashAlgorithmsTest, NonHashSignatureTypes_Ignored) {
  std::vector<UINT8>  Db;

  // X509 cert list is not a plain image hash; should not contribute.
  AppendSignatureList (Db, gEfiCertX509Guid, 0, sizeof (EFI_GUID) + 16, 1);
  SetVariable (u"db", std::move (Db));

  HASH_ALGORITHM_SET  Set;

  EXPECT_EQ (GetDatabaseHashAlgorithms (&Set), EFI_SUCCESS);
  EXPECT_EQ (Set.Count, 0u);
}

TEST_F (GetDatabaseHashAlgorithmsTest, MalformedDb_ReturnsCorrupted) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  // Corrupt the list size.
  ((EFI_SIGNATURE_LIST *)Db.data ())->SignatureListSize = (UINT32)(Db.size () + 1);
  SetVariable (u"db", std::move (Db));

  HASH_ALGORITHM_SET  Set;

  EXPECT_EQ (GetDatabaseHashAlgorithms (&Set), EFI_VOLUME_CORRUPTED);
}

TEST_F (GetDatabaseHashAlgorithmsTest, GetVariableUnexpectedError_Propagated) {
  Vars[u"db"] = { EFI_DEVICE_ERROR, { }
  };

  HASH_ALGORITHM_SET  Set;

  EXPECT_EQ (GetDatabaseHashAlgorithms (&Set), EFI_DEVICE_ERROR);
}

// ---------------------------------------------------------------------------
// IsSignatureFoundInDatabase (uses MockUefiLib::GetVariable2)
// ---------------------------------------------------------------------------

//
// Write Bytes into the entry payload (the part after the owner GUID) of
// signature index EntryIndex inside the EFI_SIGNATURE_LIST that begins
// at ListOffset within Buffer.
//
static void
SetEntryPayload (
  std::vector<UINT8>        &Buffer,
  size_t                    ListOffset,
  UINTN                     EntryIndex,
  const std::vector<UINT8>  &Bytes
  )
{
  EFI_SIGNATURE_LIST  *List      = (EFI_SIGNATURE_LIST *)(Buffer.data () + ListOffset);
  const size_t        FirstEntry = ListOffset + sizeof (EFI_SIGNATURE_LIST) + List->SignatureHeaderSize;
  const size_t        EntryStart = FirstEntry + (size_t)EntryIndex * (size_t)List->SignatureSize;
  const size_t        PayloadOff = EntryStart + sizeof (EFI_GUID);

  ASSERT_LE (PayloadOff + Bytes.size (), Buffer.size ());
  std::memcpy (Buffer.data () + PayloadOff, Bytes.data (), Bytes.size ());
}

class IsSignatureFoundInDatabaseTest : public ::testing::Test {
protected:
  MockUefiLib UefiLibMock;
  std::map<std::u16string, FakeVariable> Vars;

  void
  SetUp (
    ) override
  {
    Vars[u"db"] = { EFI_NOT_FOUND, { }
    };
    Vars[u"dbx"] = { EFI_NOT_FOUND, { }
    };

    ON_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
      .WillByDefault (
         Invoke (
           [this] (
                   IN CONST CHAR16    *Name,
                   IN CONST EFI_GUID  *Guid,
                   OUT      VOID      **Value,
                   OUT      UINTN     *Size
           ) -> EFI_STATUS {
      (VOID)Guid;
      auto  it = Vars.find (std::u16string ((const char16_t *)Name));
      if (it == Vars.end ()) {
        return EFI_NOT_FOUND;
      }

      if (it->second.Status != EFI_SUCCESS) {
        return it->second.Status;
      }

      *Value = AllocateCopyPool (it->second.Bytes.size (), it->second.Bytes.data ());
      if (Size != NULL) {
        *Size = it->second.Bytes.size ();
      }

      return EFI_SUCCESS;
    }
           )
         );

    EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _)).Times (testing::AnyNumber ());
  }

  void
  SetVariable (
    const std::u16string  &Name,
    std::vector<UINT8>    Bytes
    )
  {
    Vars[Name] = { EFI_SUCCESS, std::move (Bytes) };
  }
};

// SHA-256 digest payload size (no owner GUID).
static constexpr UINTN  kSha256DigestSize = 32;
static constexpr UINTN  kSha384DigestSize = 48;

TEST_F (IsSignatureFoundInDatabaseTest, NullDatabaseName_ReturnsInvalidParameter) {
  UINT8    Sig[kSha256DigestSize] = { 0 };
  BOOLEAN  Found                  = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase (NULL, Sig, &gEfiCertSha256Guid, sizeof (Sig), &Found),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (IsSignatureFoundInDatabaseTest, NullSignature_ReturnsInvalidParameter) {
  BOOLEAN  Found = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase ((const CHAR16 *)u"db", NULL, &gEfiCertSha256Guid, kSha256DigestSize, &Found),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (IsSignatureFoundInDatabaseTest, NullSignatureType_ReturnsInvalidParameter) {
  UINT8    Sig[kSha256DigestSize] = { 0 };
  BOOLEAN  Found                  = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase ((const CHAR16 *)u"db", Sig, NULL, sizeof (Sig), &Found),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (IsSignatureFoundInDatabaseTest, NullIsFound_ReturnsInvalidParameter) {
  UINT8  Sig[kSha256DigestSize] = { 0 };

  EXPECT_EQ (
    IsSignatureFoundInDatabase ((const CHAR16 *)u"db", Sig, &gEfiCertSha256Guid, sizeof (Sig), NULL),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (IsSignatureFoundInDatabaseTest, ZeroSignatureSize_ReturnsInvalidParameter) {
  UINT8    Sig   = 0;
  BOOLEAN  Found = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase ((const CHAR16 *)u"db", &Sig, &gEfiCertSha256Guid, 0, &Found),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (IsSignatureFoundInDatabaseTest, MissingVariable_NotFoundSuccess) {
  UINT8    Sig[kSha256DigestSize] = { 0xAB };
  BOOLEAN  Found                  = TRUE;  // pre-set to verify it gets cleared

  EXPECT_EQ (
    IsSignatureFoundInDatabase ((const CHAR16 *)u"db", Sig, &gEfiCertSha256Guid, sizeof (Sig), &Found),
    EFI_SUCCESS
    );
  EXPECT_FALSE (Found);
}

TEST_F (IsSignatureFoundInDatabaseTest, ExactMatch_Found) {
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 2);

  std::vector<UINT8>  Target (kSha256DigestSize, 0xAA);

  SetEntryPayload (Db, Off, 1, Target);
  SetVariable (u"db", std::move (Db));

  BOOLEAN  Found = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase (
      (const CHAR16 *)u"db",
      Target.data (),
      &gEfiCertSha256Guid,
      Target.size (),
      &Found
      ),
    EFI_SUCCESS
    );
  EXPECT_TRUE (Found);
}

TEST_F (IsSignatureFoundInDatabaseTest, NoMatchingEntry_NotFound) {
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  std::vector<UINT8>  Stored (kSha256DigestSize, 0xAA);

  SetEntryPayload (Db, Off, 0, Stored);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Wanted (kSha256DigestSize, 0xBB);
  BOOLEAN             Found = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase (
      (const CHAR16 *)u"db",
      Wanted.data (),
      &gEfiCertSha256Guid,
      Wanted.size (),
      &Found
      ),
    EFI_SUCCESS
    );
  EXPECT_FALSE (Found);
}

TEST_F (IsSignatureFoundInDatabaseTest, MismatchedSignatureType_Skipped) {
  // Database contains a SHA-384 entry whose payload bytes happen to
  // match the search target; lookup with a SHA-256 type GUID must skip
  // the SHA-384 list and report not-found.
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);

  std::vector<UINT8>  Stored (kSha384DigestSize, 0xAA);

  SetEntryPayload (Db, Off, 0, Stored);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Wanted (kSha256DigestSize, 0xAA);
  BOOLEAN             Found = TRUE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase (
      (const CHAR16 *)u"db",
      Wanted.data (),
      &gEfiCertSha256Guid,
      Wanted.size (),
      &Found
      ),
    EFI_SUCCESS
    );
  EXPECT_FALSE (Found);
}

TEST_F (IsSignatureFoundInDatabaseTest, MismatchedSignatureSize_Skipped) {
  // List type matches but per-entry size doesn't, so the list describes
  // a different algorithm and must be skipped.
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha384EntrySize, 1);

  std::vector<UINT8>  Stored (kSha384DigestSize, 0xCC);

  SetEntryPayload (Db, Off, 0, Stored);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Wanted (kSha256DigestSize, 0xCC);
  BOOLEAN             Found = TRUE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase (
      (const CHAR16 *)u"db",
      Wanted.data (),
      &gEfiCertSha256Guid,
      Wanted.size (),
      &Found
      ),
    EFI_SUCCESS
    );
  EXPECT_FALSE (Found);
}

TEST_F (IsSignatureFoundInDatabaseTest, MatchInSecondList_Found) {
  // First list is the wrong algorithm, second list contains the target.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);
  size_t  SecondOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 2);

  std::vector<UINT8>  Target (kSha256DigestSize, 0x77);

  SetEntryPayload (Db, SecondOff, 1, Target);
  SetVariable (u"db", std::move (Db));

  BOOLEAN  Found = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase (
      (const CHAR16 *)u"db",
      Target.data (),
      &gEfiCertSha256Guid,
      Target.size (),
      &Found
      ),
    EFI_SUCCESS
    );
  EXPECT_TRUE (Found);
}

TEST_F (IsSignatureFoundInDatabaseTest, MalformedDb_ReturnsCorrupted) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  ((EFI_SIGNATURE_LIST *)Db.data ())->SignatureListSize = (UINT32)(Db.size () + 1);
  SetVariable (u"db", std::move (Db));

  UINT8    Sig[kSha256DigestSize] = { 0 };
  BOOLEAN  Found                  = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase (
      (const CHAR16 *)u"db",
      Sig,
      &gEfiCertSha256Guid,
      sizeof (Sig),
      &Found
      ),
    EFI_VOLUME_CORRUPTED
    );
}

TEST_F (IsSignatureFoundInDatabaseTest, GetVariableUnexpectedError_Propagated) {
  Vars[u"db"] = { EFI_DEVICE_ERROR, { }
  };

  UINT8    Sig[kSha256DigestSize] = { 0 };
  BOOLEAN  Found                  = FALSE;

  EXPECT_EQ (
    IsSignatureFoundInDatabase (
      (const CHAR16 *)u"db",
      Sig,
      &gEfiCertSha256Guid,
      sizeof (Sig),
      &Found
      ),
    EFI_DEVICE_ERROR
    );
}
