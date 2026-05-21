/** @file
  Unit tests for the signature-database helpers in
  DxeImageVerificationLib (Database.c): IsKnownImageHashGuid,
  IsImageDigestFoundInDatabase, LoadSignatureDatabase, and
  LoadSignatureDatabases. IsImageDigestFoundInDatabase is exercised
  against synthetic in-memory EFI_SIGNATURE_LIST buffers built by
  helpers in this file. LoadSignatureDatabase and LoadSignatureDatabases
  are exercised against a mocked GetVariable2.
  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockUefiLib.h>
#include <GoogleTest/Library/MockBaseCryptLib.h>

#include <vector>
#include <cstring>

extern "C" {
  #include <Uefi.h>
  #include <Guid/ImageAuthentication.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include "../Database.h"
  #include "../Support.h"
}

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

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
// IsImageDigestFoundInDatabase
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

// SHA-256 digest payload size (no owner GUID).
static constexpr UINTN  kSha256DigestSize = 32;
static constexpr UINTN  kSha384DigestSize = 48;

static IMAGE_DIGEST_CACHE
MakeBoundCache (
  const EFI_GUID            *HashType,
  const std::vector<UINT8>  &Digest
  )
{
  IMAGE_DIGEST_CACHE  Cache;
  UINTN               Index;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.FileBuffer = (const VOID *)(UINTN)1;
  Cache.FileSize   = 1;

  EXPECT_TRUE (GetKnownImageHashGuidIndex (HashType, &Index));
  EXPECT_LE (Digest.size (), (size_t)MAX_DIGEST_SIZE);

  std::memcpy (Cache.Entries[Index].Bytes, Digest.data (), Digest.size ());
  Cache.Entries[Index].Size = Digest.size ();
  return Cache;
}

TEST (IsImageDigestFoundInDatabaseTest, NullDatabaseWithNonZeroSize_ReturnsSuccess) {
  IMAGE_DIGEST_CACHE  Cache;
  BOOLEAN             Found = FALSE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.FileBuffer = (const VOID *)(UINTN)1;
  Cache.FileSize   = 1;

  EXPECT_EQ (IsImageDigestFoundInDatabase (NULL, 1, &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
  // Validate that Cache remains consistent
  EXPECT_EQ (Cache.FileBuffer, (const VOID *)(UINTN)1);
  EXPECT_EQ (Cache.FileSize, (UINTN)1);
}

TEST (IsImageDigestFoundInDatabaseTest, NullDatabaseWithZeroSize_EmptyDatabaseNotFound) {
  IMAGE_DIGEST_CACHE  Cache;
  BOOLEAN             Found = TRUE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.FileBuffer = (const VOID *)(UINTN)1;
  Cache.FileSize   = 1;

  EXPECT_EQ (IsImageDigestFoundInDatabase (NULL, 0, &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
  // Validate that Cache remains consistent
  EXPECT_EQ (Cache.FileBuffer, (const VOID *)(UINTN)1);
  EXPECT_EQ (Cache.FileSize, (UINTN)1);
}

TEST (IsImageDigestFoundInDatabaseTest, NullCache_ReturnsInvalidParameter) {
  UINT8    Dummy = 0;
  BOOLEAN  Found = FALSE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (&Dummy, 1, NULL, &Found), EFI_INVALID_PARAMETER);
}

TEST (IsImageDigestFoundInDatabaseTest, NullIsFound_ReturnsInvalidParameter) {
  UINT8               Dummy = 0;
  IMAGE_DIGEST_CACHE  Cache;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.FileBuffer = (const VOID *)(UINTN)1;
  Cache.FileSize   = 1;

  EXPECT_EQ (IsImageDigestFoundInDatabase (&Dummy, 1, &Cache, NULL), EFI_INVALID_PARAMETER);
}

TEST (IsImageDigestFoundInDatabaseTest, CacheWithoutImageBinding_ReturnsInvalidParameter) {
  UINT8               Dummy = 0;
  IMAGE_DIGEST_CACHE  Cache;
  BOOLEAN             Found = FALSE;

  ZeroMem (&Cache, sizeof (Cache));
  EXPECT_EQ (IsImageDigestFoundInDatabase (&Dummy, 1, &Cache, &Found), EFI_INVALID_PARAMETER);
}

TEST (IsImageDigestFoundInDatabaseTest, CacheWithZeroFileSize_ReturnsInvalidParameter) {
  UINT8               Dummy = 0;
  IMAGE_DIGEST_CACHE  Cache;
  BOOLEAN             Found = FALSE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.FileBuffer = (const VOID *)(UINTN)1;
  Cache.FileSize   = 0;

  EXPECT_EQ (IsImageDigestFoundInDatabase (&Dummy, 1, &Cache, &Found), EFI_INVALID_PARAMETER);
}

TEST (IsImageDigestFoundInDatabaseTest, HashComputationFailure_PropagatesError) {
  MockBaseCryptLib    BaseCryptLibMock;
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  IMAGE_DIGEST_CACHE  Cache;
  BOOLEAN             Found = TRUE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.FileBuffer = (const VOID *)(UINTN)1;
  Cache.FileSize   = 1;

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHash (_, _, _, _, _))
    .WillOnce (Return (EFI_DEVICE_ERROR));

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_DEVICE_ERROR);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestFoundInDatabaseTest, ExactMatch_Found) {
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 2);
  std::vector<UINT8>  Target (kSha256DigestSize, 0xAA);

  SetEntryPayload (Db, Off, 1, Target);

  IMAGE_DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Target);
  BOOLEAN             Found = FALSE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_TRUE (Found);
}

TEST (IsImageDigestFoundInDatabaseTest, NoMatchingEntry_NotFound) {
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  std::vector<UINT8>  Stored (kSha256DigestSize, 0xAA);

  SetEntryPayload (Db, Off, 0, Stored);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0xBB);
  IMAGE_DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = FALSE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestFoundInDatabaseTest, UnknownSignatureTypeList_Skipped) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertX509Guid, 0, sizeof (EFI_GUID) + 16, 1);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0xAA);
  IMAGE_DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = TRUE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestFoundInDatabaseTest, MismatchedSignatureSize_Skipped) {
  // List type matches but per-entry size doesn't, so the list describes
  // a different algorithm and must be skipped.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha384EntrySize, 1);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0xCC);
  IMAGE_DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = TRUE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestFoundInDatabaseTest, MatchInSecondList_Found) {
  // First list is the wrong algorithm, second list contains the target.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertX509Guid, 0, sizeof (EFI_GUID) + 16, 1);
  size_t  SecondOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 2);

  std::vector<UINT8>  Target (kSha256DigestSize, 0x77);

  SetEntryPayload (Db, SecondOff, 1, Target);

  IMAGE_DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Target);
  BOOLEAN             Found = FALSE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_TRUE (Found);
}

TEST (IsImageDigestFoundInDatabaseTest, NonZeroSignatureHeaderSize_EntryMathCorrect) {
  // SignatureHeaderSize is non-zero: the per-list header occupies
  // additional bytes between EFI_SIGNATURE_LIST and the first entry.
  // A naive cursor that forgets to skip it would either miss the
  // payload entirely or read the header bytes as a fake entry.
  constexpr UINT32    kHeader = 8;
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha256Guid, kHeader, kSha256EntrySize, 2);

  // Fill the per-list header with a recognizable pattern so a math
  // bug that read it as an entry would compare against this, not the
  // real digest. The search target intentionally differs from it.
  std::memset (Db.data () + Off + sizeof (EFI_SIGNATURE_LIST), 0xEE, kHeader);

  std::vector<UINT8>  Target (kSha256DigestSize, 0x55);

  SetEntryPayload (Db, Off, 1, Target);

  IMAGE_DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Target);
  BOOLEAN             Found = FALSE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_TRUE (Found);
}

TEST (IsImageDigestFoundInDatabaseTest, ZeroEntryList_NotFound) {
  // A well-formed list with zero entries must be skipped without a
  // false positive (EntryCount == 0 means the inner loop never runs).
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 0);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0x00);
  IMAGE_DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = TRUE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestFoundInDatabaseTest, MalformedDb_ReturnsCorrupted) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  ((EFI_SIGNATURE_LIST *)Db.data ())->SignatureListSize = (UINT32)(Db.size () + 1);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0x00);
  IMAGE_DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = FALSE;

  EXPECT_EQ (IsImageDigestFoundInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_VOLUME_CORRUPTED);
}

TEST (IsImageDigestFoundInDatabaseTest, ZeroSizeNonNullDatabase_EmptyDatabaseNotFound) {
  UINT8               Dummy = 0;
  IMAGE_DIGEST_CACHE  Cache;
  BOOLEAN             Found = TRUE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.FileBuffer = (const VOID *)(UINTN)1;
  Cache.FileSize   = 1;

  EXPECT_EQ (IsImageDigestFoundInDatabase (&Dummy, 0, &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

// ---------------------------------------------------------------------------
// LoadSignatureDatabase (uses MockUefiLib::GetVariable2)
// ---------------------------------------------------------------------------

class LoadSignatureDatabaseTest : public ::testing::Test {
protected:
  MockUefiLib UefiLibMock;
};

TEST_F (LoadSignatureDatabaseTest, NullDatabaseName_ReturnsInvalidParameter) {
  VOID   *Buffer = NULL;
  UINTN  Size    = 0;

  EXPECT_EQ (
    LoadSignatureDatabase (NULL, &Buffer, &Size),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (LoadSignatureDatabaseTest, NullBuffer_ReturnsInvalidParameter) {
  UINTN  Size = 0;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", NULL, &Size),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (LoadSignatureDatabaseTest, NullSize_ReturnsInvalidParameter) {
  VOID  *Buffer = NULL;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", &Buffer, NULL),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (LoadSignatureDatabaseTest, VariableMissing_SuccessWithNullBuffer) {
  // EFI_NOT_FOUND is normalized to EFI_SUCCESS with *Buffer == NULL.
  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (Return (EFI_NOT_FOUND));

  VOID   *Buffer = (VOID *)(UINTN)0xDEADBEEF;  // pre-set: must be cleared
  UINTN  Size    = 0xAA;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", &Buffer, &Size),
    EFI_SUCCESS
    );
  EXPECT_EQ (Buffer, (VOID *)NULL);
  EXPECT_EQ (Size, 0u);
}

TEST_F (LoadSignatureDatabaseTest, VariablePresent_BufferAndSizePopulated) {
  static const UINT8  kPayload[] = { 0xAA, 0xBB, 0xCC, 0xDD };

  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (
       Invoke (
         [] (
             IN CONST CHAR16    *Name,
             IN CONST EFI_GUID  *Guid,
             OUT      VOID      **Value,
             OUT      UINTN     *Size
         ) -> EFI_STATUS {
    (VOID)Name;
    (VOID)Guid;
    *Value = AllocateCopyPool (sizeof (kPayload), kPayload);
    *Size  = sizeof (kPayload);
    return EFI_SUCCESS;
  }
         )
       );

  VOID   *Buffer = NULL;
  UINTN  Size    = 0;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", &Buffer, &Size),
    EFI_SUCCESS
    );
  ASSERT_NE (Buffer, (VOID *)NULL);
  EXPECT_EQ (Size, sizeof (kPayload));
  EXPECT_EQ (CompareMem (Buffer, kPayload, sizeof (kPayload)), 0);

  FreePool (Buffer);
}

TEST_F (LoadSignatureDatabaseTest, GetVariableUnexpectedError_PropagatedVerbatim) {
  // Errors other than EFI_NOT_FOUND must be reported unchanged.
  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (Return (EFI_DEVICE_ERROR));

  VOID   *Buffer = NULL;
  UINTN  Size    = 0;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", &Buffer, &Size),
    EFI_DEVICE_ERROR
    );
}

// ---------------------------------------------------------------------------
// LoadSignatureDatabases (db + dbx)
// ---------------------------------------------------------------------------

class LoadSignatureDatabasesTest : public ::testing::Test {
protected:
  MockUefiLib UefiLibMock;
};

//
// Lambda factory: a GetVariable2 action that allocates a copy of the
// supplied payload and returns EFI_SUCCESS. Used to feed synthetic
// db/dbx buffers into LoadSignatureDatabases through the mock.
//
static auto
ReturnVariablePayload (
  const UINT8  *Payload,
  size_t       PayloadSize
  )
{
  return Invoke (
           [Payload, PayloadSize] (
                                   IN CONST CHAR16    *Name,
                                   IN CONST EFI_GUID  *Guid,
                                   OUT      VOID      **Value,
                                   OUT      UINTN     *Size
           ) -> EFI_STATUS {
    (VOID)Name;
    (VOID)Guid;
    *Value = AllocateCopyPool (PayloadSize, Payload);
    *Size  = PayloadSize;
    return EFI_SUCCESS;
  }
           );
}

TEST_F (LoadSignatureDatabasesTest, NullDb_ReturnsInvalidParameter) {
  UINTN  DbSize;
  VOID   *Dbx = NULL;
  UINTN  DbxSize;

  EXPECT_EQ (
    LoadSignatureDatabases (NULL, &DbSize, &Dbx, &DbxSize),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (LoadSignatureDatabasesTest, NullDbSize_ReturnsInvalidParameter) {
  VOID   *Db  = NULL;
  VOID   *Dbx = NULL;
  UINTN  DbxSize;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, NULL, &Dbx, &DbxSize),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (LoadSignatureDatabasesTest, NullDbx_ReturnsInvalidParameter) {
  VOID   *Db = NULL;
  UINTN  DbSize;
  UINTN  DbxSize;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, NULL, &DbxSize),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (LoadSignatureDatabasesTest, NullDbxSize_ReturnsInvalidParameter) {
  VOID   *Db = NULL;
  UINTN  DbSize;
  VOID   *Dbx = NULL;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, &Dbx, NULL),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (LoadSignatureDatabasesTest, BothVariablesMissing_Success) {
  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (Return (EFI_NOT_FOUND))   // db
    .WillOnce (Return (EFI_NOT_FOUND));  // dbx

  VOID   *Db     = (VOID *)(UINTN)0xDEADBEEF;              // pre-set: must be cleared
  UINTN  DbSize  = 0xAA;
  VOID   *Dbx    = (VOID *)(UINTN)0xCAFEF00D;              // pre-set: must be cleared
  UINTN  DbxSize = 0xBB;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, &Dbx, &DbxSize),
    EFI_SUCCESS
    );
  EXPECT_EQ (Db, (VOID *)NULL);
  EXPECT_EQ (DbSize, 0u);
  EXPECT_EQ (Dbx, (VOID *)NULL);
  EXPECT_EQ (DbxSize, 0u);
}

TEST_F (LoadSignatureDatabasesTest, OnlyDbPresent_DbAllocated) {
  std::vector<UINT8>  DbBuf;

  AppendSignatureList (DbBuf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (ReturnVariablePayload (DbBuf.data (), DbBuf.size ()))  // db
    .WillOnce (Return (EFI_NOT_FOUND));                               // dbx

  VOID   *Db     = NULL;
  UINTN  DbSize  = 0;
  VOID   *Dbx    = NULL;
  UINTN  DbxSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, &Dbx, &DbxSize),
    EFI_SUCCESS
    );
  ASSERT_NE (Db, (VOID *)NULL);
  EXPECT_EQ (DbSize, DbBuf.size ());
  EXPECT_EQ (Dbx, (VOID *)NULL);
  EXPECT_EQ (DbxSize, 0u);
  FreePool (Db);
}

TEST_F (LoadSignatureDatabasesTest, OnlyDbxPresent_DbxAllocated) {
  std::vector<UINT8>  DbxBuf;

  AppendSignatureList (DbxBuf, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);

  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (Return (EFI_NOT_FOUND))                                  // db
    .WillOnce (ReturnVariablePayload (DbxBuf.data (), DbxBuf.size ())); // dbx

  VOID   *Db     = NULL;
  UINTN  DbSize  = 0;
  VOID   *Dbx    = NULL;
  UINTN  DbxSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, &Dbx, &DbxSize),
    EFI_SUCCESS
    );
  EXPECT_EQ (Db, (VOID *)NULL);
  EXPECT_EQ (DbSize, 0u);
  ASSERT_NE (Dbx, (VOID *)NULL);
  EXPECT_EQ (DbxSize, DbxBuf.size ());
  FreePool (Dbx);
}

TEST_F (LoadSignatureDatabasesTest, BothPresent_BuffersAllocated) {
  std::vector<UINT8>  DbBuf;
  std::vector<UINT8>  DbxBuf;

  AppendSignatureList (DbBuf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  AppendSignatureList (DbxBuf, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);

  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (ReturnVariablePayload (DbBuf.data (), DbBuf.size ()))    // db
    .WillOnce (ReturnVariablePayload (DbxBuf.data (), DbxBuf.size ())); // dbx

  VOID   *Db     = NULL;
  UINTN  DbSize  = 0;
  VOID   *Dbx    = NULL;
  UINTN  DbxSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, &Dbx, &DbxSize),
    EFI_SUCCESS
    );
  ASSERT_NE (Db, (VOID *)NULL);
  EXPECT_EQ (DbSize, DbBuf.size ());
  ASSERT_NE (Dbx, (VOID *)NULL);
  EXPECT_EQ (DbxSize, DbxBuf.size ());
  FreePool (Db);
  FreePool (Dbx);
}

TEST_F (LoadSignatureDatabasesTest, DbLoadFails_ErrorPropagatedNothingAllocated) {
  // The db lookup fails with a non-NOT_FOUND status; dbx must not even
  // be attempted, and both out-pointers must be NULL.
  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (Return (EFI_DEVICE_ERROR));

  VOID   *Db     = NULL;
  UINTN  DbSize  = 0;
  VOID   *Dbx    = NULL;
  UINTN  DbxSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, &Dbx, &DbxSize),
    EFI_DEVICE_ERROR
    );
  EXPECT_EQ (Db, (VOID *)NULL);
  EXPECT_EQ (DbSize, 0u);
  EXPECT_EQ (Dbx, (VOID *)NULL);
  EXPECT_EQ (DbxSize, 0u);
}

TEST_F (LoadSignatureDatabasesTest, DbxLoadFails_DbFreedAndErrorPropagated) {
  std::vector<UINT8>  DbBuf;

  AppendSignatureList (DbBuf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  // db succeeds (allocation must be cleaned up internally); dbx fails.
  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (ReturnVariablePayload (DbBuf.data (), DbBuf.size ()))  // db
    .WillOnce (Return (EFI_DEVICE_ERROR));                            // dbx

  VOID   *Db     = NULL;
  UINTN  DbSize  = 0;
  VOID   *Dbx    = NULL;
  UINTN  DbxSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, &Dbx, &DbxSize),
    EFI_DEVICE_ERROR
    );
  EXPECT_EQ (Db, (VOID *)NULL);   // freed and nulled
  EXPECT_EQ (DbSize, 0u);
  EXPECT_EQ (Dbx, (VOID *)NULL);
  EXPECT_EQ (DbxSize, 0u);
}

TEST_F (LoadSignatureDatabasesTest, DbxLoadFailsWithAllocatedBuffer_DbxFreedAndNulled) {
  std::vector<UINT8>  DbBuf;

  AppendSignatureList (DbBuf, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (ReturnVariablePayload (DbBuf.data (), DbBuf.size ()))
    .WillOnce (
       Invoke (
         [] (
             IN CONST CHAR16    *Name,
             IN CONST EFI_GUID  *Guid,
             OUT      VOID      **Value,
             OUT      UINTN     *Size
         ) -> EFI_STATUS {
    (VOID)Name;
    (VOID)Guid;
    *Value = AllocatePool (8);
    *Size  = 8;
    return EFI_DEVICE_ERROR;
  }
         )
       );

  VOID   *Db     = NULL;
  UINTN  DbSize  = 0;
  VOID   *Dbx    = NULL;
  UINTN  DbxSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabases (&Db, &DbSize, &Dbx, &DbxSize),
    EFI_DEVICE_ERROR
    );
  EXPECT_EQ (Db, (VOID *)NULL);
  EXPECT_EQ (DbSize, 0u);
  EXPECT_EQ (Dbx, (VOID *)NULL);
  EXPECT_EQ (DbxSize, 0u);
}
