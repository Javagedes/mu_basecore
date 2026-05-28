/** @file
  Unit tests for the signature-database helpers in
  DxeImageVerificationLib (Database.c): IsImageDigestInDatabase,
  LoadSignatureDatabase, and
  LoadSignatureDatabases. IsImageDigestInDatabase is exercised
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

  EFI_STATUS
  LoadSignatureDatabase (
    IN  CONST CHAR16  *DatabaseName,
    OUT VOID          **Buffer,
    OUT UINTN         *BufferSize
    );
}

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

static bool
GetImageHashIndexForTest (
  const EFI_GUID  *Guid,
  UINTN           *Index
  )
{
  UINTN  I;

  if ((Guid == nullptr) || (Index == nullptr)) {
    return false;
  }

  for (I = 0; I < ARRAY_SIZE (mHashAlgorithms); I++) {
    if (CompareGuid (Guid, mHashAlgorithms[I].ImageHashGuid)) {
      *Index = I;
      return true;
    }
  }

  return false;
}

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
// IsImageDigestInDatabase
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

static DIGEST_CACHE
MakeBoundCache (
  const EFI_GUID            *HashType,
  const std::vector<UINT8>  &Digest
  )
{
  DIGEST_CACHE  Cache;
  UINTN         Index;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = (const VOID *)(UINTN)1;
  Cache.BufferSize = 1;

  EXPECT_TRUE (GetImageHashIndexForTest (HashType, &Index));
  EXPECT_LE (Digest.size (), (size_t)MAX_DIGEST_SIZE);

  std::memcpy (Cache.Entries[Index].Bytes, Digest.data (), Digest.size ());
  Cache.Entries[Index].BufferSize = Digest.size ();
  return Cache;
}

TEST (IsImageDigestInDatabaseTest, NullDatabaseWithNonZeroSize_ReturnsSuccess) {
  DIGEST_CACHE  Cache;
  BOOLEAN       Found = FALSE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = (const VOID *)(UINTN)1;
  Cache.BufferSize = 1;

  EXPECT_EQ (IsImageDigestInDatabase (NULL, 1, &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
  // Validate that Cache remains consistent
  EXPECT_EQ (Cache.Buffer, (const VOID *)(UINTN)1);
  EXPECT_EQ (Cache.BufferSize, (UINTN)1);
}

TEST (IsImageDigestInDatabaseTest, NullDatabaseWithZeroSize_EmptyDatabaseNotFound) {
  DIGEST_CACHE  Cache;
  BOOLEAN       Found = TRUE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = (const VOID *)(UINTN)1;
  Cache.BufferSize = 1;

  EXPECT_EQ (IsImageDigestInDatabase (NULL, 0, &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
  // Validate that Cache remains consistent
  EXPECT_EQ (Cache.Buffer, (const VOID *)(UINTN)1);
  EXPECT_EQ (Cache.BufferSize, (UINTN)1);
}

TEST (IsImageDigestInDatabaseTest, NullCache_ReturnsInvalidParameter) {
  UINT8    Dummy = 0;
  BOOLEAN  Found = FALSE;

  EXPECT_EQ (IsImageDigestInDatabase (&Dummy, 1, NULL, &Found), EFI_INVALID_PARAMETER);
}

TEST (IsImageDigestInDatabaseTest, NullIsFound_ReturnsInvalidParameter) {
  UINT8         Dummy = 0;
  DIGEST_CACHE  Cache;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = (const VOID *)(UINTN)1;
  Cache.BufferSize = 1;

  EXPECT_EQ (IsImageDigestInDatabase (&Dummy, 1, &Cache, NULL), EFI_INVALID_PARAMETER);
}

TEST (IsImageDigestInDatabaseTest, CacheWithoutImageBinding_ReturnsInvalidParameter) {
  UINT8         Dummy = 0;
  DIGEST_CACHE  Cache;
  BOOLEAN       Found = FALSE;

  ZeroMem (&Cache, sizeof (Cache));
  EXPECT_EQ (IsImageDigestInDatabase (&Dummy, 1, &Cache, &Found), EFI_INVALID_PARAMETER);
}

TEST (IsImageDigestInDatabaseTest, CacheWithZeroFileSize_ReturnsInvalidParameter) {
  UINT8         Dummy = 0;
  DIGEST_CACHE  Cache;
  BOOLEAN       Found = FALSE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = (const VOID *)(UINTN)1;
  Cache.BufferSize = 0;

  EXPECT_EQ (IsImageDigestInDatabase (&Dummy, 1, &Cache, &Found), EFI_INVALID_PARAMETER);
}

TEST (IsImageDigestInDatabaseTest, HashComputationFailure_ReturnsSecurityViolation) {
  MockBaseCryptLib    BaseCryptLibMock;
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  DIGEST_CACHE  Cache;
  BOOLEAN       Found = TRUE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = (const VOID *)(UINTN)1;
  Cache.BufferSize = 1;

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHash (_, _, _, _, _))
    .WillOnce (Return (EFI_DEVICE_ERROR));

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SECURITY_VIOLATION);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestInDatabaseTest, ExactMatch_Found) {
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 2);
  std::vector<UINT8>  Target (kSha256DigestSize, 0xAA);

  SetEntryPayload (Db, Off, 1, Target);

  DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Target);
  BOOLEAN       Found = FALSE;

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_TRUE (Found);
}

TEST (IsImageDigestInDatabaseTest, NoMatchingEntry_NotFound) {
  std::vector<UINT8>  Db;
  size_t              Off = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  std::vector<UINT8>  Stored (kSha256DigestSize, 0xAA);

  SetEntryPayload (Db, Off, 0, Stored);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0xBB);
  DIGEST_CACHE        Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = FALSE;

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestInDatabaseTest, UnknownSignatureTypeList_Skipped) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertX509Guid, 0, sizeof (EFI_GUID) + 16, 1);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0xAA);
  DIGEST_CACHE        Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = TRUE;

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestInDatabaseTest, MismatchedSignatureSize_Skipped) {
  // List type matches but per-entry size doesn't, so the list describes
  // a different algorithm and must be skipped.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha384EntrySize, 1);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0xCC);
  DIGEST_CACHE        Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = TRUE;

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestInDatabaseTest, MatchInSecondList_Found) {
  // First list is the wrong algorithm, second list contains the target.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertX509Guid, 0, sizeof (EFI_GUID) + 16, 1);
  size_t  SecondOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 2);

  std::vector<UINT8>  Target (kSha256DigestSize, 0x77);

  SetEntryPayload (Db, SecondOff, 1, Target);

  DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Target);
  BOOLEAN       Found = FALSE;

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_TRUE (Found);
}

TEST (IsImageDigestInDatabaseTest, NonZeroSignatureHeaderSize_EntryMathCorrect) {
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

  DIGEST_CACHE  Cache = MakeBoundCache (&gEfiCertSha256Guid, Target);
  BOOLEAN       Found = FALSE;

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_TRUE (Found);
}

TEST (IsImageDigestInDatabaseTest, ZeroEntryList_NotFound) {
  // A well-formed list with zero entries must be skipped without a
  // false positive (EntryCount == 0 means the inner loop never runs).
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 0);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0x00);
  DIGEST_CACHE        Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = TRUE;

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_SUCCESS);
  EXPECT_FALSE (Found);
}

TEST (IsImageDigestInDatabaseTest, MalformedDb_ReturnsCorrupted) {
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  ((EFI_SIGNATURE_LIST *)Db.data ())->SignatureListSize = (UINT32)(Db.size () + 1);

  std::vector<UINT8>  Digest (kSha256DigestSize, 0x00);
  DIGEST_CACHE        Cache = MakeBoundCache (&gEfiCertSha256Guid, Digest);
  BOOLEAN             Found = FALSE;

  EXPECT_EQ (IsImageDigestInDatabase (Db.data (), Db.size (), &Cache, &Found), EFI_VOLUME_CORRUPTED);
}

TEST (IsImageDigestInDatabaseTest, ZeroSizeNonNullDatabase_EmptyDatabaseNotFound) {
  UINT8         Dummy = 0;
  DIGEST_CACHE  Cache;
  BOOLEAN       Found = TRUE;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = (const VOID *)(UINTN)1;
  Cache.BufferSize = 1;

  EXPECT_EQ (IsImageDigestInDatabase (&Dummy, 0, &Cache, &Found), EFI_SUCCESS);
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
  VOID   *Buffer    = NULL;
  UINTN  BufferSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabase (NULL, &Buffer, &BufferSize),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (LoadSignatureDatabaseTest, NullBuffer_ReturnsInvalidParameter) {
  UINTN  BufferSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", NULL, &BufferSize),
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

  VOID   *Buffer    = (VOID *)(UINTN)0xDEADBEEF; // pre-set: must be cleared
  UINTN  BufferSize = 0xAA;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", &Buffer, &BufferSize),
    EFI_SUCCESS
    );
  EXPECT_EQ (Buffer, (VOID *)NULL);
  EXPECT_EQ (BufferSize, 0u);
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
             OUT      UINTN     *BufferSize
         ) -> EFI_STATUS {
    (VOID)Name;
    (VOID)Guid;
    *Value      = AllocateCopyPool (sizeof (kPayload), kPayload);
    *BufferSize = sizeof (kPayload);
    return EFI_SUCCESS;
  }
         )
       );

  VOID   *Buffer    = NULL;
  UINTN  BufferSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", &Buffer, &BufferSize),
    EFI_SUCCESS
    );
  ASSERT_NE (Buffer, (VOID *)NULL);
  EXPECT_EQ (BufferSize, sizeof (kPayload));
  EXPECT_EQ (CompareMem (Buffer, kPayload, sizeof (kPayload)), 0);

  FreePool (Buffer);
}

TEST_F (LoadSignatureDatabaseTest, GetVariableUnexpectedError_PropagatedVerbatim) {
  // Errors other than EFI_NOT_FOUND must be reported unchanged.
  EXPECT_CALL (UefiLibMock, GetVariable2 (_, _, _, _))
    .WillOnce (Return (EFI_DEVICE_ERROR));

  VOID   *Buffer    = NULL;
  UINTN  BufferSize = 0;

  EXPECT_EQ (
    LoadSignatureDatabase ((const CHAR16 *)u"db", &Buffer, &BufferSize),
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
                                   OUT      UINTN     *BufferSize
           ) -> EFI_STATUS {
    (VOID)Name;
    (VOID)Guid;
    *Value      = AllocateCopyPool (PayloadSize, Payload);
    *BufferSize = PayloadSize;
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
             OUT      UINTN     *BufferSize
         ) -> EFI_STATUS {
    (VOID)Name;
    (VOID)Guid;
    *Value      = AllocatePool (8);
    *BufferSize = 8;
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

// ---------------------------------------------------------------------------
// IsTBSCertHashInDbx -- additional list-handling coverage
// ---------------------------------------------------------------------------

//
// Dbx is too small to even contain one EFI_SIGNATURE_LIST header.
// DatabaseIterInit must reject it and the helper must fail closed
// (return TRUE).
//
TEST (IsTBSCertHashInDbxTest, MalformedDbx_ReturnsTrue) {
  UINT8  TBSCert[] = { 0xDE, 0xAD };
  // Less than sizeof(EFI_SIGNATURE_LIST) -> DatabaseIterInit returns corrupted.
  std::vector<UINT8>  Dbx (4, 0);

  EXPECT_TRUE (IsTBSCertHashInDbx (TBSCert, sizeof (TBSCert), Dbx.data (), Dbx.size ()));
}

//
// Dbx contains exactly one list whose SignatureType is not any of the
// supported gEfiCertX509ShaXXXGuid values. The helper must skip it
// and return FALSE.
//
TEST (IsTBSCertHashInDbxTest, UnsupportedShaList_ReturnsFalse) {
  MockBaseCryptLib    BaseCryptLibMock;
  UINT8               TBSCert[] = { 0xDE };
  std::vector<UINT8>  Dbx;

  // gEfiCertSha256Guid is an image-hash list type, not a cert-hash list type.
  AppendSignatureList (Dbx, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  // Neither hash routine should be invoked.
  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _)).Times (0);
  EXPECT_CALL (BaseCryptLibMock, Sha384HashAll (_, _, _)).Times (0);
  EXPECT_CALL (BaseCryptLibMock, Sha512HashAll (_, _, _)).Times (0);

  EXPECT_FALSE (IsTBSCertHashInDbx (TBSCert, sizeof (TBSCert), Dbx.data (), Dbx.size ()));
}

//
// Dbx is an X509-SHA384 list with no matching entry. The helper must
// take the SHA-384 branch (Sha384HashAll) and return FALSE.
//
TEST (IsTBSCertHashInDbxTest, Sha384List_NoMatch_ReturnsFalse) {
  MockBaseCryptLib    BaseCryptLibMock;
  UINT8               TBSCert[] = { 0xDE };
  const UINT32        EntrySize = (UINT32)(sizeof (EFI_GUID) + SHA384_DIGEST_SIZE);
  std::vector<UINT8>  Dbx;

  AppendSignatureList (Dbx, gEfiCertX509Sha384Guid, 0, EntrySize, 1);

  EXPECT_CALL (BaseCryptLibMock, Sha384HashAll (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST VOID *, UINTN, UINT8 *Digest) -> BOOLEAN {
    std::memset (Digest, 0x11, SHA384_DIGEST_SIZE);
    return TRUE;
  }
         )
       );

  EXPECT_FALSE (IsTBSCertHashInDbx (TBSCert, sizeof (TBSCert), Dbx.data (), Dbx.size ()));
}

//
// Dbx is an X509-SHA512 list that contains the matching cert hash.
// The helper must take the SHA-512 branch (Sha512HashAll) and return
// TRUE.
//
TEST (IsTBSCertHashInDbxTest, Sha512List_Match_ReturnsTrue) {
  MockBaseCryptLib    BaseCryptLibMock;
  UINT8               TBSCert[] = { 0xDE };
  const UINT32        EntrySize = (UINT32)(sizeof (EFI_GUID) + SHA512_DIGEST_SIZE);
  std::vector<UINT8>  Dbx;

  size_t  Off = AppendSignatureList (Dbx, gEfiCertX509Sha512Guid, 0, EntrySize, 1);

  SetEntryPayload (Dbx, Off, 0, std::vector<UINT8>(SHA512_DIGEST_SIZE, 0x99));

  EXPECT_CALL (BaseCryptLibMock, Sha512HashAll (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST VOID *, UINTN, UINT8 *Digest) -> BOOLEAN {
    std::memset (Digest, 0x99, SHA512_DIGEST_SIZE);
    return TRUE;
  }
         )
       );

  EXPECT_TRUE (IsTBSCertHashInDbx (TBSCert, sizeof (TBSCert), Dbx.data (), Dbx.size ()));
}

//
// The hash routine itself fails (Sha256HashAll returns FALSE).
// The helper must fail closed and return TRUE.
//
TEST (IsTBSCertHashInDbxTest, HashFails_FailsClosed_ReturnsTrue) {
  MockBaseCryptLib    BaseCryptLibMock;
  UINT8               TBSCert[] = { 0xDE };
  std::vector<UINT8>  Dbx;

  AppendSignatureList (Dbx, gEfiCertX509Sha256Guid, 0, kSha256EntrySize, 1);

  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .WillOnce (Return (FALSE));

  EXPECT_TRUE (IsTBSCertHashInDbx (TBSCert, sizeof (TBSCert), Dbx.data (), Dbx.size ()));
}

//
// Dbx X509-SHA256 list whose SignatureSize is too small to contain a
// 32-byte digest. The helper must fail closed and return TRUE.
//
TEST (IsTBSCertHashInDbxTest, SignatureSizeTooSmall_FailsClosed_ReturnsTrue) {
  MockBaseCryptLib  BaseCryptLibMock;
  UINT8             TBSCert[] = { 0xDE };
  // EntrySize = GUID + 16 bytes -- smaller than required for a SHA-256 digest.
  const UINT32        EntrySize = (UINT32)(sizeof (EFI_GUID) + 16);
  std::vector<UINT8>  Dbx;

  AppendSignatureList (Dbx, gEfiCertX509Sha256Guid, 0, EntrySize, 1);

  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST VOID *, UINTN, UINT8 *Digest) -> BOOLEAN {
    std::memset (Digest, 0x00, SHA256_DIGEST_SIZE);
    return TRUE;
  }
         )
       );

  EXPECT_TRUE (IsTBSCertHashInDbx (TBSCert, sizeof (TBSCert), Dbx.data (), Dbx.size ()));
}

//
// Dbx X509-SHA256 list that passes the size check but whose
// SignatureHeaderSize is inconsistent with SignatureListSize, causing
// SigListIterInit to fail. The helper must fail closed and return
// TRUE.
//
TEST (IsTBSCertHashInDbxTest, SigListIterInitFails_FailsClosed_ReturnsTrue) {
  MockBaseCryptLib    BaseCryptLibMock;
  UINT8               TBSCert[] = { 0xDE };
  std::vector<UINT8>  Dbx;

  // Build a list with a SignatureHeaderSize larger than the list itself
  // allows. We size the list to contain a single SHA-256 cert-hash entry
  // (so the size check at the top of IsX509HashInList passes), but
  // the inflated SignatureHeaderSize makes SigListIterInit reject it.
  const UINT32  EntrySize = kSha256EntrySize;
  const UINT32  ListSize  = (UINT32)(sizeof (EFI_SIGNATURE_LIST) + EntrySize);

  Dbx.resize (ListSize, 0);

  EFI_SIGNATURE_LIST  *List = (EFI_SIGNATURE_LIST *)Dbx.data ();

  CopyMem (&List->SignatureType, &gEfiCertX509Sha256Guid, sizeof (EFI_GUID));
  List->SignatureListSize = ListSize;
  // SignatureHeaderSize > SignatureListSize - sizeof (EFI_SIGNATURE_LIST).
  List->SignatureHeaderSize = ListSize;
  List->SignatureSize       = EntrySize;

  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST VOID *, UINTN, UINT8 *Digest) -> BOOLEAN {
    std::memset (Digest, 0x00, SHA256_DIGEST_SIZE);
    return TRUE;
  }
         )
       );

  EXPECT_TRUE (IsTBSCertHashInDbx (TBSCert, sizeof (TBSCert), Dbx.data (), Dbx.size ()));
}

//
// Dbx contains two X509-SHA256 lists for the same certificate. The
// TBS digest should be computed once and reused for the second list.
//
TEST (IsTBSCertHashInDbxTest, RepeatedSha256Lists_UsesCachedDigest_ReturnsFalse) {
  MockBaseCryptLib    BaseCryptLibMock;
  UINT8               TBSCert[] = { 0xDE };
  std::vector<UINT8>  Dbx;

  size_t  Off0 = AppendSignatureList (Dbx, gEfiCertX509Sha256Guid, 0, kSha256EntrySize, 1);
  size_t  Off1 = AppendSignatureList (Dbx, gEfiCertX509Sha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Dbx, Off0, 0, std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x11));
  SetEntryPayload (Dbx, Off1, 0, std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x22));

  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .Times (1)
    .WillOnce (
       Invoke (
         [] (CONST VOID *, UINTN, UINT8 *Digest) -> BOOLEAN {
    std::memset (Digest, 0xAA, SHA256_DIGEST_SIZE);
    return TRUE;
  }
         )
       );

  EXPECT_FALSE (IsTBSCertHashInDbx (TBSCert, sizeof (TBSCert), Dbx.data (), Dbx.size ()));
}
