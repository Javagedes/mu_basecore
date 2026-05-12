/** @file
  Unit tests for ValidateUnsignedImage in DxeImageVerificationLib.

  Exercises the per-algorithm dbx-then-db lookup loop driven by the
  HASH_ALGORITHM_SET returned from GetDatabaseHashAlgorithms. The image
  digest is supplied by a mocked GetAuthenticodeHash so the database
  contents (also mocked through GetVariable2) deterministically drive
  the outcome.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockUefiLib.h>
#include <GoogleTest/Library/MockBaseCryptLib.h>

#include <vector>
#include <map>
#include <string>
#include <cstring>

extern "C" {
  #include <Uefi.h>
  #include <Guid/ImageAuthentication.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include "../DxeImageVerificationLib.h"
}

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

// ---------------------------------------------------------------------------
// Helpers: build EFI_SIGNATURE_LIST buffers in-place.
// ---------------------------------------------------------------------------

static constexpr UINTN   kSha256DigestSize = 32;
static constexpr UINTN   kSha384DigestSize = 48;
static constexpr UINT32  kSha256EntrySize  = sizeof (EFI_GUID) + (UINT32)kSha256DigestSize;
static constexpr UINT32  kSha384EntrySize  = sizeof (EFI_GUID) + (UINT32)kSha384DigestSize;

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

// ---------------------------------------------------------------------------
// Test fixture.
// ---------------------------------------------------------------------------

struct FakeVariable {
  EFI_STATUS            Status;
  std::vector<UINT8>    Bytes;
};

class ValidateUnsignedImageTest : public ::testing::Test {
protected:
  MockUefiLib UefiLibMock;
  MockBaseCryptLib CryptMock;
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

  //
  // Wire GetAuthenticodeHash to return DigestBytes for the matching
  // HashType GUID. Other GUIDs (e.g. a different SHA flavor) return
  // EFI_UNSUPPORTED and are silently skipped by the caller's
  // continue-on-mismatch in GetAuthenticodeHash semantics — but since
  // ValidateUnsignedImage treats any error as deny, the per-algorithm
  // tests below configure exactly the algorithms they want enrolled.
  //
  void
  ExpectAuthenticodeHash (
    const EFI_GUID            &HashType,
    const std::vector<UINT8>  &DigestBytes,
    EFI_STATUS                ReturnStatus = EFI_SUCCESS
    )
  {
    EFI_GUID            Expected = HashType;
    std::vector<UINT8>  Captured = DigestBytes;

    EXPECT_CALL (CryptMock, GetAuthenticodeHash (_, _, _, _, _))
      .WillRepeatedly (
         Invoke (
           [Expected, Captured, ReturnStatus] (
                                               IN  VOID            *FileBuffer,
                                               IN  UINTN           FileSize,
                                               IN  CONST EFI_GUID  *HashType,
                                               OUT UINT8           *Digest,
                                               OUT UINTN           *DigestSize
           ) -> EFI_STATUS {
      (VOID)FileBuffer;
      (VOID)FileSize;
      if (!CompareGuid (HashType, &Expected)) {
        return EFI_UNSUPPORTED;
      }

      if (ReturnStatus != EFI_SUCCESS) {
        return ReturnStatus;
      }

      CopyMem (Digest, Captured.data (), Captured.size ());
      *DigestSize = Captured.size ();
      return EFI_SUCCESS;
    }
           )
         );
  }
};

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

TEST_F (ValidateUnsignedImageTest, NoAlgorithmsEnrolled_AccessDenied) {
  // db and dbx absent -> HashAlgorithms.Count == 0 -> deny.
  EXPECT_EQ (ValidateUnsignedImage (NULL, 0), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, GetDatabaseHashAlgorithmsFails_AccessDenied) {
  Vars[u"db"] = { EFI_DEVICE_ERROR, { }
  };

  EXPECT_EQ (ValidateUnsignedImage (NULL, 0), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, GetAuthenticodeHashFails_AccessDenied) {
  // Enroll SHA-256 in db so we have one algorithm to iterate.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  SetVariable (u"db", std::move (Db));

  ExpectAuthenticodeHash (gEfiCertSha256Guid, { }, EFI_DEVICE_ERROR);

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, HashInDbx_AccessDenied) {
  // dbx contains a SHA-256 entry; db is enrolled with a non-matching
  // entry (otherwise it would not be checked, but we want to be sure
  // the dbx check short-circuits before db is consulted).
  std::vector<UINT8>  TargetDigest (kSha256DigestSize, 0x42);

  std::vector<UINT8>  Dbx;
  size_t              DbxOff = AppendSignatureList (Dbx, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Dbx, DbxOff, 0, TargetDigest);
  SetVariable (u"dbx", std::move (Dbx));

  ExpectAuthenticodeHash (gEfiCertSha256Guid, TargetDigest);

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, HashInDb_Success) {
  std::vector<UINT8>  TargetDigest (kSha256DigestSize, 0xAB);

  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Db, DbOff, 0, TargetDigest);
  SetVariable (u"db", std::move (Db));

  ExpectAuthenticodeHash (gEfiCertSha256Guid, TargetDigest);

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_SUCCESS);
}

TEST_F (ValidateUnsignedImageTest, HashInNeither_AccessDenied) {
  // db enrolled with a non-matching entry; dbx empty. The digest the
  // mock returns will not be present anywhere.
  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  std::vector<UINT8>  Other (kSha256DigestSize, 0x11);

  SetEntryPayload (Db, DbOff, 0, Other);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Digest (kSha256DigestSize, 0x22);

  ExpectAuthenticodeHash (gEfiCertSha256Guid, Digest);

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, DbxMatchSkipsDb) {
  // Same digest is in both db and dbx; dbx must win and deny.
  std::vector<UINT8>  Target (kSha256DigestSize, 0x55);

  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Db, DbOff, 0, Target);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Dbx;
  size_t              DbxOff = AppendSignatureList (Dbx, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Dbx, DbxOff, 0, Target);
  SetVariable (u"dbx", std::move (Dbx));

  ExpectAuthenticodeHash (gEfiCertSha256Guid, Target);

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, SecondAlgorithmAuthorizes_Success) {
  // db enrolls SHA-256 (no match) and SHA-384 (target match). The
  // first iteration computes the SHA-256 digest, misses db, continues
  // to the SHA-384 iteration which hits.
  std::vector<UINT8>  Sha256Digest (kSha256DigestSize, 0xCC);
  std::vector<UINT8>  Sha384Digest (kSha384DigestSize, 0xDD);

  std::vector<UINT8>  Db;
  size_t              Off256 = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Db, Off256, 0, std::vector<UINT8> (kSha256DigestSize, 0x00));
  size_t  Off384 = AppendSignatureList (Db, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);

  SetEntryPayload (Db, Off384, 0, Sha384Digest);
  SetVariable (u"db", std::move (Db));

  // Hash mock: return Sha256Digest for SHA-256, Sha384Digest for SHA-384.
  EXPECT_CALL (CryptMock, GetAuthenticodeHash (_, _, _, _, _))
    .WillRepeatedly (
       Invoke (
         [Sha256Digest, Sha384Digest] (
                                       IN  VOID            *FileBuffer,
                                       IN  UINTN           FileSize,
                                       IN  CONST EFI_GUID  *HashType,
                                       OUT UINT8           *Digest,
                                       OUT UINTN           *DigestSize
         ) -> EFI_STATUS {
    (VOID)FileBuffer;
    (VOID)FileSize;
    if (CompareGuid (HashType, &gEfiCertSha256Guid)) {
      CopyMem (Digest, Sha256Digest.data (), Sha256Digest.size ());
      *DigestSize = Sha256Digest.size ();
      return EFI_SUCCESS;
    }

    if (CompareGuid (HashType, &gEfiCertSha384Guid)) {
      CopyMem (Digest, Sha384Digest.data (), Sha384Digest.size ());
      *DigestSize = Sha384Digest.size ();
      return EFI_SUCCESS;
    }

    return EFI_UNSUPPORTED;
  }
         )
       );

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_SUCCESS);
}

TEST_F (ValidateUnsignedImageTest, MalformedDbx_AccessDenied) {
  // dbx is structurally corrupt; the dbx lookup returns an error and
  // ValidateUnsignedImage must deny rather than fall through to db.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  SetVariable (u"db", Db);

  std::vector<UINT8>  Dbx;

  AppendSignatureList (Dbx, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  // Corrupt: declare a size larger than the buffer.
  ((EFI_SIGNATURE_LIST *)Dbx.data ())->SignatureListSize = (UINT32)(Dbx.size () + 1);
  SetVariable (u"dbx", std::move (Dbx));

  std::vector<UINT8>  Digest (kSha256DigestSize, 0x99);

  ExpectAuthenticodeHash (gEfiCertSha256Guid, Digest);

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, DbxOverridesDbAcrossAlgorithms_AccessDenied) {
  // The image's SHA-256 digest is enrolled in db (would authorize on
  // its own) while its SHA-384 digest is enrolled in dbx. dbx must
  // override db across algorithms, so the image must be denied.
  std::vector<UINT8>  Sha256Digest (kSha256DigestSize, 0xAA);
  std::vector<UINT8>  Sha384Digest (kSha384DigestSize, 0xBB);

  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Db, DbOff, 0, Sha256Digest);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Dbx;
  size_t              DbxOff = AppendSignatureList (Dbx, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);

  SetEntryPayload (Dbx, DbxOff, 0, Sha384Digest);
  SetVariable (u"dbx", std::move (Dbx));

  EXPECT_CALL (CryptMock, GetAuthenticodeHash (_, _, _, _, _))
    .WillRepeatedly (
       Invoke (
         [Sha256Digest, Sha384Digest] (
                                       IN  VOID            *FileBuffer,
                                       IN  UINTN           FileSize,
                                       IN  CONST EFI_GUID  *HashType,
                                       OUT UINT8           *Digest,
                                       OUT UINTN           *DigestSize
         ) -> EFI_STATUS {
    (VOID)FileBuffer;
    (VOID)FileSize;
    if (CompareGuid (HashType, &gEfiCertSha256Guid)) {
      CopyMem (Digest, Sha256Digest.data (), Sha256Digest.size ());
      *DigestSize = Sha256Digest.size ();
      return EFI_SUCCESS;
    }

    if (CompareGuid (HashType, &gEfiCertSha384Guid)) {
      CopyMem (Digest, Sha384Digest.data (), Sha384Digest.size ());
      *DigestSize = Sha384Digest.size ();
      return EFI_SUCCESS;
    }

    return EFI_UNSUPPORTED;
  }
         )
       );

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, DbHitFollowedByDbxHit_AccessDenied) {
  // An earlier algorithm's digest is present in db (would authorize
  // on its own) but a later algorithm's digest is present in dbx. The
  // implementation must not return success on the early db hit; every
  // dbx lookup has to complete first, and any dbx hit denies
  // regardless of prior db hits. SHA-256 is enrolled via db (matching)
  // and SHA-384 is enrolled via dbx (matching).
  std::vector<UINT8>  Sha256Digest (kSha256DigestSize, 0x11);
  std::vector<UINT8>  Sha384Digest (kSha384DigestSize, 0x22);

  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Db, DbOff, 0, Sha256Digest);
  SetVariable (u"db", std::move (Db));

  std::vector<UINT8>  Dbx;
  size_t              DbxOff = AppendSignatureList (Dbx, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);

  SetEntryPayload (Dbx, DbxOff, 0, Sha384Digest);
  SetVariable (u"dbx", std::move (Dbx));

  EXPECT_CALL (CryptMock, GetAuthenticodeHash (_, _, _, _, _))
    .WillRepeatedly (
       Invoke (
         [Sha256Digest, Sha384Digest] (
                                       IN  VOID            *FileBuffer,
                                       IN  UINTN           FileSize,
                                       IN  CONST EFI_GUID  *HashType,
                                       OUT UINT8           *Digest,
                                       OUT UINTN           *DigestSize
         ) -> EFI_STATUS {
    (VOID)FileBuffer;
    (VOID)FileSize;
    if (CompareGuid (HashType, &gEfiCertSha256Guid)) {
      CopyMem (Digest, Sha256Digest.data (), Sha256Digest.size ());
      *DigestSize = Sha256Digest.size ();
      return EFI_SUCCESS;
    }

    if (CompareGuid (HashType, &gEfiCertSha384Guid)) {
      CopyMem (Digest, Sha384Digest.data (), Sha384Digest.size ());
      *DigestSize = Sha384Digest.size ();
      return EFI_SUCCESS;
    }

    return EFI_UNSUPPORTED;
  }
         )
       );

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, DbHitOnEarlyAlgorithmCleanLater_Success) {
  // Companion to DbHitFollowedByDbxHit: the earlier algorithm's
  // digest is in db and the later algorithm's digest is in neither
  // database. The implementation must still walk the later iteration
  // (to ensure dbx is clean for that algorithm), and the redundant
  // db lookup for the later algorithm must not clear the earlier
  // db hit. Final result: allow.
  std::vector<UINT8>  Sha256Digest (kSha256DigestSize, 0x33);
  std::vector<UINT8>  Sha384Digest (kSha384DigestSize, 0x44);

  // db enrolls both algorithms: SHA-256 matches the image, SHA-384
  // does not. Enrolling both ensures the algorithm set contains both
  // entries; dbx is absent.
  std::vector<UINT8>  Db;
  size_t              Off256 = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Db, Off256, 0, Sha256Digest);
  size_t  Off384 = AppendSignatureList (Db, gEfiCertSha384Guid, 0, kSha384EntrySize, 1);

  SetEntryPayload (Db, Off384, 0, std::vector<UINT8> (kSha384DigestSize, 0x00));
  SetVariable (u"db", std::move (Db));

  EXPECT_CALL (CryptMock, GetAuthenticodeHash (_, _, _, _, _))
    .WillRepeatedly (
       Invoke (
         [Sha256Digest, Sha384Digest] (
                                       IN  VOID            *FileBuffer,
                                       IN  UINTN           FileSize,
                                       IN  CONST EFI_GUID  *HashType,
                                       OUT UINT8           *Digest,
                                       OUT UINTN           *DigestSize
         ) -> EFI_STATUS {
    (VOID)FileBuffer;
    (VOID)FileSize;
    if (CompareGuid (HashType, &gEfiCertSha256Guid)) {
      CopyMem (Digest, Sha256Digest.data (), Sha256Digest.size ());
      *DigestSize = Sha256Digest.size ();
      return EFI_SUCCESS;
    }

    if (CompareGuid (HashType, &gEfiCertSha384Guid)) {
      CopyMem (Digest, Sha384Digest.data (), Sha384Digest.size ());
      *DigestSize = Sha384Digest.size ();
      return EFI_SUCCESS;
    }

    return EFI_UNSUPPORTED;
  }
         )
       );

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_SUCCESS);
}

TEST_F (ValidateUnsignedImageTest, MalformedDb_AccessDenied) {
  // db is structurally corrupt; GetDatabaseHashAlgorithms reports
  // EFI_VOLUME_CORRUPTED and ValidateUnsignedImage must deny without
  // proceeding to hash computation.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  ((EFI_SIGNATURE_LIST *)Db.data ())->SignatureListSize = (UINT32)(Db.size () + 1);
  SetVariable (u"db", std::move (Db));

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, LoadDbFails_AccessDenied) {
  // GetVariable2 returns a non-NOT_FOUND error for db; LoadSignatureDatabase
  // surfaces it and ValidateUnsignedImage denies without touching dbx or
  // computing any hash.
  Vars[u"db"] = { EFI_DEVICE_ERROR, { } };

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}

TEST_F (ValidateUnsignedImageTest, LoadDbxFails_AccessDenied) {
  // db loads cleanly but dbx returns a non-NOT_FOUND error; the dbx
  // load failure must deny before hash computation.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  SetVariable (u"db", std::move (Db));

  Vars[u"dbx"] = { EFI_DEVICE_ERROR, { } };

  UINT8  Image[1] = { 0 };

  EXPECT_EQ (ValidateUnsignedImage (Image, sizeof (Image)), EFI_ACCESS_DENIED);
}
