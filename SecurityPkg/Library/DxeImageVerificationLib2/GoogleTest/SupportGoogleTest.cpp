/** @file
  Unit tests for helpers in DxeImageVerificationLib's Support.{c,h}.

  GetImageSecurityDataDirectory: constructs minimal-but-valid PE/COFF
  images in memory and exercises the real PeCoffLib so that the
  data-directory callback path is covered end-to-end.

  GetOrComputeAuthenticodeHash: exercises the slot-indexed digest
  cache plumbing. Hit-path tests pre-seed cache slots directly so the
  test does not depend on GetAuthenticodeHash succeeding for a
  particular byte sequence; miss-path tests use MockBaseCryptLib to
  drive GetAuthenticodeHash to a chosen status / output.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockBaseCryptLib.h>

#include <vector>
#include <cstring>

extern "C" {
  #include <Uefi.h>
  #include <IndustryStandard/PeImage.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/BaseCryptLib.h>
  #include "../Support.h"
}

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

//
// Layout constants for the synthetic PE32+ image.
//
// The buffer is a single contiguous blob laid out as:
//   [DOS hdr][NT64 hdrs][1 section hdr][padding to SizeOfHeaders][image body]
//
// All sizes are picked to satisfy PeCoffLoaderGetImageInfo's
// consistency checks (NumberOfRvaAndSizes, SizeOfOptionalHeader,
// SectionHeaderOffset, SizeOfHeaders < SizeOfImage, last-byte reads of
// SizeOfHeaders and the security directory).
//
static constexpr UINT32  kDosHdrSize    = sizeof (EFI_IMAGE_DOS_HEADER);
static constexpr UINT32  kNt64Size      = sizeof (EFI_IMAGE_NT_HEADERS64);
static constexpr UINT32  kPeCoffOffset  = kDosHdrSize;
static constexpr UINT32  kSizeOfHeaders = 0x200;
static constexpr UINT32  kSizeOfImage   = 0x400;
static constexpr UINT32  kSecDirVa      = 0x300;
static constexpr UINT32  kSecDirSize    = 0x100;

/**
  Build a minimal valid PE32+ image in heap-backed storage.
  When IncludeSecurityDir is true, the returned image's
  EFI_IMAGE_DIRECTORY_ENTRY_SECURITY entry points at [kSecDirVa,
  kSecDirVa + kSecDirSize). Otherwise that entry is left zero.
**/
static std::vector<UINT8>
BuildPe32PlusImage (
  bool  IncludeSecurityDir
  )
{
  std::vector<UINT8>  Image (kSizeOfImage, 0);

  EFI_IMAGE_DOS_HEADER    *Dos = (EFI_IMAGE_DOS_HEADER *)Image.data ();
  EFI_IMAGE_NT_HEADERS64  *Nt  = (EFI_IMAGE_NT_HEADERS64 *)(Image.data () + kPeCoffOffset);

  Dos->e_magic  = EFI_IMAGE_DOS_SIGNATURE;
  Dos->e_lfanew = kPeCoffOffset;

  Nt->Signature                          = EFI_IMAGE_NT_SIGNATURE;
  Nt->FileHeader.Machine                 = IMAGE_FILE_MACHINE_X64;
  Nt->FileHeader.NumberOfSections        = 1;
  Nt->FileHeader.SizeOfOptionalHeader    = sizeof (EFI_IMAGE_OPTIONAL_HEADER64);
  Nt->OptionalHeader.Magic               = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt->OptionalHeader.SizeOfImage         = kSizeOfImage;
  Nt->OptionalHeader.SizeOfHeaders       = kSizeOfHeaders;
  Nt->OptionalHeader.SectionAlignment    = 0x200;
  Nt->OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;

  if (IncludeSecurityDir) {
    Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = kSecDirVa;
    Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size           = kSecDirSize;
  }

  return Image;
}

class GetImageSecurityDataDirectoryTest : public ::testing::Test {
};

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

TEST_F (GetImageSecurityDataDirectoryTest, NullFileBuffer_ReturnsInvalidParameter) {
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (NULL, 0x100, &SecDataDir),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (GetImageSecurityDataDirectoryTest, NullSecDataDir_ReturnsInvalidParameter) {
  std::vector<UINT8>  Image = BuildPe32PlusImage (false);

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), NULL),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (GetImageSecurityDataDirectoryTest, NullFileBuffer_DoesNotTouchSecDataDir) {
  //
  // Caller-supplied SecDataDir must be untouched on the early
  // invalid-parameter return; only the success path is allowed to
  // overwrite it.
  //
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  SetMem (&SecDataDir, sizeof (SecDataDir), 0xAA);

  EXPECT_EQ (
    GetImageSecurityDataDirectory (NULL, 0x100, &SecDataDir),
    EFI_INVALID_PARAMETER
    );
  EXPECT_EQ (SecDataDir.VirtualAddress, 0xAAAAAAAAu);
  EXPECT_EQ (SecDataDir.Size, 0xAAAAAAAAu);
}

// ---------------------------------------------------------------------------
// Malformed images
// ---------------------------------------------------------------------------

TEST_F (GetImageSecurityDataDirectoryTest, GarbageBuffer_ReturnsLoadError) {
  //
  // A buffer that is large enough to attempt header parsing but does
  // not actually carry valid DOS/NT signatures must be rejected.
  //
  std::vector<UINT8>        Buffer (kSizeOfImage, 0xAB);
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Buffer.data (), Buffer.size (), &SecDataDir),
    EFI_LOAD_ERROR
    );
}

TEST_F (GetImageSecurityDataDirectoryTest, TinyBuffer_ReturnsLoadError) {
  //
  // A buffer too small to contain a DOS header must be rejected
  // without dereferencing any of the bytes.
  //
  UINT8                     TinyBuffer[4] = { 0 };
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (TinyBuffer, sizeof (TinyBuffer), &SecDataDir),
    EFI_LOAD_ERROR
    );
}

TEST_F (GetImageSecurityDataDirectoryTest, ZeroFileSize_ReturnsLoadError) {
  UINT8                     Byte = 0;
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (&Byte, 0, &SecDataDir),
    EFI_LOAD_ERROR
    );
}

TEST_F (GetImageSecurityDataDirectoryTest, ElfanewPastEof_ReturnsLoadError) {
  //
  // Valid DOS signature but e_lfanew points well past the end of the
  // buffer. The bounded reader must refuse to fetch the NT headers.
  //
  std::vector<UINT8>    Image = BuildPe32PlusImage (false);
  EFI_IMAGE_DOS_HEADER  *Dos  = (EFI_IMAGE_DOS_HEADER *)Image.data ();

  Dos->e_lfanew = (UINT32)(Image.size () + 0x1000);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), &SecDataDir),
    EFI_LOAD_ERROR
    );
}

TEST_F (GetImageSecurityDataDirectoryTest, TruncatedAtNtHeaders_ReturnsLoadError) {
  //
  // Buffer is truncated to the DOS header only, so the read of the NT
  // headers at e_lfanew straddles EOF.
  //
  std::vector<UINT8>  Image = BuildPe32PlusImage (false);

  Image.resize (sizeof (EFI_IMAGE_DOS_HEADER));

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), &SecDataDir),
    EFI_LOAD_ERROR
    );
}

TEST_F (GetImageSecurityDataDirectoryTest, ValidDosBadNtSignature_ReturnsLoadError) {
  //
  // Valid DOS header but corrupted NT signature -- exercises the NT
  // signature validation path inside PeCoffLib.
  //
  std::vector<UINT8>      Image = BuildPe32PlusImage (false);
  EFI_IMAGE_NT_HEADERS64  *Nt   = (EFI_IMAGE_NT_HEADERS64 *)(Image.data () + kPeCoffOffset);

  Nt->Signature = 0xDEADBEEF;

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), &SecDataDir),
    EFI_LOAD_ERROR
    );
}

// ---------------------------------------------------------------------------
// Happy paths exercised through real PeCoffLib + the data-directory callback
// ---------------------------------------------------------------------------

TEST_F (GetImageSecurityDataDirectoryTest, ValidImageWithoutSecurityDir_ReturnsZeroedDir) {
  std::vector<UINT8>        Image = BuildPe32PlusImage (false);
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  //
  // Pre-poison SecDataDir so we can prove the function actually wrote
  // back zeros (rather than leaving stale caller-supplied bytes).
  //
  SetMem (&SecDataDir, sizeof (SecDataDir), 0xCD);

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), &SecDataDir),
    EFI_SUCCESS
    );
  EXPECT_EQ (SecDataDir.VirtualAddress, 0u);
  EXPECT_EQ (SecDataDir.Size, 0u);
}

TEST_F (GetImageSecurityDataDirectoryTest, ValidImageWithSecurityDir_ReturnsCapturedDir) {
  std::vector<UINT8>        Image = BuildPe32PlusImage (true);
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), &SecDataDir),
    EFI_SUCCESS
    );
  EXPECT_EQ (SecDataDir.VirtualAddress, kSecDirVa);
  EXPECT_EQ (SecDataDir.Size, kSecDirSize);
}

TEST_F (GetImageSecurityDataDirectoryTest, OtherDataDirectoriesDoNotLeak) {
  //
  // Populate a non-SECURITY data directory entry (export table) with
  // a recognizable value to prove the callback only captures the
  // SECURITY index and ignores every other directory PeCoffLib walks.
  //
  std::vector<UINT8>      Image = BuildPe32PlusImage (true);
  EFI_IMAGE_NT_HEADERS64  *Nt   = (EFI_IMAGE_NT_HEADERS64 *)(Image.data () + kPeCoffOffset);

  Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0xCAFEBABE;
  Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].Size           = 0xBEEFu;

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), &SecDataDir),
    EFI_SUCCESS
    );
  EXPECT_EQ (SecDataDir.VirtualAddress, kSecDirVa);
  EXPECT_EQ (SecDataDir.Size, kSecDirSize);
}

// ===========================================================================
// GetOrComputeAuthenticodeHash
// ===========================================================================

class GetOrComputeAuthenticodeHashTest : public ::testing::Test {
protected:
  MockBaseCryptLib BaseCryptLibMock;
  IMAGE_DIGEST_CACHE Cache{ };
  std::vector<UINT8> FileBytes{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33 };

  void
  SetUp (
    ) override
  {
    ZeroMem (&Cache, sizeof (Cache));
  }

  //
  // Verify every slot in Cache currently looks empty (Size == 0 and
  // Bytes all-zero). Used to assert early returns do not scribble.
  //
  void
  ExpectCacheUntouched (
    )
  {
    for (UINTN I = 0; I < (sizeof (Cache.Entries) / sizeof (Cache.Entries[0])); I++) {
      EXPECT_EQ (Cache.Entries[I].Size, (UINTN)0);
      for (UINTN J = 0; J < sizeof (Cache.Entries[I].Bytes); J++) {
        EXPECT_EQ (Cache.Entries[I].Bytes[J], (UINT8)0);
      }
    }
  }
};

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

TEST_F (GetOrComputeAuthenticodeHashTest, NullFileBuffer_ReturnsInvalidParameter) {
  CONST UINT8  *Digest    = NULL;
  UINTN        DigestSize = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (NULL, FileBytes.size (), &gEfiCertSha256Guid, &Cache, &Digest, &DigestSize),
    EFI_INVALID_PARAMETER
    );
  ExpectCacheUntouched ();
}

TEST_F (GetOrComputeAuthenticodeHashTest, NullHashType_ReturnsInvalidParameter) {
  CONST UINT8  *Digest    = NULL;
  UINTN        DigestSize = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), NULL, &Cache, &Digest, &DigestSize),
    EFI_INVALID_PARAMETER
    );
  ExpectCacheUntouched ();
}

TEST_F (GetOrComputeAuthenticodeHashTest, NullCache_ReturnsInvalidParameter) {
  CONST UINT8  *Digest    = NULL;
  UINTN        DigestSize = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), &gEfiCertSha256Guid, NULL, &Digest, &DigestSize),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (GetOrComputeAuthenticodeHashTest, NullDigest_ReturnsInvalidParameter) {
  UINTN  DigestSize = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), &gEfiCertSha256Guid, &Cache, NULL, &DigestSize),
    EFI_INVALID_PARAMETER
    );
  ExpectCacheUntouched ();
}

TEST_F (GetOrComputeAuthenticodeHashTest, NullDigestSize_ReturnsInvalidParameter) {
  CONST UINT8  *Digest = NULL;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), &gEfiCertSha256Guid, &Cache, &Digest, NULL),
    EFI_INVALID_PARAMETER
    );
  ExpectCacheUntouched ();
}

// ---------------------------------------------------------------------------
// Algorithm validation
// ---------------------------------------------------------------------------

TEST_F (GetOrComputeAuthenticodeHashTest, X509Sha256Guid_ReturnsUnsupported) {
  //
  // X509-with-hash GUIDs are valid signature-type GUIDs but are not
  // image hash algorithms and have no cache slot.
  //
  CONST UINT8  *Digest    = NULL;
  UINTN        DigestSize = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), &gEfiCertX509Sha256Guid, &Cache, &Digest, &DigestSize),
    EFI_UNSUPPORTED
    );
  ExpectCacheUntouched ();
}

TEST_F (GetOrComputeAuthenticodeHashTest, ArbitraryGuid_ReturnsUnsupported) {
  EFI_GUID     Junk = { 0x12345678, 0x1234, 0x5678,
                        { 0x9a,     0xbc,   0xde,  0xf0,0x12, 0x34, 0x56, 0x78 }
  };
  CONST UINT8  *Digest    = NULL;
  UINTN        DigestSize = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), &Junk, &Cache, &Digest, &DigestSize),
    EFI_UNSUPPORTED
    );
  ExpectCacheUntouched ();
}

// ---------------------------------------------------------------------------
// Hit path (cache pre-seeded so GetAuthenticodeHash is bypassed)
// ---------------------------------------------------------------------------

TEST_F (GetOrComputeAuthenticodeHashTest, PreSeededSha256Slot_ReturnsPointerIntoCache) {
  UINTN  Index = 0;

  ASSERT_TRUE (GetKnownImageHashGuidIndex (&gEfiCertSha256Guid, &Index));

  //
  // Seed the slot with a recognizable byte pattern so we can prove
  // the returned pointer aliases the cache storage and the returned
  // size matches what we stored.
  //
  for (UINTN I = 0; I < SHA256_DIGEST_SIZE; I++) {
    Cache.Entries[Index].Bytes[I] = (UINT8)(0x40 + I);
  }

  Cache.Entries[Index].Size = SHA256_DIGEST_SIZE;

  CONST UINT8  *Digest    = NULL;
  UINTN        DigestSize = 0;

  //
  // A hit must not delegate to GetAuthenticodeHash, so the contents
  // of FileBuffer are irrelevant on this path. No EXPECT_CALL is set
  // up; an accidental invocation would be reported by gmock.
  //
  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), &gEfiCertSha256Guid, &Cache, &Digest, &DigestSize),
    EFI_SUCCESS
    );
  EXPECT_EQ (DigestSize, (UINTN)SHA256_DIGEST_SIZE);
  EXPECT_EQ (Digest, Cache.Entries[Index].Bytes);
  for (UINTN I = 0; I < SHA256_DIGEST_SIZE; I++) {
    EXPECT_EQ (Digest[I], (UINT8)(0x40 + I));
  }
}

TEST_F (GetOrComputeAuthenticodeHashTest, EachKnownAlgorithm_HitsItsOwnSlot) {
  //
  // Seed every known-algorithm slot with a distinct one-byte digest
  // and verify each lookup returns its own slot's bytes, proving the
  // GUID-to-index mapping is consistent between the cache layout and
  // GetOrComputeAuthenticodeHash.
  //
  CONST EFI_GUID  *KnownGuids[] = {
    &gEfiCertSha1Guid,
    &gEfiCertSha256Guid,
    &gEfiCertSha384Guid,
    &gEfiCertSha512Guid
  };

  for (UINTN K = 0; K < sizeof (KnownGuids) / sizeof (KnownGuids[0]); K++) {
    UINTN  Index = 0;
    ASSERT_TRUE (GetKnownImageHashGuidIndex (KnownGuids[K], &Index));

    Cache.Entries[Index].Bytes[0] = (UINT8)(0xA0 + K);
    Cache.Entries[Index].Size     = 1;
  }

  for (UINTN K = 0; K < sizeof (KnownGuids) / sizeof (KnownGuids[0]); K++) {
    CONST UINT8  *Digest    = NULL;
    UINTN        DigestSize = 0;

    EXPECT_EQ (
      GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), KnownGuids[K], &Cache, &Digest, &DigestSize),
      EFI_SUCCESS
      );
    EXPECT_EQ (DigestSize, (UINTN)1);
    ASSERT_NE (Digest, (CONST UINT8 *)NULL);
    EXPECT_EQ (Digest[0], (UINT8)(0xA0 + K));
  }
}

TEST_F (GetOrComputeAuthenticodeHashTest, RepeatedHits_ReturnSamePointer) {
  UINTN  Index = 0;

  ASSERT_TRUE (GetKnownImageHashGuidIndex (&gEfiCertSha1Guid, &Index));
  Cache.Entries[Index].Bytes[0] = 0x5A;
  Cache.Entries[Index].Size     = 1;

  CONST UINT8  *FirstDigest  = NULL;
  UINTN        FirstSize     = 0;
  CONST UINT8  *SecondDigest = NULL;
  UINTN        SecondSize    = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), &gEfiCertSha1Guid, &Cache, &FirstDigest, &FirstSize),
    EFI_SUCCESS
    );
  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (FileBytes.data (), FileBytes.size (), &gEfiCertSha1Guid, &Cache, &SecondDigest, &SecondSize),
    EFI_SUCCESS
    );
  EXPECT_EQ (FirstDigest, SecondDigest);
  EXPECT_EQ (FirstSize, SecondSize);
}

// ---------------------------------------------------------------------------
// Miss path (GetAuthenticodeHash driven by MockBaseCryptLib)
// ---------------------------------------------------------------------------

TEST_F (GetOrComputeAuthenticodeHashTest, GetAuthenticodeHashFails_PropagatesErrorAndPreservesEmptySlot) {
  //
  // When the underlying GetAuthenticodeHash returns an error, the
  // status must propagate verbatim and the slot must remain empty
  // (Size == 0) so a later call retries the computation rather than
  // returning stale bytes.
  //
  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHash (_, _, _, _, _))
    .WillOnce (Return (EFI_DEVICE_ERROR));

  CONST UINT8  *Digest    = NULL;
  UINTN        DigestSize = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (
      FileBytes.data (),
      FileBytes.size (),
      &gEfiCertSha256Guid,
      &Cache,
      &Digest,
      &DigestSize
      ),
    EFI_DEVICE_ERROR
    );

  UINTN  Index = 0;

  ASSERT_TRUE (GetKnownImageHashGuidIndex (&gEfiCertSha256Guid, &Index));
  EXPECT_EQ (Cache.Entries[Index].Size, (UINTN)0);

  //
  // Other slots must also be untouched: an unrelated algorithm should
  // not be affected by another algorithm's miss-failure.
  //
  for (UINTN I = 0; I < (sizeof (Cache.Entries) / sizeof (Cache.Entries[0])); I++) {
    if (I != Index) {
      EXPECT_EQ (Cache.Entries[I].Size, (UINTN)0);
    }
  }
}

TEST_F (GetOrComputeAuthenticodeHashTest, MissSucceeds_PopulatesCacheAndSecondCallSkipsRecomputation) {
  //
  // Drive GetAuthenticodeHash to a successful return with a known
  // digest pattern, then call GetOrComputeAuthenticodeHash twice for
  // the same algorithm. The .Times (1) constraint asserts the second
  // call must NOT delegate to GetAuthenticodeHash again -- it must be
  // served from the cache.
  //
  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHash (_, _, _, _, _))
    .Times (1)
    .WillOnce (
       Invoke (
         [] (
             IN VOID            *FileBuffer,
             IN UINTN           FileSize,
             IN CONST EFI_GUID  *HashType,
             OUT UINT8          *Digest,
             OUT UINTN          *DigestSize
         ) -> EFI_STATUS {
    (VOID)FileBuffer;
    (VOID)FileSize;
    (VOID)HashType;
    for (UINTN I = 0; I < SHA256_DIGEST_SIZE; I++) {
      Digest[I] = (UINT8)(0x80 + I);
    }

    *DigestSize = SHA256_DIGEST_SIZE;
    return EFI_SUCCESS;
  }
         )
       );

  CONST UINT8  *DigestPtr1 = NULL;
  UINTN        DigestSize1 = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (
      FileBytes.data (),
      FileBytes.size (),
      &gEfiCertSha256Guid,
      &Cache,
      &DigestPtr1,
      &DigestSize1
      ),
    EFI_SUCCESS
    );
  EXPECT_EQ (DigestSize1, (UINTN)SHA256_DIGEST_SIZE);
  ASSERT_NE (DigestPtr1, (CONST UINT8 *)NULL);
  for (UINTN I = 0; I < SHA256_DIGEST_SIZE; I++) {
    EXPECT_EQ (DigestPtr1[I], (UINT8)(0x80 + I));
  }

  //
  // The slot must now look populated.
  //
  UINTN  Index = 0;

  ASSERT_TRUE (GetKnownImageHashGuidIndex (&gEfiCertSha256Guid, &Index));
  EXPECT_EQ (Cache.Entries[Index].Size, (UINTN)SHA256_DIGEST_SIZE);
  EXPECT_EQ (DigestPtr1, Cache.Entries[Index].Bytes);

  //
  // Second call -- expected to be served from the cache. The
  // EXPECT_CALL above limits GetAuthenticodeHash invocations to 1;
  // a second invocation would fail this test.
  //
  CONST UINT8  *DigestPtr2 = NULL;
  UINTN        DigestSize2 = 0;

  EXPECT_EQ (
    GetOrComputeAuthenticodeHash (
      FileBytes.data (),
      FileBytes.size (),
      &gEfiCertSha256Guid,
      &Cache,
      &DigestPtr2,
      &DigestSize2
      ),
    EFI_SUCCESS
    );
  EXPECT_EQ (DigestPtr1, DigestPtr2);
  EXPECT_EQ (DigestSize1, DigestSize2);
}
