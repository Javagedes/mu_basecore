/** @file
  Unit tests for GetImageSecurityDataDirectory in the
  DxeImageVerificationLib.
  These tests construct minimal-but-valid PE/COFF images in memory and
  exercise the real PeCoffLib through GetImageSecurityDataDirectory so
  that the security-data-directory capture path is covered end-to-end.
  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockBaseCryptLib.h>

#include <vector>
#include <cstring>
#include <functional>

extern "C" {
  #include <Uefi.h>
  #include <IndustryStandard/PeImage.h>
  #include <Library/BaseMemoryLib.h>
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
// Happy paths exercised through real PeCoffLib security-directory capture
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
  // a recognizable value to prove PeCoffLib only records the SECURITY
  // entry and ignores every other directory it walks.
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

// ---------------------------------------------------------------------------
// GetHash / FreeDigestCache
// ---------------------------------------------------------------------------

//
// A fixed non-zero buffer for the cache to hash. GetHash () only forwards these bytes to the mocked
// Sha*HashAll (), so their exact contents do not affect the assertions below.
//
static UINT8  mCacheBuffer[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

//
// A gmock action for the Sha*HashAll () mocks: fill DigestSize bytes of the output digest with Fill
// and report success, standing in for a real hash of the bound buffer.
//
static std::function<BOOLEAN (CONST VOID *, UINTN, UINT8 *)>
FillDigest (
  UINTN  DigestSize,
  UINT8  Fill
  )
{
  return [DigestSize, Fill](CONST VOID *Data, UINTN DataSize, UINT8 *HashValue) -> BOOLEAN {
           (VOID)Data;
           (VOID)DataSize;
           SetMem (HashValue, DigestSize, Fill);
           return TRUE;
  };
}

TEST (GetHashTest, NullParameters_ReturnsInvalidParameter) {
  DIGEST_CACHE  Cache;
  CONST UINT8   *Digest    = NULL;
  UINTN         DigestSize = 0;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = mCacheBuffer;
  Cache.BufferSize = sizeof (mCacheBuffer);

  EXPECT_EQ (GetHash (NULL, &Cache, &Digest, &DigestSize), EFI_INVALID_PARAMETER);
  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, NULL, &Digest, &DigestSize), EFI_INVALID_PARAMETER);
  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, NULL, &DigestSize), EFI_INVALID_PARAMETER);
  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest, NULL), EFI_INVALID_PARAMETER);
}

TEST (GetHashTest, CacheWithoutFileBuffer_ReturnsInvalidParameter) {
  DIGEST_CACHE  Cache;
  CONST UINT8   *Digest    = NULL;
  UINTN         DigestSize = 0;

  ZeroMem (&Cache, sizeof (Cache));

  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest, &DigestSize), EFI_INVALID_PARAMETER);
}

TEST (GetHashTest, UnsupportedHashGuid_ReturnsUnsupported) {
  EFI_GUID      UnknownGuid = {
    0xA1B2C3D4,
    0x9999,
    0x8888,
    { 0x10,    0x20,0x30, 0x40, 0x50, 0x60, 0x70, 0x80 }
  };
  DIGEST_CACHE  Cache;
  CONST UINT8   *Digest    = NULL;
  UINTN         DigestSize = 0;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = mCacheBuffer;
  Cache.BufferSize = sizeof (mCacheBuffer);

  EXPECT_EQ (GetHash (&UnknownGuid, &Cache, &Digest, &DigestSize), EFI_UNSUPPORTED);
  EXPECT_EQ (Cache.Entries, nullptr);
}

TEST (GetHashTest, Sha256Miss_HashesBufferAndMemoizes) {
  MockBaseCryptLib  BaseCryptLibMock;
  DIGEST_CACHE      Cache;
  CONST UINT8       *Digest    = NULL;
  UINTN             DigestSize = 0;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = mCacheBuffer;
  Cache.BufferSize = sizeof (mCacheBuffer);

  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .WillOnce (Invoke (FillDigest (SHA256_DIGEST_SIZE, 0x5A)));

  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest, &DigestSize), EFI_SUCCESS);
  ASSERT_NE (Digest, (CONST UINT8 *)NULL);
  EXPECT_EQ (DigestSize, (UINTN)SHA256_DIGEST_SIZE);
  EXPECT_EQ (Digest[0], (UINT8)0x5A);
  EXPECT_EQ (Digest[SHA256_DIGEST_SIZE - 1], (UINT8)0x5A);
  EXPECT_NE (Cache.Entries, nullptr);

  FreeDigestCache (&Cache);
  EXPECT_EQ (Cache.Entries, nullptr);
}

TEST (GetHashTest, Sha256Hit_ReturnsMemoizedDigestWithoutRehashing) {
  MockBaseCryptLib  BaseCryptLibMock;
  DIGEST_CACHE      Cache;
  CONST UINT8       *Digest1    = NULL;
  CONST UINT8       *Digest2    = NULL;
  UINTN             DigestSize1 = 0;
  UINTN             DigestSize2 = 0;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = mCacheBuffer;
  Cache.BufferSize = sizeof (mCacheBuffer);

  //
  // WillOnce means a second Sha256HashAll () call would fail the test, proving the second GetHash ()
  // is served from the memoized entry rather than re-hashing the buffer.
  //
  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .WillOnce (Invoke (FillDigest (SHA256_DIGEST_SIZE, 0xC3)));

  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest1, &DigestSize1), EFI_SUCCESS);
  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest2, &DigestSize2), EFI_SUCCESS);
  EXPECT_EQ (Digest1, Digest2);
  EXPECT_EQ (DigestSize1, DigestSize2);

  FreeDigestCache (&Cache);
}

TEST (GetHashTest, Sha256HashFailure_ReturnsSecurityViolationAndLeavesCacheEmpty) {
  MockBaseCryptLib  BaseCryptLibMock;
  DIGEST_CACHE      Cache;
  CONST UINT8       *Digest    = NULL;
  UINTN             DigestSize = 0;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = mCacheBuffer;
  Cache.BufferSize = sizeof (mCacheBuffer);

  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .WillOnce (Return (FALSE));

  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest, &DigestSize), EFI_SECURITY_VIOLATION);
  EXPECT_EQ (Cache.Entries, nullptr);
}

TEST (GetHashTest, DistinctAlgorithms_MemoizedSeparately) {
  MockBaseCryptLib  BaseCryptLibMock;
  DIGEST_CACHE      Cache;
  CONST UINT8       *Digest256    = NULL;
  CONST UINT8       *Digest384    = NULL;
  CONST UINT8       *Digest512    = NULL;
  UINTN             DigestSize256 = 0;
  UINTN             DigestSize384 = 0;
  UINTN             DigestSize512 = 0;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = mCacheBuffer;
  Cache.BufferSize = sizeof (mCacheBuffer);

  //
  // Each Sha*HashAll () is expected exactly once: the second round of GetHash () calls below must be
  // served from the three separate memoized entries.
  //
  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .WillOnce (Invoke (FillDigest (SHA256_DIGEST_SIZE, 0x11)));
  EXPECT_CALL (BaseCryptLibMock, Sha384HashAll (_, _, _))
    .WillOnce (Invoke (FillDigest (SHA384_DIGEST_SIZE, 0x22)));
  EXPECT_CALL (BaseCryptLibMock, Sha512HashAll (_, _, _))
    .WillOnce (Invoke (FillDigest (SHA512_DIGEST_SIZE, 0x33)));

  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest256, &DigestSize256), EFI_SUCCESS);
  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha384Guid, &Cache, &Digest384, &DigestSize384), EFI_SUCCESS);
  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha512Guid, &Cache, &Digest512, &DigestSize512), EFI_SUCCESS);

  EXPECT_EQ (DigestSize256, (UINTN)SHA256_DIGEST_SIZE);
  EXPECT_EQ (DigestSize384, (UINTN)SHA384_DIGEST_SIZE);
  EXPECT_EQ (DigestSize512, (UINTN)SHA512_DIGEST_SIZE);
  EXPECT_EQ (Digest256[0], (UINT8)0x11);
  EXPECT_EQ (Digest384[0], (UINT8)0x22);
  EXPECT_EQ (Digest512[0], (UINT8)0x33);

  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest256, &DigestSize256), EFI_SUCCESS);
  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha384Guid, &Cache, &Digest384, &DigestSize384), EFI_SUCCESS);
  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha512Guid, &Cache, &Digest512, &DigestSize512), EFI_SUCCESS);

  FreeDigestCache (&Cache);
  EXPECT_EQ (Cache.Entries, nullptr);
}

TEST (GetHashTest, FreeDigestCache_ReleasesEntriesAndAllowsRecompute) {
  MockBaseCryptLib  BaseCryptLibMock;
  DIGEST_CACHE      Cache;
  CONST UINT8       *Digest    = NULL;
  UINTN             DigestSize = 0;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer     = mCacheBuffer;
  Cache.BufferSize = sizeof (mCacheBuffer);

  //
  // After FreeDigestCache () drops the memoized entry, a second GetHash () for the same algorithm is
  // a fresh miss and hashes the buffer again, so Sha256HashAll () is expected twice.
  //
  EXPECT_CALL (BaseCryptLibMock, Sha256HashAll (_, _, _))
    .Times (2)
    .WillRepeatedly (Invoke (FillDigest (SHA256_DIGEST_SIZE, 0x77)));

  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest, &DigestSize), EFI_SUCCESS);
  EXPECT_NE (Cache.Entries, nullptr);

  FreeDigestCache (&Cache);
  EXPECT_EQ (Cache.Entries, nullptr);

  EXPECT_EQ (GetHash (&gEfiHashAlgorithmSha256Guid, &Cache, &Digest, &DigestSize), EFI_SUCCESS);
  EXPECT_EQ (DigestSize, (UINTN)SHA256_DIGEST_SIZE);

  FreeDigestCache (&Cache);
}

TEST (GetHashTest, FreeDigestCache_NullAndEmpty_NoOp) {
  DIGEST_CACHE  Cache;

  ZeroMem (&Cache, sizeof (Cache));

  FreeDigestCache (NULL);
  FreeDigestCache (&Cache);
  EXPECT_EQ (Cache.Entries, nullptr);
}

// ---------------------------------------------------------------------------
// BuildImageAuthority / FreeImageAuthority
// ---------------------------------------------------------------------------

TEST (BuildImageAuthorityTest, NullPayload_InvalidParameter) {
  IMAGE_AUTHORITY  Authority = { NULL, 0 };

  EXPECT_EQ (BuildImageAuthority (NULL, NULL, 4, &Authority), EFI_INVALID_PARAMETER);
  EXPECT_EQ (Authority.Data, nullptr);
}

TEST (BuildImageAuthorityTest, ZeroPayloadSize_InvalidParameter) {
  UINT8            Payload[4] = { 0 };
  IMAGE_AUTHORITY  Authority  = { NULL, 0 };

  EXPECT_EQ (BuildImageAuthority (NULL, Payload, 0, &Authority), EFI_INVALID_PARAMETER);
  EXPECT_EQ (Authority.Data, nullptr);
}

TEST (BuildImageAuthorityTest, NullAuthority_InvalidParameter) {
  UINT8  Payload[4] = { 0 };

  EXPECT_EQ (BuildImageAuthority (NULL, Payload, sizeof (Payload), NULL), EFI_INVALID_PARAMETER);
}

//
// A payload large enough to overflow the EFI_SIGNATURE_DATA header addition is rejected before any
// allocation or read of the payload.
//
TEST (BuildImageAuthorityTest, OverflowingPayloadSize_InvalidParameter) {
  UINT8            Sentinel  = 0;
  IMAGE_AUTHORITY  Authority = { NULL, 0 };

  EXPECT_EQ (BuildImageAuthority (NULL, &Sentinel, MAX_UINTN, &Authority), EFI_INVALID_PARAMETER);
  EXPECT_EQ (Authority.Data, nullptr);
}

//
// With no owner, the SignatureOwner is zeroed and the payload follows it. Size is the payload plus
// a SignatureOwner GUID.
//
TEST (BuildImageAuthorityTest, NoOwner_ZeroesOwnerAndCopiesPayload) {
  UINT8            Payload[5] = { 0x11, 0x22, 0x33, 0x44, 0x55 };
  EFI_GUID         ZeroGuid   = { 0 };
  IMAGE_AUTHORITY  Authority  = { NULL, 0 };

  EXPECT_EQ (BuildImageAuthority (NULL, Payload, sizeof (Payload), &Authority), EFI_SUCCESS);
  ASSERT_NE (Authority.Data, nullptr);
  EXPECT_EQ (Authority.Size, (UINTN)(sizeof (EFI_GUID) + sizeof (Payload)));
  EXPECT_TRUE (CompareGuid (&Authority.Data->SignatureOwner, &ZeroGuid));
  EXPECT_EQ (CompareMem (Authority.Data->SignatureData, Payload, sizeof (Payload)), 0);

  FreeImageAuthority (&Authority);
  EXPECT_EQ (Authority.Data, nullptr);
  EXPECT_EQ (Authority.Size, (UINTN)0);
}

//
// A supplied owner GUID is stored verbatim ahead of the payload.
//
TEST (BuildImageAuthorityTest, WithOwner_StoresOwnerAndPayload) {
  EFI_GUID         Owner = { 0x11223344, 0x5566, 0x7788, { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 }
  };
  UINT8            Payload[3] = { 0xDE, 0xAD, 0xBE };
  IMAGE_AUTHORITY  Authority  = { NULL, 0 };

  EXPECT_EQ (BuildImageAuthority (&Owner, Payload, sizeof (Payload), &Authority), EFI_SUCCESS);
  ASSERT_NE (Authority.Data, nullptr);
  EXPECT_TRUE (CompareGuid (&Authority.Data->SignatureOwner, &Owner));
  EXPECT_EQ (CompareMem (Authority.Data->SignatureData, Payload, sizeof (Payload)), 0);

  FreeImageAuthority (&Authority);
}

//
// FreeImageAuthority tolerates a NULL pointer and an already-empty authority.
//
TEST (FreeImageAuthorityTest, NullAndEmpty_NoOp) {
  IMAGE_AUTHORITY  Empty = { NULL, 0 };

  FreeImageAuthority (NULL);
  FreeImageAuthority (&Empty);
  EXPECT_EQ (Empty.Data, nullptr);
  EXPECT_EQ (Empty.Size, (UINTN)0);
}

//
// FreeImageAuthority clears the record it frees, so a second call is a safe no-op (no double free).
//
TEST (FreeImageAuthorityTest, DoubleFree_Safe) {
  UINT8            Payload[4] = { 1, 2, 3, 4 };
  IMAGE_AUTHORITY  Authority  = { NULL, 0 };

  ASSERT_EQ (BuildImageAuthority (NULL, Payload, sizeof (Payload), &Authority), EFI_SUCCESS);
  FreeImageAuthority (&Authority);
  FreeImageAuthority (&Authority);
  EXPECT_EQ (Authority.Data, nullptr);
}
