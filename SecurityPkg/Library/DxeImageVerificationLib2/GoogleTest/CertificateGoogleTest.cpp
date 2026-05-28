/** @file
  Unit tests for the signed-image validation stubs in
  DxeImageVerificationLib (Certificate.c): IsSignedImageAuthorized and
  IsSignedImageRevoked.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockBaseCryptLib.h>

#include <vector>
#include <cstring>

extern "C" {
  #include <Uefi.h>
  #include <Guid/ImageAuthentication.h>
  #include <Guid/WinCertificate.h>
  #include <Library/BaseMemoryLib.h>
  #include "../Certificate.h"
  #include "../Support.h"

  //
  // Forward declarations of internal helpers exercised directly by
  // unit tests but not published in Certificate.h.
  //
  EFI_STATUS
  GetWinCertificatePkcs7AuthData (
    IN  CONST WIN_CERTIFICATE  *Cert,
    OUT CONST UINT8            **AuthData,
    OUT UINTN                  *AuthDataSize
    );
}

// SHA-256 digest payload size (no owner GUID).
static constexpr UINTN   kSha256DigestSize = 32;
static constexpr UINT32  kSha256EntrySize  = sizeof (EFI_GUID) + 32;

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
// Write Bytes into the entry payload (the part after the owner GUID) of
// the signature entry at index EntryIndex inside the EFI_SIGNATURE_LIST
// that begins at ListOffset within Buffer.
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

  std::memcpy (Buffer.data () + PayloadOff, Bytes.data (), Bytes.size ());
}

//
// Construct an DIGEST_CACHE bound to a non-NULL FileBuffer and
// non-zero FileSize, suitable for the stubs' parameter validation.
//
static DIGEST_CACHE
MakeBoundCache (
  void
  )
{
  DIGEST_CACHE  Cache;

  ZeroMem (&Cache, sizeof (Cache));
  Cache.Buffer = (const VOID *)(UINTN)1;
  Cache.BufferSize   = 1;
  return Cache;
}

//
// Construct an DIGEST_CACHE pre-populated with a digest for
// HashType. IsImageDigestInDatabase will use the stored digest
// instead of asking BaseCryptLib to compute one.
//
static DIGEST_CACHE
MakeCacheWithDigest (
  const EFI_GUID            *HashType,
  const std::vector<UINT8>  &Digest
  )
{
  DIGEST_CACHE  Cache = MakeBoundCache ();
  UINTN         Index;

  EXPECT_TRUE (GetImageHashIndexForTest (HashType, &Index));
  EXPECT_LE (Digest.size (), (size_t)MAX_DIGEST_SIZE);

  std::memcpy (Cache.Entries[Index].Bytes, Digest.data (), Digest.size ());
  Cache.Entries[Index].BufferSize = Digest.size ();
  return Cache;
}

// ---------------------------------------------------------------------------
// IsSignedImageAuthorized
// ---------------------------------------------------------------------------

TEST (IsSignedImageAuthorizedTest, NullSecDataDir_ReturnsFalse) {
  DIGEST_CACHE                Cache  = MakeBoundCache ();
  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (NULL, NULL, 0, NULL, 0, &Cache, &Action)
    );
}

TEST (IsSignedImageAuthorizedTest, NullCache_ReturnsFalse) {
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir = { 0, 0 };
  EFI_IMAGE_EXECUTION_ACTION  Action     = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (&SecDataDir, NULL, 0, NULL, 0, NULL, &Action)
    );
}

TEST (IsSignedImageAuthorizedTest, CacheWithoutImageBinding_ReturnsFalse) {
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir = { 0, 0 };
  DIGEST_CACHE                Cache;
  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  ZeroMem (&Cache, sizeof (Cache));

  EXPECT_FALSE (
    IsSignedImageAuthorized (&SecDataDir, NULL, 0, NULL, 0, &Cache, &Action)
    );
}

TEST (IsSignedImageAuthorizedTest, NullAction_ReturnsFalse) {
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, 0 };
  DIGEST_CACHE              Cache      = MakeBoundCache ();

  EXPECT_FALSE (
    IsSignedImageAuthorized (&SecDataDir, NULL, 0, NULL, 0, &Cache, NULL)
    );
}

TEST (IsSignedImageAuthorizedTest, EmptyDb_ReturnsFalseAndSetsSigNotFound) {
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir = { 0, 0 };
  DIGEST_CACHE                Cache      = MakeBoundCache ();
  EFI_IMAGE_EXECUTION_ACTION  Action     = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (&SecDataDir, NULL, 0, NULL, 0, &Cache, &Action)
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

TEST (IsSignedImageAuthorizedTest, ImageDigestInDb_ReturnsTrueAndSetsSigPassed) {
  // Pre-populate cache with a digest, and build a db that contains it.
  std::vector<UINT8>          Target (kSha256DigestSize, 0x42);
  std::vector<UINT8>          Db;
  size_t                      Off        = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir = { 0, 0 };
  DIGEST_CACHE                Cache      = MakeCacheWithDigest (&gEfiCertSha256Guid, Target);
  EFI_IMAGE_EXECUTION_ACTION  Action     = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  SetEntryPayload (Db, Off, 0, Target);

  EXPECT_TRUE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  // Action is updated to SIG_PASSED on the digest-in-db fast path.
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_PASSED);
}

TEST (IsSignedImageAuthorizedTest, ImageDigestNotInDb_ReturnsFalseAndSetsSigNotFound) {
  // Db contains a different digest from what the cache holds.
  std::vector<UINT8>          Stored (kSha256DigestSize, 0xAA);
  std::vector<UINT8>          Other (kSha256DigestSize, 0xBB);
  std::vector<UINT8>          Db;
  size_t                      Off        = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir = { 0, 0 };
  DIGEST_CACHE                Cache      = MakeCacheWithDigest (&gEfiCertSha256Guid, Other);
  EFI_IMAGE_EXECUTION_ACTION  Action     = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  SetEntryPayload (Db, Off, 0, Stored);

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

// ---------------------------------------------------------------------------
// IsSignedImageRevoked
// ---------------------------------------------------------------------------

TEST (IsSignedImageRevokedTest, NullSecDataDir_ReturnsFalse) {
  DIGEST_CACHE                Cache  = MakeBoundCache ();
  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageRevoked (NULL, NULL, 0, &Cache, &Action)
    );
}

TEST (IsSignedImageRevokedTest, NullCache_ReturnsFalse) {
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir = { 0, 0 };
  EFI_IMAGE_EXECUTION_ACTION  Action     = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageRevoked (&SecDataDir, NULL, 0, NULL, &Action)
    );
}

TEST (IsSignedImageRevokedTest, CacheWithoutImageBinding_ReturnsFalse) {
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir = { 0, 0 };
  DIGEST_CACHE                Cache;
  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  ZeroMem (&Cache, sizeof (Cache));

  EXPECT_FALSE (
    IsSignedImageRevoked (&SecDataDir, NULL, 0, &Cache, &Action)
    );
}

TEST (IsSignedImageRevokedTest, NullAction_ReturnsFalse) {
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, 0 };
  DIGEST_CACHE              Cache      = MakeBoundCache ();

  EXPECT_FALSE (
    IsSignedImageRevoked (&SecDataDir, NULL, 0, &Cache, NULL)
    );
}

TEST (IsSignedImageRevokedTest, Stub_ReturnsFalse) {
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir = { 0, 0 };
  DIGEST_CACHE                Cache      = MakeBoundCache ();
  EFI_IMAGE_EXECUTION_ACTION  Action     = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageRevoked (&SecDataDir, NULL, 0, &Cache, &Action)
    );
}

// ---------------------------------------------------------------------------
// Helpers for building synthetic certificate tables.
// ---------------------------------------------------------------------------

//
// Append a single WIN_CERTIFICATE entry of total size dwLength (which
// must be at least sizeof (WIN_CERTIFICATE)) to Buffer, padding the
// entry up to the next 8-byte boundary as the PE/COFF spec requires.
// Returns the offset of the entry within Buffer.
//
static size_t
AppendWinCert (
  std::vector<UINT8>  &Buffer,
  UINT32              dwLength,
  UINT16              wRevision,
  UINT16              wCertificateType
  )
{
  const size_t  Padded = (dwLength + 7u) & ~(size_t)7u;
  const size_t  Offset = Buffer.size ();

  Buffer.resize (Offset + Padded, 0);

  WIN_CERTIFICATE  *Cert = (WIN_CERTIFICATE *)(Buffer.data () + Offset);

  Cert->dwLength         = dwLength;
  Cert->wRevision        = wRevision;
  Cert->wCertificateType = wCertificateType;
  return Offset;
}

//
// Append a PKCS_SIGNED_DATA WIN_CERTIFICATE whose payload is filled
// with Fill repeated PayloadSize times. Returns the offset of the
// entry within Buffer.
//
static size_t
AppendPkcs7Cert (
  std::vector<UINT8>  &Buffer,
  UINT32              PayloadSize,
  UINT8               Fill
  )
{
  const UINT32  dwLength = (UINT32)(sizeof (WIN_CERTIFICATE) + PayloadSize);
  const size_t  Offset   = AppendWinCert (Buffer, dwLength, 0x0200, WIN_CERT_TYPE_PKCS_SIGNED_DATA);

  std::memset (Buffer.data () + Offset + sizeof (WIN_CERTIFICATE), Fill, PayloadSize);
  return Offset;
}

// ---------------------------------------------------------------------------
// GetWinCertificatePkcs7AuthData
// ---------------------------------------------------------------------------

TEST (GetWinCertificatePkcs7AuthDataTest, NullCert_ReturnsInvalidParameter) {
  const UINT8  *AuthData    = NULL;
  UINTN        AuthDataSize = 0;

  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (NULL, &AuthData, &AuthDataSize),
    EFI_INVALID_PARAMETER
    );
}

TEST (GetWinCertificatePkcs7AuthDataTest, NullOutputs_ReturnsInvalidParameter) {
  WIN_CERTIFICATE  Cert         = { sizeof (WIN_CERTIFICATE) + 1, 0x0200, WIN_CERT_TYPE_PKCS_SIGNED_DATA };
  const UINT8      *AuthData    = NULL;
  UINTN            AuthDataSize = 0;

  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (&Cert, NULL, &AuthDataSize),
    EFI_INVALID_PARAMETER
    );
  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (&Cert, &AuthData, NULL),
    EFI_INVALID_PARAMETER
    );
}

TEST (GetWinCertificatePkcs7AuthDataTest, PkcsSignedData_ExtractsPayload) {
  // Build a WIN_CERTIFICATE followed by 4 bytes of payload.
  const UINT8         Payload[] = { 0xAA, 0xBB, 0xCC, 0xDD };
  std::vector<UINT8>  Buffer (sizeof (WIN_CERTIFICATE) + sizeof (Payload), 0);
  WIN_CERTIFICATE     *Cert = (WIN_CERTIFICATE *)Buffer.data ();

  Cert->dwLength         = (UINT32)Buffer.size ();
  Cert->wRevision        = 0x0200;
  Cert->wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
  std::memcpy (Buffer.data () + sizeof (WIN_CERTIFICATE), Payload, sizeof (Payload));

  const UINT8  *AuthData    = NULL;
  UINTN        AuthDataSize = 0;

  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (Cert, &AuthData, &AuthDataSize),
    EFI_SUCCESS
    );
  ASSERT_EQ (AuthDataSize, sizeof (Payload));
  EXPECT_EQ (0, std::memcmp (AuthData, Payload, sizeof (Payload)));
}

TEST (GetWinCertificatePkcs7AuthDataTest, PkcsSignedData_HeaderOnly_ReturnsCorrupted) {
  WIN_CERTIFICATE  Cert         = { sizeof (WIN_CERTIFICATE), 0x0200, WIN_CERT_TYPE_PKCS_SIGNED_DATA };
  const UINT8      *AuthData    = NULL;
  UINTN            AuthDataSize = 0;

  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (&Cert, &AuthData, &AuthDataSize),
    EFI_VOLUME_CORRUPTED
    );
}

TEST (GetWinCertificatePkcs7AuthDataTest, EfiGuidPkcs7_ExtractsPayload) {
  const UINT8                Payload[]  = { 0x11, 0x22, 0x33 };
  const size_t               HeaderSize = OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  std::vector<UINT8>         Buffer (HeaderSize + sizeof (Payload), 0);
  WIN_CERTIFICATE_UEFI_GUID  *UefiCert = (WIN_CERTIFICATE_UEFI_GUID *)Buffer.data ();

  UefiCert->Hdr.dwLength         = (UINT32)Buffer.size ();
  UefiCert->Hdr.wRevision        = 0x0200;
  UefiCert->Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
  CopyMem (&UefiCert->CertType, &gEfiCertPkcs7Guid, sizeof (EFI_GUID));
  std::memcpy (Buffer.data () + HeaderSize, Payload, sizeof (Payload));

  const UINT8  *AuthData    = NULL;
  UINTN        AuthDataSize = 0;

  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (&UefiCert->Hdr, &AuthData, &AuthDataSize),
    EFI_SUCCESS
    );
  ASSERT_EQ (AuthDataSize, sizeof (Payload));
  EXPECT_EQ (0, std::memcmp (AuthData, Payload, sizeof (Payload)));
}

TEST (GetWinCertificatePkcs7AuthDataTest, EfiGuidNonPkcs7_ReturnsUnsupported) {
  const size_t               HeaderSize = OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  std::vector<UINT8>         Buffer (HeaderSize + 4, 0);
  WIN_CERTIFICATE_UEFI_GUID  *UefiCert = (WIN_CERTIFICATE_UEFI_GUID *)Buffer.data ();
  const EFI_GUID             OtherGuid = { 0x12345678, 0x1234, 0x1234, { 1, 2, 3, 4, 5, 6, 7, 8 }
  };

  UefiCert->Hdr.dwLength         = (UINT32)Buffer.size ();
  UefiCert->Hdr.wRevision        = 0x0200;
  UefiCert->Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
  CopyMem (&UefiCert->CertType, &OtherGuid, sizeof (EFI_GUID));

  const UINT8  *AuthData    = NULL;
  UINTN        AuthDataSize = 0;

  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (&UefiCert->Hdr, &AuthData, &AuthDataSize),
    EFI_UNSUPPORTED
    );
}

TEST (GetWinCertificatePkcs7AuthDataTest, EfiGuid_HeaderOnly_ReturnsCorrupted) {
  WIN_CERTIFICATE_UEFI_GUID  UefiCert;

  ZeroMem (&UefiCert, sizeof (UefiCert));
  UefiCert.Hdr.dwLength         = (UINT32)OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  UefiCert.Hdr.wRevision        = 0x0200;
  UefiCert.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;

  const UINT8  *AuthData    = NULL;
  UINTN        AuthDataSize = 0;

  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (&UefiCert.Hdr, &AuthData, &AuthDataSize),
    EFI_VOLUME_CORRUPTED
    );
}

TEST (GetWinCertificatePkcs7AuthDataTest, UnknownCertType_ReturnsUnsupported) {
  WIN_CERTIFICATE  Cert         = { sizeof (WIN_CERTIFICATE) + 8, 0x0200, WIN_CERT_TYPE_EFI_PKCS115 };
  const UINT8      *AuthData    = NULL;
  UINTN            AuthDataSize = 0;

  EXPECT_EQ (
    GetWinCertificatePkcs7AuthData (&Cert, &AuthData, &AuthDataSize),
    EFI_UNSUPPORTED
    );
}

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

// ---------------------------------------------------------------------------
// IsSignedImageAuthorized -- end-to-end PKCS#7 + dbx scenarios
// ---------------------------------------------------------------------------

//
// One PKCS#7 signature whose only valid trust anchor in db has its
// hash listed in dbx. The signature must be rejected and the function
// must return FALSE with Action == AUTH_SIG_NOT_FOUND.
//
TEST (IsSignedImageAuthorizedTest, SignatureCertInDbAndDbx_ReturnsFalse) {
  MockBaseCryptLib  BaseCryptLibMock;

  // FileBuffer = a single PKCS#7 entry; the security data directory
  // spans the entire file.
  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, /*PayloadSize=*/ 16, /*Fill=*/ 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // db: one X509 list with one cert (payload byte == 0x11).
  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (
                                Db,
                                gEfiCertX509Guid,
                                0,
                                sizeof (EFI_GUID) + 16,
                                1
                                );

  SetEntryPayload (Db, DbOff, 0, std::vector<UINT8>(16, 0x11));

  // dbx: one X509-SHA256 list with the digest the mocked GetX509Hash
  // will produce for the cert's TBS bytes (0xE1 * 32).
  std::vector<UINT8>  Dbx;
  size_t              DbxOff = AppendSignatureList (
                                 Dbx,
                                 gEfiCertX509Sha256Guid,
                                 0,
                                 kSha256EntrySize,
                                 1
                                 );

  SetEntryPayload (Dbx, DbxOff, 0, std::vector<UINT8>(kSha256DigestSize, 0xE1));

  // Cache: bind to FileBuf and pre-populate the sha256 slot so that
  // GetHash never needs to call BaseCryptLib.
  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _))
    .WillOnce (Return (TRUE));
  EXPECT_CALL (BaseCryptLibMock, X509GetTBSCert (_, _, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, UINT8 **OutTbs, UINTN *OutTbsSize) -> BOOLEAN {
    static UINT8  TbsBytes[] = { 0x11 };
    *OutTbs                  = TbsBytes;
    *OutTbsSize              = sizeof (TbsBytes);
    return TRUE;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, GetX509Hash (_, _, _, _, _))
    .WillOnce (
       Invoke (
         [] (VOID *, UINTN, CONST EFI_GUID *, UINT8 *Digest, UINTN *DigestSize) -> EFI_STATUS {
    std::memset (Digest, 0xE1, SHA256_DIGEST_SIZE);
    *DigestSize = SHA256_DIGEST_SIZE;
    return EFI_SUCCESS;
  }
         )
       );

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      Dbx.data (),
      Dbx.size (),
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// Two PKCS#7 signatures. The first signature's only trust anchor (E1)
// has its cert hash in dbx and is therefore rejected. The second
// signature verifies against a different trust anchor (E2) whose hash
// is not in dbx. The image must be authorized (returns TRUE) and
// Action must remain unchanged.
//
TEST (IsSignedImageAuthorizedTest, TwoSignatures_FirstRevoked_SecondAuthorized_ReturnsTrue) {
  MockBaseCryptLib  BaseCryptLibMock;

  // FileBuffer: two PKCS#7 entries with distinguishable payloads.
  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);
  AppendPkcs7Cert (FileBuf, 16, 0xA2);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // db: one X509 list with two distinct certs (E1=0x11, E2=0x22).
  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (
                                Db,
                                gEfiCertX509Guid,
                                0,
                                sizeof (EFI_GUID) + 16,
                                2
                                );

  SetEntryPayload (Db, DbOff, 0, std::vector<UINT8>(16, 0x11));
  SetEntryPayload (Db, DbOff, 1, std::vector<UINT8>(16, 0x22));

  // dbx: holds only E1's hash (0xE1 * 32). E2's hash (0xE2 * 32) is
  // not present.
  std::vector<UINT8>  Dbx;
  size_t              DbxOff = AppendSignatureList (
                                 Dbx,
                                 gEfiCertX509Sha256Guid,
                                 0,
                                 kSha256EntrySize,
                                 1
                                 );

  SetEntryPayload (Dbx, DbxOff, 0, std::vector<UINT8>(kSha256DigestSize, 0xE1));

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillRepeatedly (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  // Sig1 verifies only against E1; Sig2 verifies only against E2.
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _))
    .WillRepeatedly (
       Invoke (
         [] (CONST UINT8 *AuthData, UINTN, CONST UINT8 *Cert, UINTN, CONST UINT8 *, UINTN) -> BOOLEAN {
    if ((AuthData[0] == 0xA1) && (Cert[0] == 0x11)) {
      return TRUE;
    }

    if ((AuthData[0] == 0xA2) && (Cert[0] == 0x22)) {
      return TRUE;
    }

    return FALSE;
  }
         )
       );
  // TBS bytes mirror the first byte of the cert so GetX509Hash can
  // route on them.
  EXPECT_CALL (BaseCryptLibMock, X509GetTBSCert (_, _, _, _))
    .WillRepeatedly (
       Invoke (
         [] (CONST UINT8 *Cert, UINTN, UINT8 **OutTbs, UINTN *OutTbsSize) -> BOOLEAN {
    static UINT8  Tbs1[] = { 0x11 };
    static UINT8  Tbs2[] = { 0x22 };

    if (Cert[0] == 0x11) {
      *OutTbs     = Tbs1;
      *OutTbsSize = sizeof (Tbs1);
    } else {
      *OutTbs     = Tbs2;
      *OutTbsSize = sizeof (Tbs2);
    }

    return TRUE;
  }
         )
       );
  // Hash(0x11) -> 0xE1*32 (matches dbx); Hash(0x22) -> 0xE2*32 (does
  // not match dbx).
  EXPECT_CALL (BaseCryptLibMock, GetX509Hash (_, _, _, _, _))
    .WillRepeatedly (
       Invoke (
         [] (VOID *Data, UINTN, CONST EFI_GUID *, UINT8 *Digest, UINTN *DigestSize) -> EFI_STATUS {
    UINT8  Marker = ((CONST UINT8 *)Data)[0];
    std::memset (Digest, (Marker == 0x11) ? 0xE1 : 0xE2, SHA256_DIGEST_SIZE);
    *DigestSize = SHA256_DIGEST_SIZE;
    return EFI_SUCCESS;
  }
         )
       );

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_TRUE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      Dbx.data (),
      Dbx.size (),
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_PASSED);
}

//
// Happy path: a single PKCS#7 signature, db contains an X509 trust
// anchor that AuthenticodeVerify accepts, and no dbx. The image must
// be authorized and Action must be set to SIG_PASSED. X509GetTBSCert is
// still called for the verifying trust anchor, but dbx hashing is skipped
// because dbx is empty.
//
TEST (IsSignedImageAuthorizedTest, SingleSignatureVerifies_NoDbx_ReturnsTrue) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (
                                Db,
                                gEfiCertX509Guid,
                                0,
                                sizeof (EFI_GUID) + 16,
                                1
                                );

  SetEntryPayload (Db, DbOff, 0, std::vector<UINT8>(16, 0x11));

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _))
    .WillOnce (Return (TRUE));
  EXPECT_CALL (BaseCryptLibMock, X509GetTBSCert (_, _, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, UINT8 **OutTbs, UINTN *OutTbsSize) -> BOOLEAN {
    static UINT8  TbsBytes[] = { 0x11 };
    *OutTbs                  = TbsBytes;
    *OutTbsSize              = sizeof (TbsBytes);
    return TRUE;
  }
         )
       );

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_TRUE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_PASSED);
}

//
// Image digest is present in db (image-hash list) AND a PKCS#7
// signature is present alongside an X509 list. The digest fast path
// must short-circuit before any signature/crypto work runs.
//
TEST (IsSignedImageAuthorizedTest, ImageDigestInDb_BeatsSignatureWalk) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // db: image-hash list (matches cached digest) followed by an X509
  // list (which would otherwise be walked).
  std::vector<UINT8>  CachedDigest (SHA256_DIGEST_SIZE, 0x42);
  std::vector<UINT8>  Db;
  size_t              HashOff = AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  SetEntryPayload (Db, HashOff, 0, CachedDigest);
  size_t  X509Off = AppendSignatureList (Db, gEfiCertX509Guid, 0, sizeof (EFI_GUID) + 16, 1);

  SetEntryPayload (Db, X509Off, 0, std::vector<UINT8>(16, 0x11));

  DIGEST_CACHE  Cache = MakeCacheWithDigest (&gEfiCertSha256Guid, CachedDigest);

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  // No crypto / signature mocks expected. If the fast path regresses
  // and the signature walk runs, gmock will flag unexpected calls.
  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _)).Times (0);
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);
  EXPECT_CALL (BaseCryptLibMock, X509GetTBSCert (_, _, _, _)).Times (0);
  EXPECT_CALL (BaseCryptLibMock, GetX509Hash (_, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_TRUE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_PASSED);
}

//
// A PKCS#7 signature exists but no db cert verifies it. The image
// must not be authorized and Action must be set to SIG_NOT_FOUND.
//
TEST (IsSignedImageAuthorizedTest, SignatureDoesNotVerifyAnyDbCert_ReturnsFalse) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (
                                Db,
                                gEfiCertX509Guid,
                                0,
                                sizeof (EFI_GUID) + 16,
                                2
                                );

  SetEntryPayload (Db, DbOff, 0, std::vector<UINT8>(16, 0x11));
  SetEntryPayload (Db, DbOff, 1, std::vector<UINT8>(16, 0x22));

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _))
    .Times (2)
    .WillRepeatedly (Return (FALSE));

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// SecDataDir extends past the end of the cached file buffer. The
// signature walk must fail closed (no authorization, SIG_NOT_FOUND).
//
TEST (IsSignedImageAuthorizedTest, CorruptedSecDataDir_ReturnsFalse) {
  MockBaseCryptLib  BaseCryptLibMock;

  // Small file but SecDataDir claims a much larger BufferSize.
  std::vector<UINT8>        FileBuf (32, 0);
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, 1024 };

  DIGEST_CACHE  Cache = MakeBoundCache ();

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  // No crypto should be invoked.
  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _)).Times (0);
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      NULL,
      0,
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// db is absent (NULL/0) but the image carries a valid-looking PKCS#7
// signature. With no trust anchors at all the function must return
// FALSE with SIG_NOT_FOUND, and no crypto must be invoked beyond
// classifying the auth data.
//
TEST (IsSignedImageAuthorizedTest, NoDbButValidSignature_ReturnsFalse) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  // No db => WalkSignatureDatabase visits nothing => AuthenticodeVerify
  // is never called.
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      NULL,
      0,
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

// ---------------------------------------------------------------------------
// IsSignedImageAuthorized -- additional signature-list handling coverage
// ---------------------------------------------------------------------------

//
// db contains only a non-X.509 list (image-hash list). The signature
// walk inspects it but skips it; with no trust anchors available the
// image must be rejected with AUTH_SIG_NOT_FOUND.
//
TEST (IsSignedImageAuthorizedTest, DbHasOnlyNonX509List_ReturnsFalse) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // db: one image-hash list (gEfiCertSha256Guid) with a non-matching digest.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertSha256Guid, 0, kSha256EntrySize, 1);

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  // No X.509 list => AuthenticodeVerify is never called.
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// db contains an X.509 list whose SignatureSize equals sizeof(EFI_GUID),
// i.e. no cert payload at all. The list must be skipped and the image
// rejected.
//
TEST (IsSignedImageAuthorizedTest, DbX509ListNoCertPayload_ReturnsFalse) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // X.509 list with SignatureSize = sizeof(EFI_GUID) (no cert payload).
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertX509Guid, 0, (UINT32)sizeof (EFI_GUID), 1);

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// db contains an X.509 list whose SignatureHeaderSize is inflated past
// SignatureListSize - sizeof(EFI_SIGNATURE_LIST). DatabaseIterInit
// accepts the list (it only validates SignatureListSize), but
// SigListIterInit inside IsPkcs7AuthDataVerifiedByX509 rejects it.
// The list must be skipped and the image rejected.
//
TEST (IsSignedImageAuthorizedTest, DbX509ListMalformedHeader_ReturnsFalse) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // Build a single X.509 list with SignatureSize > sizeof(EFI_GUID) (so
  // the early-return check in IsPkcs7AuthDataVerifiedByX509 is passed)
  // but a SignatureHeaderSize that overflows the list payload area.
  const UINT32        EntrySize = (UINT32)(sizeof (EFI_GUID) + 16);
  const UINT32        ListSize  = (UINT32)(sizeof (EFI_SIGNATURE_LIST) + EntrySize);
  std::vector<UINT8>  Db (ListSize, 0);

  EFI_SIGNATURE_LIST  *List = (EFI_SIGNATURE_LIST *)Db.data ();

  CopyMem (&List->SignatureType, &gEfiCertX509Guid, sizeof (EFI_GUID));
  List->SignatureListSize   = ListSize;
  List->SignatureHeaderSize = ListSize;          // > ListSize - sizeof(EFI_SIGNATURE_LIST)
  List->SignatureSize       = EntrySize;

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// GetAuthenticodeHashAlgorithm fails on the image's signature. The
// signature must be skipped and, with no other signatures, the image
// must be rejected.
//
TEST (IsSignedImageAuthorizedTest, GetHashAlgoFails_RejectsSignature) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // db: one X.509 list with one cert. Need only enough to drive
  // IsPkcs7AuthDataAuthorizedByDb past its early Db-iter checks; we
  // expect to bail out before reaching the cert.
  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertX509Guid, 0, (UINT32)(sizeof (EFI_GUID) + 16), 1);

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (Return (EFI_UNSUPPORTED));
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// GetAuthenticodeHashAlgorithm returns a GUID that GetOrCompute-
// AuthenticodeHash does not recognize as an image-hash slot. The
// signature must be rejected.
//
TEST (IsSignedImageAuthorizedTest, GetHashAlgoReturnsUnknownGuid_RejectsSignature) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  std::vector<UINT8>  Db;

  AppendSignatureList (Db, gEfiCertX509Guid, 0, (UINT32)(sizeof (EFI_GUID) + 16), 1);

  DIGEST_CACHE  Cache = MakeBoundCache ();

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    // Not a recognized image hash GUID.
    *Out = gEfiCertX509Guid;
    return EFI_SUCCESS;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// db is malformed (less than one EFI_SIGNATURE_LIST header). The image
// digest lookup short-circuits to a non-success status (falls through
// to the signature walk); the per-signature DatabaseIterInit call then
// also fails. With no other signatures the image must be rejected.
//
TEST (IsSignedImageAuthorizedTest, MalformedDb_RejectsImage) {
  MockBaseCryptLib  BaseCryptLibMock;

  std::vector<UINT8>  FileBuf;

  AppendPkcs7Cert (FileBuf, 16, 0xA1);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // Less than sizeof(EFI_SIGNATURE_LIST) -> DatabaseIterInit fails.
  std::vector<UINT8>  Db (4, 0);

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _)).Times (0);

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_FALSE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND);
}

//
// First WIN_CERTIFICATE in the image has an unknown wCertificateType
// (GetWinCertificatePkcs7AuthData returns EFI_UNSUPPORTED) so the iteration
// continues to the next entry, which is a valid PKCS#7 that
// authorizes against db.
//
TEST (IsSignedImageAuthorizedTest, FirstCertUnsupportedSecondAuthorized_ReturnsTrue) {
  MockBaseCryptLib  BaseCryptLibMock;

  // Build two WIN_CERTIFICATE entries: an unknown type followed by a
  // PKCS#7 SignedData entry.
  std::vector<UINT8>  FileBuf;

  AppendWinCert (
    FileBuf,
    /*dwLength=*/ (UINT32)sizeof (WIN_CERTIFICATE) + 8,
    /*wRevision=*/ 0x0200,
    /*wCertificateType=*/ 0x0BAD
    );
  AppendPkcs7Cert (FileBuf, 16, 0xA2);

  EFI_IMAGE_DATA_DIRECTORY  SecDataDir = { 0, (UINT32)FileBuf.size () };

  // db with one valid X.509 trust anchor.
  std::vector<UINT8>  Db;
  size_t              DbOff = AppendSignatureList (
                                Db,
                                gEfiCertX509Guid,
                                0,
                                (UINT32)(sizeof (EFI_GUID) + 16),
                                1
                                );

  SetEntryPayload (Db, DbOff, 0, std::vector<UINT8>(16, 0x22));

  DIGEST_CACHE  Cache = MakeCacheWithDigest (
                          &gEfiCertSha256Guid,
                          std::vector<UINT8>(SHA256_DIGEST_SIZE, 0x55)
                          );

  Cache.Buffer = FileBuf.data ();
  Cache.BufferSize   = FileBuf.size ();

  EXPECT_CALL (BaseCryptLibMock, GetAuthenticodeHashAlgorithm (_, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, EFI_GUID *Out) -> EFI_STATUS {
    *Out = gEfiCertSha256Guid;
    return EFI_SUCCESS;
  }
         )
       );
  EXPECT_CALL (BaseCryptLibMock, AuthenticodeVerify (_, _, _, _, _, _))
    .WillOnce (Return (TRUE));
  EXPECT_CALL (BaseCryptLibMock, X509GetTBSCert (_, _, _, _))
    .WillOnce (
       Invoke (
         [] (CONST UINT8 *, UINTN, UINT8 **OutTbs, UINTN *OutTbsSize) -> BOOLEAN {
    static UINT8  TbsBytes[] = { 0x22 };
    *OutTbs                  = TbsBytes;
    *OutTbsSize              = sizeof (TbsBytes);
    return TRUE;
  }
         )
       );

  EFI_IMAGE_EXECUTION_ACTION  Action = EFI_IMAGE_EXECUTION_AUTH_UNTESTED;

  EXPECT_TRUE (
    IsSignedImageAuthorized (
      &SecDataDir,
      Db.data (),
      Db.size (),
      NULL,
      0,
      &Cache,
      &Action
      )
    );
  EXPECT_EQ (Action, (EFI_IMAGE_EXECUTION_ACTION)EFI_IMAGE_EXECUTION_AUTH_SIG_PASSED);
}
