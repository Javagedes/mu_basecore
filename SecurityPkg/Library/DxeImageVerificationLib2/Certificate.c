/** @file
  Signed image (certificate / Authenticode) validation helpers for the
  DXE Image Verification Library.

  Caution: This file consumes external input (the PE/COFF image and the
  Secure Boot signature databases). All inputs must be treated as
  attacker-controlled.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Certificate.h"
#include "Database.h"

#include <Guid/WinCertificate.h>

/**
  A callback that is executed by WalkImageSignatures once per supported
  WIN_CERTIFICATE entry in a PE/COFF image's attribute certificate
  table. The walker has already extracted the DER-encoded PKCS#7
  SignedData payload from the certificate.

  Returning EFI_SUCCESS continues iteration. Returning any other status
  stops the walk and the error is propagated to the caller.

  @param[in]  AuthData      Pointer to the PKCS#7 payload inside the
                            image's attribute certificate table.
                            Borrowed pointer; the callback must not
                            free it and must not retain it past return.
  @param[in]  AuthDataSize  Length of AuthData in bytes.
  @param[in]  Context       Caller-owned opaque pointer passed
                            unmodified through WalkImageSignatures.

  @retval EFI_SUCCESS  The signature was processed successfully.
  @retval other        Callback-specific error.
**/
typedef
EFI_STATUS
(EFIAPI *IMAGE_SIGNATURE_CALLBACK)(
  IN CONST UINT8  *AuthData,
  IN UINTN        AuthDataSize,
  IN VOID         *Context  OPTIONAL
  );

//
// Forward declarations of internal helpers. Definitions follow below;
// the public IsSignedImageAuthorized and IsSignedImageRevoked entry
// points are at the end of this file. These are not declared STATIC
// so that host-based unit tests can exercise them directly.
//
BOOLEAN
IsCertHashFoundInDbx (
  IN  CONST UINT8  *Cert,
  IN  UINTN        CertSize,
  IN  CONST VOID   *Dbx,
  IN  UINTN        DbxSize
  );

EFI_STATUS
WalkImageSignatures (
  IN  CONST VOID                      *FileBuffer,
  IN  UINTN                           FileSize,
  IN  CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir,
  IN  IMAGE_SIGNATURE_CALLBACK        Callback,
  IN  VOID                            *Context  OPTIONAL
  );

EFI_STATUS
GetWinCertificateAuthData (
  IN  CONST WIN_CERTIFICATE  *Cert,
  OUT CONST UINT8            **AuthData,
  OUT UINTN                  *AuthDataSize
  );

EFI_STATUS
EFIAPI
VerifyImageSignatureCallback (
  IN CONST UINT8  *AuthData,
  IN UINTN        AuthDataSize,
  IN VOID         *Context  OPTIONAL
  );

//
// Context passed to VerifyAuthDataAgainstX509ListCallback while
// walking the db. The callback only inspects EFI_SIGNATURE_LISTs whose
// SignatureType is gEfiCertX509Guid; for each X509 entry it invokes
// AuthenticodeVerify and, when verification succeeds, additionally
// checks that the trusted cert's hash is not present in dbx before
// accepting the signature.
//
typedef struct {
  CONST UINT8    *AuthData;
  UINTN          AuthDataSize;
  CONST UINT8    *ImageHash;
  UINTN          ImageHashSize;
  CONST VOID     *Dbx;
  UINTN          DbxSize;
  BOOLEAN        Verified;
} VERIFY_X509_CTX;

/**
  WalkSignatureDatabase callback to check if a X509 certificate in the `db` is a trust anchor for
  the PKCS#7 signature provided by the callback context.

  A successful verification is when AuthenticodeVerify returns TRUE for the cert in the `db` and
  the hash of that cert's TBSCertificate is not found in the `dbx`.

  Records a successful verification by setting Search->Verified to TRUE and returning EFI_ABORTED
  to short circuit the walk. Otherwise this always returns EFI_SUCCESS so the walk continues until
  all EFI_SIGNATURE_LIST entries of SignatureType gEfiCertX509Guid have been checked.
**/
EFI_STATUS
EFIAPI
VerifyAuthDataAgainstX509ListCallback (
  IN CONST EFI_SIGNATURE_LIST  *List,
  IN VOID                      *Context  OPTIONAL
  )
{
  VERIFY_X509_CTX           *Search;
  UINTN                     EntryCount;
  CONST UINT8               *EntryCursor;
  CONST EFI_SIGNATURE_DATA  *Entry;
  CONST UINT8               *TrustedCert;
  UINTN                     CertSize;
  UINTN                     Index;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // We only care about X.509 certificate EFI_SIGNATURE_LISTs.
  //
  if (!CompareGuid (&List->SignatureType, &gEfiCertX509Guid)) {
    return EFI_SUCCESS;
  }

  Search = (VERIFY_X509_CTX *)Context;

  //
  // If the signature size is less then an EFI_GUID, it is malformed and should be skipped.
  //
  if (List->SignatureSize <= sizeof (EFI_GUID)) {
    return EFI_SUCCESS;
  }

  //
  // Iterate through each X.509 certificate in the EFI_SIGNATURE_LIST
  //
  EntryCount = (List->SignatureListSize
                - sizeof (EFI_SIGNATURE_LIST)
                - List->SignatureHeaderSize) / List->SignatureSize;
  EntryCursor = (CONST UINT8 *)List
                + sizeof (EFI_SIGNATURE_LIST)
                + List->SignatureHeaderSize;

  for (Index = 0; Index < EntryCount; Index++) {
    Entry       = (CONST EFI_SIGNATURE_DATA *)EntryCursor;
    TrustedCert = Entry->SignatureData;
    CertSize    = List->SignatureSize - sizeof (EFI_GUID);

    //
    // Check if this X.509 certificate is a trust anchor for the PKCS#7 signature provided by the
    // callback context.
    //
    if (AuthenticodeVerify (
          Search->AuthData,
          Search->AuthDataSize,
          TrustedCert,
          CertSize,
          Search->ImageHash,
          Search->ImageHashSize
          ))
    {
      //
      // The certificate is a valid trust anchor, make sure the TBS certificate is not revoked.
      //
      if (!IsCertHashFoundInDbx (TrustedCert, CertSize, Search->Dbx, Search->DbxSize)) {
        //
        // Match found and cert is not revoked; set verified and short circuit the walk.
        //
        Search->Verified = TRUE;
        return EFI_ABORTED;
      }

      DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: signing cert hash present in dbx; rejected.\n"));
    }

    EntryCursor += List->SignatureSize;
  }

  return EFI_SUCCESS;
}

//
// Context passed to VerifyImageSignatureCallback while walking the
// image's attribute certificate table. The callback uses Db to
// authenticate each AuthData; on the first verification success whose
// signing certificate is not revoked by Dbx it flips Authorized and
// aborts the walk.
//
typedef struct {
  CONST VOID            *Db;
  UINTN                 DbSize;
  CONST VOID            *Dbx;
  UINTN                 DbxSize;
  IMAGE_DIGEST_CACHE    *Cache;
  BOOLEAN               Authorized;
} AUTHORIZE_SIG_CTX;

/**
  WalkImageSignatures callback that checks if any X509 certificates in the `db` are a trust anchor
  for the current PKCS#7 signature (AuthData/AuthDataSize).

  If a trust anchor is found, check the dbx to ensure the certificate is not revoked. The image is
  only authorized if a certificate in the `db` is both a trust anchor for the current signature and
  not revoked.

  Records a successful verification by setting Ctx->Authorized to TRUE and returning EFI_ABORTED to
  short circuit the walk. Otherwise this always returns EFI_SUCCESS so the walk continues so that
  all signatures are checked.
**/
EFI_STATUS
EFIAPI
VerifyImageSignatureCallback (
  IN CONST UINT8  *AuthData,
  IN UINTN        AuthDataSize,
  IN VOID         *Context  OPTIONAL
  )
{
  EFI_STATUS         Status;
  AUTHORIZE_SIG_CTX  *Ctx;
  EFI_GUID           HashType;
  CONST UINT8        *ImageHash;
  UINTN              ImageHashSize;
  VERIFY_X509_CTX    Search;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Ctx = (AUTHORIZE_SIG_CTX *)Context;

  //
  // Get the hash algorithm this signature uses and compute the image digest if we haven't already.
  // Failure to do either step is logged and treated as a non-verifying signatures. We will
  // continue to walk the rest of the signatures.
  //
  Status = GetAuthenticodeHashAlgorithm (AuthData, AuthDataSize, &HashType);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_WARN,
      "DxeImageVerificationLib: skipping signature; GetAuthenticodeHashAlgorithm failed (%r).\n",
      Status
      ));
    return EFI_SUCCESS;
  }

  Status = GetOrComputeAuthenticodeHash (&HashType, Ctx->Cache, &ImageHash, &ImageHashSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_WARN,
      "DxeImageVerificationLib: skipping signature; GetOrComputeAuthenticodeHash failed (%r).\n",
      Status
      ));
    return EFI_SUCCESS;
  }

  Search = (VERIFY_X509_CTX) {
    .AuthData      = AuthData,
    .AuthDataSize  = AuthDataSize,
    .ImageHash     = ImageHash,
    .ImageHashSize = ImageHashSize,
    .Dbx           = Ctx->Dbx,
    .DbxSize       = Ctx->DbxSize,
    .Verified      = FALSE
  };

  //
  // Walk db looking for an X509 certificate that is a trust anchor for this signature.
  //
  Status = WalkSignatureDatabase (
             Ctx->Db,
             Ctx->DbSize,
             VerifyAuthDataAgainstX509ListCallback,
             &Search
             );
  //
  // EFI_ABORTED is a short circuit, not an error; translate it back to success and continue.
  //
  if (Status == EFI_ABORTED) {
    Status = EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // This funciton is a callback for every signature in the image. Short circuit on the first
  // verifying signature since that's sufficient to authorize the image.
  //
  if (Search.Verified) {
    Ctx->Authorized = TRUE;
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}

//
// Context passed to CertHashSearchCallback while walking dbx. The
// callback compares the SHA-256/384/512 digest of TBSCert against
// every gEfiCertX509Sha{256,384,512}Guid entry it encounters and
// records the first match.
//
typedef struct {
  CONST UINT8    *TBSCert;
  UINTN          TBSCertSize;
  BOOLEAN        Found;
} CERT_HASH_SEARCH_CTX;

/**
  WalkSignatureDatabase callback that searches the dbx for a hash of a
  candidate X.509 certificate's TBSCertificate.

  Lists whose SignatureType is not one of gEfiCertX509Sha256Guid /
  gEfiCertX509Sha384Guid / gEfiCertX509Sha512Guid are ignored. For
  matching lists the TBSCert is hashed with the corresponding
  algorithm and compared against the leading digest bytes of every
  entry. The first match flips Search->Found and returns EFI_ABORTED
  so the database walk terminates immediately.
**/
EFI_STATUS
EFIAPI
CertHashSearchCallback (
  IN CONST EFI_SIGNATURE_LIST  *List,
  IN VOID                      *Context  OPTIONAL
  )
{
  CERT_HASH_SEARCH_CTX      *Search;
  UINTN                     DigestSize;
  UINT8                     CertDigest[SHA512_DIGEST_SIZE];
  BOOLEAN                   HashOk;
  UINTN                     EntryCount;
  CONST UINT8               *EntryCursor;
  CONST EFI_SIGNATURE_DATA  *Entry;
  UINTN                     Index;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Search = (CERT_HASH_SEARCH_CTX *)Context;

  if (CompareGuid (&List->SignatureType, &gEfiCertX509Sha256Guid)) {
    DigestSize = SHA256_DIGEST_SIZE;
    HashOk     = Sha256HashAll (Search->TBSCert, Search->TBSCertSize, CertDigest);
  } else if (CompareGuid (&List->SignatureType, &gEfiCertX509Sha384Guid)) {
    DigestSize = SHA384_DIGEST_SIZE;
    HashOk     = Sha384HashAll (Search->TBSCert, Search->TBSCertSize, CertDigest);
  } else if (CompareGuid (&List->SignatureType, &gEfiCertX509Sha512Guid)) {
    DigestSize = SHA512_DIGEST_SIZE;
    HashOk     = Sha512HashAll (Search->TBSCert, Search->TBSCertSize, CertDigest);
  } else {
    return EFI_SUCCESS;
  }

  if (!HashOk) {
    DEBUG ((DEBUG_WARN, "DxeImageVerificationLib: TBS cert hash failed; skipping list.\n"));
    return EFI_SUCCESS;
  }

  //
  // Each entry is laid out as `EFI_GUID owner | digest | EFI_TIME`. We
  // only compare the digest portion; the EFI_TIME (revocation time)
  // is intentionally ignored.
  //
  if (List->SignatureSize < sizeof (EFI_GUID) + DigestSize) {
    return EFI_SUCCESS;
  }

  EntryCount = (List->SignatureListSize
                - sizeof (EFI_SIGNATURE_LIST)
                - List->SignatureHeaderSize) / List->SignatureSize;
  EntryCursor = (CONST UINT8 *)List
                + sizeof (EFI_SIGNATURE_LIST)
                + List->SignatureHeaderSize;

  for (Index = 0; Index < EntryCount; Index++) {
    Entry = (CONST EFI_SIGNATURE_DATA *)EntryCursor;
    if (CompareMem (Entry->SignatureData, CertDigest, DigestSize) == 0) {
      Search->Found = TRUE;
      return EFI_ABORTED;
    }

    EntryCursor += List->SignatureSize;
  }

  return EFI_SUCCESS;
}

/**
  Determine whether a SHA-256/384/512 hash of a given X.509 certificate's
  TBSCertificate is present in dbx.

  When dbx is empty or absent the result is FALSE. Any failure that
  prevents a definitive answer (TBSCertificate cannot be extracted,
  dbx is malformed, etc.) is logged and reported as TRUE so callers
  conservatively refuse to trust the certificate.

  @param[in]  Cert      DER-encoded X.509 certificate.
  @param[in]  CertSize  Size of Cert in bytes.
  @param[in]  Dbx       Raw dbx contents, or NULL.
  @param[in]  DbxSize   Size of Dbx in bytes; 0 when Dbx is NULL.

  @retval TRUE   The certificate hash was located in dbx, or an error
                 prevented a definitive answer.
  @retval FALSE  The certificate hash is not present in dbx.
**/
BOOLEAN
IsCertHashFoundInDbx (
  IN  CONST UINT8  *Cert,
  IN  UINTN        CertSize,
  IN  CONST VOID   *Dbx,
  IN  UINTN        DbxSize
  )
{
  EFI_STATUS            Status;
  CERT_HASH_SEARCH_CTX  Search;
  UINT8                 *TBSCert;
  UINTN                 TBSCertSize;

  if ((Dbx == NULL) || (DbxSize == 0)) {
    return FALSE;
  }

  if (!X509GetTBSCert (Cert, CertSize, &TBSCert, &TBSCertSize)) {
    DEBUG ((DEBUG_WARN, "DxeImageVerificationLib: X509GetTBSCert failed; treating cert as revoked.\n"));
    return TRUE;
  }

  Search = (CERT_HASH_SEARCH_CTX) {
    .TBSCert     = TBSCert,
    .TBSCertSize = TBSCertSize,
    .Found       = FALSE
  };

  Status = WalkSignatureDatabase (Dbx, DbxSize, CertHashSearchCallback, &Search);
  //
  // CertHashSearchCallback returns EFI_ABORTED to stop the walk on
  // the first match; translate it back.
  //
  if (Status == EFI_ABORTED) {
    Status = EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_WARN,
      "DxeImageVerificationLib: dbx walk failed (%r); treating cert as revoked.\n",
      Status
      ));
    return TRUE;
  }

  return Search.Found;
}

/**
  Walk a PE/COFF image's security data directory and invoke a callback for each PKCS#7 signature.

  @param[in]  FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]  FileSize    Size of FileBuffer in bytes.
  @param[in]  SecDataDir  Security data directory describing the
                          embedded WIN_CERTIFICATE table.
  @param[in]  Callback    Invoked once per supported PKCS#7 signature.
  @param[in]  Context     Opaque pointer passed unmodified to Callback.

  @retval EFI_SUCCESS            The table was fully consumed and
                                 Callback returned EFI_SUCCESS for
                                 every invocation.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_VOLUME_CORRUPTED   The certificate table is structurally
                                 invalid in a way that prevents safe
                                 iteration.
  @retval other                  First non-EFI_SUCCESS status returned
                                 by Callback. Iteration stops
                                 immediately.
**/
EFI_STATUS
WalkImageSignatures (
  IN  CONST VOID                      *FileBuffer,
  IN  UINTN                           FileSize,
  IN  CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir,
  IN  IMAGE_SIGNATURE_CALLBACK        Callback,
  IN  VOID                            *Context  OPTIONAL
  )
{
  CONST UINT8            *Cursor;
  UINTN                  Remaining;
  CONST WIN_CERTIFICATE  *Cert;
  UINTN                  EntrySize;
  CONST UINT8            *AuthData;
  UINTN                  AuthDataSize;
  EFI_STATUS             Status;

  if ((FileBuffer == NULL) || (SecDataDir == NULL) || (Callback == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // The Security data directory must lie entirely within the file buffer provided by the caller.
  //
  if ((SecDataDir->VirtualAddress > FileSize) ||
      (SecDataDir->Size > FileSize - SecDataDir->VirtualAddress))
  {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: provided security data directory is out of bounds of the file.\n"));
    return EFI_VOLUME_CORRUPTED;
  }

  Cursor    = (CONST UINT8 *)FileBuffer + SecDataDir->VirtualAddress;
  Remaining = SecDataDir->Size;

  while (Remaining >= sizeof (WIN_CERTIFICATE)) {
    Cert = (CONST WIN_CERTIFICATE *)(CONST VOID *)Cursor;

    //
    // dwLength is the total bytes of this entry including the WIN_CERTIFICATE header.
    // Entries that don't cover their own header, or extend past the remaining table size
    // indicate the data directory layout is corrupted. Abort the walk completely.
    //
    if ((Cert->dwLength < sizeof (WIN_CERTIFICATE)) ||
        (Cert->dwLength > Remaining))
    {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: malformed WIN_CERTIFICATE dwLength.\n"));
      return EFI_VOLUME_CORRUPTED;
    }

    Status = GetWinCertificateAuthData (Cert, &AuthData, &AuthDataSize);
    if (Status == EFI_SUCCESS) {
      Status = Callback (AuthData, AuthDataSize, Context);
      if (EFI_ERROR (Status)) {
        return Status;
      }
    } else {
      //
      // Skip unsupported certificate types and per-entry corruption
      // (dwLength too small for the declared type header). Continuing
      // here preserves legacy behavior and avoids masking later
      // callback-reported failures behind a single bad entry.
      //
      DEBUG ((
        DEBUG_WARN,
        "DxeImageVerificationLib: skipping WIN_CERTIFICATE (type=0x%04x, status=%r).\n",
        Cert->wCertificateType,
        Status
        ));
    }

    //
    // Each entry is padded to an 8-byte boundary. The rounded-up size
    // may exceed Remaining if the final entry uses up the rest of the
    // table without padding; clamp to Remaining in that case so the
    // walk terminates cleanly.
    //
    EntrySize = ALIGN_VALUE (Cert->dwLength, 8);
    if (EntrySize > Remaining) {
      EntrySize = Remaining;
    }

    Cursor    += EntrySize;
    Remaining -= EntrySize;
  }

  return EFI_SUCCESS;
}

/**
  Extract the DER-encoded PKCS#7 SignedData payload from a single
  WIN_CERTIFICATE entry.

  @param[in]   Cert          The certificate to inspect.
  @param[out]  AuthData      On success, set to point at the PKCS#7
                             payload inside Cert. Borrowed pointer;
                             the caller must not free it and must not
                             outlive Cert.
  @param[out]  AuthDataSize  On success, set to the PKCS#7 payload
                             length in bytes.

  @retval EFI_SUCCESS            AuthData/AuthDataSize were populated.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_UNSUPPORTED        The certificate's wCertificateType (or
                                 CertType for WIN_CERT_TYPE_EFI_GUID)
                                 is not a supported PKCS#7 carrier.
  @retval EFI_VOLUME_CORRUPTED   dwLength is too small to contain the
                                 required header for the declared type.
**/
EFI_STATUS
GetWinCertificateAuthData (
  IN  CONST WIN_CERTIFICATE  *Cert,
  OUT CONST UINT8            **AuthData,
  OUT UINTN                  *AuthDataSize
  )
{
  CONST WIN_CERTIFICATE_UEFI_GUID  *UefiGuidCert;

  if ((Cert == NULL) || (AuthData == NULL) || (AuthDataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  switch (Cert->wCertificateType) {
    case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
      //
      // The certificate is a bare DER-encoded PKCS#7 SignedData prefixed
      // by the WIN_CERTIFICATE header.
      //
      if (Cert->dwLength <= sizeof (WIN_CERTIFICATE)) {
        return EFI_VOLUME_CORRUPTED;
      }

      *AuthData     = (CONST UINT8 *)Cert + sizeof (WIN_CERTIFICATE);
      *AuthDataSize = Cert->dwLength - sizeof (WIN_CERTIFICATE);
      return EFI_SUCCESS;

    case WIN_CERT_TYPE_EFI_GUID:
      //
      // The certificate is a WIN_CERTIFICATE_UEFI_GUID; the embedded
      // payload format is identified by CertType. Only the PKCS#7
      // SignedData GUID is supported.
      //
      if (Cert->dwLength <= OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)) {
        return EFI_VOLUME_CORRUPTED;
      }

      UefiGuidCert = (CONST WIN_CERTIFICATE_UEFI_GUID *)Cert;
      if (!CompareGuid (&UefiGuidCert->CertType, &gEfiCertPkcs7Guid)) {
        return EFI_UNSUPPORTED;
      }

      *AuthData     = UefiGuidCert->CertData;
      *AuthDataSize = Cert->dwLength - OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
      return EFI_SUCCESS;

    default:
      return EFI_UNSUPPORTED;
  }
}

/**
  Determine whether a signed PE/COFF image is authorized to execute by
  the platform's `db` signature database.

  Authorization succeeds when at least one of the image's embedded
  signatures (or one of its image hashes) is reflected in `db`. The
  shared IMAGE_DIGEST_CACHE is used to avoid recomputing Authenticode
  digests across signature-list iterations. On a definitive outcome the
  function updates `*Action` with the corresponding
  EFI_IMAGE_EXECUTION_ACTION value.

  @param[in]      SecDataDir  Security data directory describing the
                              embedded WIN_CERTIFICATE table.
  @param[in]      Db          Raw `db` signature database contents, or
                              NULL when the variable is absent.
  @param[in]      DbSize      Size of Db in bytes; 0 when Db is NULL.
  @param[in]      Dbx         Raw `dbx` signature database contents, or
                              NULL when the variable is absent. Used to
                              reject signing certificates and image
                              hashes that have been revoked even when
                              they would otherwise authorize the image.
  @param[in]      DbxSize     Size of Dbx in bytes; 0 when Dbx is NULL.
  @param[in,out]  Cache       Caller-owned digest cache bound to the
                              image being validated. The image buffer
                              and size are taken from the cache.
                              Updated as digests are computed.
  @param[in,out]  Action      Updated to reflect the outcome of the
                              authorization check.

  @retval TRUE   The image is authorized by `db`.
  @retval FALSE  The image is not authorized, or an error prevented a
                 definitive answer.
**/
BOOLEAN
IsSignedImageAuthorized (
  IN     CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir,
  IN     CONST VOID                      *Db,
  IN     UINTN                           DbSize,
  IN     CONST VOID                      *Dbx,
  IN     UINTN                           DbxSize,
  IN OUT IMAGE_DIGEST_CACHE              *Cache,
  IN OUT EFI_IMAGE_EXECUTION_ACTION      *Action
  )
{
  EFI_STATUS         Status;
  BOOLEAN            IsFound;
  AUTHORIZE_SIG_CTX  SigCtx;

  if ((SecDataDir == NULL) || (Cache == NULL) || (Cache->FileBuffer == NULL) ||
      (Cache->FileSize == 0) || (Action == NULL))
  {
    return FALSE;
  }

  //
  // An image whose authenticode digest is found in db is authorized. No need to check the
  // security data directory and we can return early.
  //
  Status = IsImageDigestFoundInDatabase (Db, DbSize, Cache, &IsFound);
  if (!EFI_ERROR (Status) && IsFound) {
    return TRUE;
  }

  //
  // Check if any X509 certificates in the `db` are a trust anchor for any of the image's
  // signatures. If so, the image is marked as authorized.
  //
  SigCtx = (AUTHORIZE_SIG_CTX) {
    .Db         = Db,
    .DbSize     = DbSize,
    .Dbx        = Dbx,
    .DbxSize    = DbxSize,
    .Cache      = Cache,
    .Authorized = FALSE
  };

  Status = WalkImageSignatures (
             Cache->FileBuffer,
             Cache->FileSize,
             SecDataDir,
             VerifyImageSignatureCallback,
             &SigCtx
             );
  //
  // EFI_ABORTED is returned to short-circuit the walk once a trust anchor is found, so convert it
  // to EFI_SUCCESS.
  //
  if (Status == EFI_ABORTED) {
    Status = EFI_SUCCESS;
  }

  if (!EFI_ERROR (Status) && SigCtx.Authorized) {
    return TRUE;
  }

  *Action = EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND;
  return FALSE;
}

/**
  Determine whether a signed PE/COFF image is revoked by the platform's
  `dbx` signature database.

  Revocation succeeds (returns TRUE) when any of the image's embedded
  signatures, signing certificates, or image hashes are reflected in
  `dbx`. The shared IMAGE_DIGEST_CACHE is reused so that digests
  computed during the authorization check are not recomputed here. On a
  definitive outcome the function updates `*Action` with the
  corresponding EFI_IMAGE_EXECUTION_ACTION value.

  @param[in]      SecDataDir  Security data directory describing the
                              embedded WIN_CERTIFICATE table.
  @param[in]      Dbx         Raw `dbx` signature database contents, or
                              NULL when the variable is absent.
  @param[in]      DbxSize     Size of Dbx in bytes; 0 when Dbx is NULL.
  @param[in,out]  Cache       Caller-owned digest cache bound to the
                              image being validated. The image buffer
                              and size are taken from the cache.
                              Updated as digests are computed.
  @param[in,out]  Action      Updated to reflect the outcome of the
                              revocation check.

  @retval TRUE   The image is revoked by `dbx`.
  @retval FALSE  The image is not revoked.
**/
BOOLEAN
IsSignedImageRevoked (
  IN     CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir,
  IN     CONST VOID                      *Dbx,
  IN     UINTN                           DbxSize,
  IN OUT IMAGE_DIGEST_CACHE              *Cache,
  IN OUT EFI_IMAGE_EXECUTION_ACTION      *Action
  )
{
  if ((SecDataDir == NULL) || (Cache == NULL) || (Cache->FileBuffer == NULL) ||
      (Cache->FileSize == 0) || (Action == NULL))
  {
    return FALSE;
  }

  return FALSE;
}
