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

/**
  Extract the DER-encoded PKCS#7 SignedData payload from a single WIN_CERTIFICATE entry.

  @param[in]   Cert          The certificate to inspect.
  @param[out]  AuthData      On success, set to point at the PKCS#7 payload inside Cert.
  @param[out]  AuthDataSize  On success, set to the PKCS#7 payload length in bytes.

  @retval EFI_SUCCESS            AuthData/AuthDataSize were populated.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_UNSUPPORTED        Unsupported WIN_CERTIFICATE type.
  @retval EFI_VOLUME_CORRUPTED   dwLength is too small to contain the required header for the
                                 declared type.
**/
EFI_STATUS
GetWinCertificatePkcs7AuthData (
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
  Determine whether a single PKCS#7 signature is authorized by an X.509 certificate in a single
  `EFI_SIGNATURE_LIST`.

  This is done by Iterating over the `List` EFI_SIGNATURE_LIST and checking if one of the
  X.509 certificates is a trust anchor for the provided PKCS#7 AuthData and that X.509
  certificate is not also found in the `dbx`.

  @param[in]  List           Candidate list of X.509 certificates (an EFI_SIGNATURE_LIST).
  @param[in]  AuthData       DER-encoded PKCS#7 SignedData.
  @param[in]  AuthDataSize   BufferSize of AuthData in bytes.
  @param[in]  ImageHash      Authenticode digest of the image.
  @param[in]  ImageHashSize  BufferSize of ImageHash in bytes.
  @param[in]  Dbx            Raw dbx contents, or NULL.
  @param[in]  DbxSize        BufferSize of Dbx in bytes; 0 when Dbx is NULL.

  @retval TRUE   At least one entry verifies AuthData and is not revoked.
  @retval FALSE  No entry verifies AuthData (or all that do are revoked).
**/
STATIC
BOOLEAN
IsPkcs7AuthDataAuthorizedBySignatureList (
  IN  CONST EFI_SIGNATURE_LIST  *List,
  IN  CONST UINT8               *AuthData,
  IN  UINTN                     AuthDataSize,
  IN  CONST UINT8               *ImageHash,
  IN  UINTN                     ImageHashSize,
  IN  CONST VOID                *Dbx,
  IN  UINTN                     DbxSize
  )
{
  SIG_LIST_ITER             Iter;
  CONST EFI_SIGNATURE_DATA  *Entry;
  CONST UINT8               *TrustedCert;
  UINTN                     TrustedCertSize;
  UINT8                     *TBSCert;
  UINTN                     TBSCertSize;

  //
  // We only care about X.509 certificate EFI_SIGNATURE_LISTs.
  //
  if (!CompareGuid (&List->SignatureType, &gEfiCertX509Guid)) {
    return FALSE;
  }

  //
  // If the signature size is less than or equal to an EFI_GUID there
  // is no cert payload to inspect.
  //
  if (List->SignatureSize <= sizeof (EFI_GUID)) {
    return FALSE;
  }

  if (EFI_ERROR (SigListIterInit (&Iter, List))) {
    return FALSE;
  }

  TrustedCertSize = List->SignatureSize - sizeof (EFI_GUID);

  while ((Entry = SigListIterNext (&Iter)) != NULL) {
    TrustedCert = Entry->SignatureData;

    if (!AuthenticodeVerify (
           AuthData,
           AuthDataSize,
           TrustedCert,
           TrustedCertSize,
           ImageHash,
           ImageHashSize
           ))
    {
      continue;
    }

    if (!X509GetTBSCert (TrustedCert, TrustedCertSize, &TBSCert, &TBSCertSize)) {
      DEBUG ((DEBUG_WARN, "DxeImageVerificationLib: X509GetTBSCert failed; treating cert as revoked.\n"));
      return FALSE;
    }

    //
    // The Authenticode signature is a valid trust anchor; make sure its not revoked
    //
    if (IsTBSCertHashInDbx (TBSCert, TBSCertSize, Dbx, DbxSize)) {
      DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: signing cert hash present in dbx; rejected.\n"));
      continue;
    }

    return TRUE;
  }

  return FALSE;
}

/**
  Determine whether a single PKCS#7 signature is authorized by an X.509 certificate in the `db`.

  This is done by Iterating over the `db` signature database and checking if a single X.509
  certificate in the `db` is a trust anchor for the provided PKCS#7 AuthData and that X.509
  certificate is not also found in the `dbx`.

  @param[in]      AuthData      DER-encoded PKCS#7 SignedData.
  @param[in]      AuthDataSize  BufferSize of AuthData in bytes.
  @param[in]      Db            Raw db contents, or NULL.
  @param[in]      DbSize        BufferSize of Db in bytes; 0 when Db is NULL.
  @param[in]      Dbx           Raw dbx contents, or NULL.
  @param[in]      DbxSize       BufferSize of Dbx in bytes; 0 when Dbx is NULL.
  @param[in,out]  Cache         Caller-owned digest cache bound to the
                                image being validated.

  @retval TRUE   The signature is authorized.
  @retval FALSE  The signature is not authorized, or the image digest
                 could not be computed.
**/
STATIC
BOOLEAN
IsPkcs7AuthDataAuthorizedByDb (
  IN     CONST UINT8   *AuthData,
  IN     UINTN         AuthDataSize,
  IN     CONST VOID    *Db,
  IN     UINTN         DbSize,
  IN     CONST VOID    *Dbx,
  IN     UINTN         DbxSize,
  IN OUT DIGEST_CACHE  *Cache
  )
{
  EFI_STATUS                Status;
  EFI_GUID                  HashType;
  CONST UINT8               *ImageHash;
  UINTN                     ImageHashSize;
  SIG_DATABASE_ITER         Iter;
  CONST EFI_SIGNATURE_LIST  *List;

  //
  // Get the hash algorithm this signature uses and compute the image
  // digest if we haven't already. Failure to do either step is treated
  // as a non-verifying signature.
  //
  Status = GetAuthenticodeHashAlgorithm (AuthData, AuthDataSize, &HashType);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_WARN,
      "DxeImageVerificationLib: skipping signature; GetAuthenticodeHashAlgorithm failed (%r).\n",
      Status
      ));
    return FALSE;
  }

  Status = GetHash (&HashType, Cache, &ImageHash, &ImageHashSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_WARN,
      "DxeImageVerificationLib: skipping signature; GetHash failed (%r).\n",
      Status
      ));
    return FALSE;
  }

  if (EFI_ERROR (DatabaseIterInit (&Iter, Db, DbSize))) {
    return FALSE;
  }

  //
  // Iterate over each signature list in the database.
  //
  while ((List = DatabaseIterNext (&Iter)) != NULL) {
    if (IsPkcs7AuthDataAuthorizedBySignatureList (
          List,
          AuthData,
          AuthDataSize,
          ImageHash,
          ImageHashSize,
          Dbx,
          DbxSize
          ))
    {
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Determine whether a signed PE/COFF image is authorized to execute by the platform's `db`
  signature database.

  An image can be authorized one of two ways:
    1. It's authenticode image hash is found in the `db` database.
    2. A X.509 certificate in the `db` is a trust anchor for one of the image's signatures, and
       that X.509 certificate is not also found in the `dbx`.

  @param[in]      SecDataDir  Security data directory in the PE/COFF image described by Cache.
  @param[in]      Db          The `db` signature database.
  @param[in]      DbSize      The size of the `db`.
  @param[in]      Dbx         The `dbx` signature database.
  @param[in]      DbxSize     The size of the `dbx`.
  @param[in,out]  Cache       DIGEST_CACHE pointer bound to the image being searched. The cache may
                              be updated during the search.
  @param[in,out]  Action      Updated to reflect the outcome of the authorization check.

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
  IN OUT DIGEST_CACHE                    *Cache,
  IN OUT EFI_IMAGE_EXECUTION_ACTION      *Action
  )
{
  EFI_STATUS             Status;
  BOOLEAN                IsFound;
  WIN_CERT_ITER          CertIter;
  CONST WIN_CERTIFICATE  *Cert;
  CONST UINT8            *AuthData;
  UINTN                  AuthDataSize;

  if ((SecDataDir == NULL) || (Cache == NULL) || (Cache->Buffer == NULL) ||
      (Cache->BufferSize == 0) || (Action == NULL))
  {
    return FALSE;
  }

  //
  // An image whose authenticode digest is found in db is authorized. No need to check the
  // security data directory and we can return early.
  //
  Status = IsImageDigestInDatabase (Db, DbSize, Cache, &IsFound);
  if (!EFI_ERROR (Status) && IsFound) {
    *Action = EFI_IMAGE_EXECUTION_AUTH_SIG_PASSED;
    return TRUE;
  }

  Status = WinCertIterInit (
             &CertIter,
             Cache->Buffer,
             Cache->BufferSize,
             SecDataDir
             );
  if (EFI_ERROR (Status)) {
    *Action = EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND;
    return FALSE;
  }

  //
  // Walk the image's security data directory (N sized list of WIN_CERTIFICATEs). For each
  // supported PKCS#7 signature, check whether any X509 certificate in `db` is a trust anchor and
  // not revoked by `dbx`.
  //
  while ((Cert = WinCertIterNext (&CertIter)) != NULL) {
    Status = GetWinCertificatePkcs7AuthData (Cert, &AuthData, &AuthDataSize);
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_WARN,
        "DxeImageVerificationLib: skipping WIN_CERTIFICATE (type=0x%04x, status=%r).\n",
        Cert->wCertificateType,
        Status
        ));
      continue;
    }

    if (IsPkcs7AuthDataAuthorizedByDb (AuthData, AuthDataSize, Db, DbSize, Dbx, DbxSize, Cache)) {
      *Action = EFI_IMAGE_EXECUTION_AUTH_SIG_PASSED;
      return TRUE;
    }
  }

  *Action = EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND;
  return FALSE;
}

/**
  Determine whether a signed PE/COFF image is revoked by the platform's
  `dbx` signature database.

  TODO: Currently a stub function

  @param[in]      SecDataDir  Security data directory describing the
                              embedded WIN_CERTIFICATE table.
  @param[in]      Dbx         Raw `dbx` signature database contents, or
                              NULL when the variable is absent.
  @param[in]      DbxSize     BufferSize of Dbx in bytes; 0 when Dbx is NULL.
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
  IN OUT DIGEST_CACHE                    *Cache,
  IN OUT EFI_IMAGE_EXECUTION_ACTION      *Action
  )
{
  if ((SecDataDir == NULL) || (Cache == NULL) || (Cache->Buffer == NULL) ||
      (Cache->BufferSize == 0) || (Action == NULL))
  {
    return FALSE;
  }

  return FALSE;
}
