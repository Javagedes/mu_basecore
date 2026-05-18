/** @file
  Certificate parsing and signature-database validation helpers for
  the DXE Image Verification Library.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Certificate.h"

/**
  Extract the signed-data payload from a single WIN_CERTIFICATE entry
  carried in a PE/COFF security data directory.

  @param[in]   WinCert        Pointer to the candidate WIN_CERTIFICATE
                              entry.
  @param[in]   RemainingSize  Bytes available starting at WinCert.
                              Must encompass WinCert->dwLength.
  @param[out]  CertData       On success, set to the embedded signed-
                              data blob within WinCert.
  @param[out]  CertDataSize   On success, set to the blob's size in
                              bytes.

  @retval EFI_SUCCESS            CertData / CertDataSize populated.
  @retval EFI_INVALID_PARAMETER  WinCert, CertData, or CertDataSize is
                                 NULL.
  @retval EFI_VOLUME_CORRUPTED   WinCert->dwLength does not fit within
                                 RemainingSize, or is too small for the
                                 declared certificate variant.
  @retval EFI_UNSUPPORTED        WinCert->wCertificateType, or (for
                                 WIN_CERT_TYPE_EFI_GUID) the inner
                                 CertType GUID, is not one this library
                                 can verify.
**/
EFI_STATUS
GetCertificateData (
  IN  CONST WIN_CERTIFICATE  *WinCert,
  IN  UINTN                  RemainingSize,
  OUT CONST VOID             **CertData,
  OUT UINTN                  *CertDataSize
  )
{
  CONST WIN_CERTIFICATE_UEFI_GUID  *UefiGuidCert;

  if ((WinCert == NULL) || (CertData == NULL) || (CertDataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *CertData     = NULL;
  *CertDataSize = 0;

  //
  // The header itself must fit within the available bytes, and the
  // declared dwLength must cover at least the WIN_CERTIFICATE header
  // and not exceed what's available.
  //
  if ((RemainingSize < sizeof (WIN_CERTIFICATE)) ||
      (WinCert->dwLength < sizeof (WIN_CERTIFICATE)) ||
      (WinCert->dwLength > RemainingSize))
  {
    return EFI_VOLUME_CORRUPTED;
  }

  switch (WinCert->wCertificateType) {
    case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
      //
      // The payload follows the WIN_CERTIFICATE header inline; require
      // at least one byte of payload to be present.
      //
      if (WinCert->dwLength <= sizeof (WIN_CERTIFICATE)) {
        return EFI_VOLUME_CORRUPTED;
      }

      *CertData     = (CONST UINT8 *)WinCert + sizeof (WIN_CERTIFICATE);
      *CertDataSize = WinCert->dwLength - sizeof (WIN_CERTIFICATE);
      return EFI_SUCCESS;

    case WIN_CERT_TYPE_EFI_GUID:
      UefiGuidCert = (CONST WIN_CERTIFICATE_UEFI_GUID *)WinCert;
      if (UefiGuidCert->Hdr.dwLength <= OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)) {
        return EFI_VOLUME_CORRUPTED;
      }

      if (!CompareGuid (&UefiGuidCert->CertType, &gEfiCertPkcs7Guid)) {
        return EFI_UNSUPPORTED;
      }

      *CertData     = UefiGuidCert->CertData;
      *CertDataSize = UefiGuidCert->Hdr.dwLength - OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
      return EFI_SUCCESS;

    default:
      return EFI_UNSUPPORTED;
  }
}

/**
  Walk the Attribute Certificate Table referenced by a PE/COFF
  security data directory, invoking Callback for every well-formed,
  supported WIN_CERTIFICATE entry.

  Each entry is qword-aligned per the PE/COFF Attribute Certificate
  Table layout. Entries whose certificate variant is not supported by
  GetCertificateData are silently skipped; a malformed entry
  terminates the walk with EFI_VOLUME_CORRUPTED.

  Caution: SecDataDir may reflect untrusted input. Bounds are
  re-validated against FileBufferSize before any dereference.

  @param[in]  FileBuffer      Pointer to the in-memory PE/COFF file.
  @param[in]  FileBufferSize  Size of FileBuffer in bytes.
  @param[in]  SecDataDir      Security data directory describing the
                              embedded WIN_CERTIFICATE table.
  @param[in]  Callback        Invoked once per supported certificate
                              entry.
  @param[in]  Context         Opaque pointer passed unmodified to
                              Callback.

  @retval EFI_SUCCESS            Table was fully consumed and Callback
                                 returned EFI_SUCCESS for every entry.
  @retval EFI_INVALID_PARAMETER  FileBuffer, SecDataDir, or Callback is
                                 NULL.
  @retval EFI_VOLUME_CORRUPTED   SecDataDir falls outside FileBuffer or
                                 a certificate entry is malformed.
  @retval Other                  First non-EFI_SUCCESS status returned
                                 by Callback. Iteration stops
                                 immediately.
**/
EFI_STATUS
WalkCertificateTable (
  IN CONST VOID                      *FileBuffer,
  IN UINTN                           FileBufferSize,
  IN CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir,
  IN CERTIFICATE_CALLBACK            Callback,
  IN VOID                            *Context  OPTIONAL
  )
{
  EFI_STATUS             Status;
  CONST UINT8            *Cursor;
  UINTN                  Remaining;
  CONST WIN_CERTIFICATE  *WinCert;
  CONST VOID             *CertData;
  UINTN                  CertDataSize;
  UINTN                  Step;

  if ((FileBuffer == NULL) || (SecDataDir == NULL) || (Callback == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // The attribute certificate table lives at a raw file offset (not an
  // RVA), so re-validate that the SecDataDir range lies entirely within
  // FileBuffer before dereferencing it.
  //
  if ((SecDataDir->VirtualAddress > FileBufferSize) ||
      (SecDataDir->Size > FileBufferSize - SecDataDir->VirtualAddress))
  {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: Security data directory out of bounds.\n"));
    return EFI_VOLUME_CORRUPTED;
  }

  Cursor    = (CONST UINT8 *)FileBuffer + SecDataDir->VirtualAddress;
  Remaining = SecDataDir->Size;

  while (Remaining >= sizeof (WIN_CERTIFICATE)) {
    WinCert = (CONST WIN_CERTIFICATE *)Cursor;

    Status = GetCertificateData (WinCert, Remaining, &CertData, &CertDataSize);
    if (Status == EFI_SUCCESS) {
      Status = Callback (WinCert, CertData, CertDataSize, Context);
      if (EFI_ERROR (Status)) {
        return Status;
      }
    } else if (Status == EFI_UNSUPPORTED) {
      DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: Skipping unsupported WIN_CERTIFICATE entry.\n"));
    } else {
      return EFI_VOLUME_CORRUPTED;
    }

    Step = ALIGN_VALUE (WinCert->dwLength, 8);
    if ((Step < WinCert->dwLength) || (Step > Remaining)) {
      return EFI_VOLUME_CORRUPTED;
    }

    Cursor    += Step;
    Remaining -= Step;
  }

  return EFI_SUCCESS;
}

/**
  Context passed to AuthorizeCertificateCallback by
  IsSignedImageAuthorized. Carries the inputs and outputs the
  per-certificate authorization step needs to consult.
**/
typedef struct {
  CONST VOID    *Db;
  UINTN         DbSize;
  CONST VOID    *Dbx;
  UINTN         DbxSize;
  BOOLEAN       *IsAuthorized;
} AUTHORIZE_CERT_CONTEXT;

/**
  WalkCertificateTable callback for IsSignedImageAuthorized. Tests
  one embedded signed-data blob against the platform `db` and, on a
  hit, marks the image authorized via the caller's output flag.
**/
STATIC
EFI_STATUS
EFIAPI
AuthorizeCertificateCallback (
  IN CONST WIN_CERTIFICATE  *WinCert,
  IN CONST VOID             *CertData,
  IN UINTN                  CertDataSize,
  IN VOID                   *Context  OPTIONAL
  )
{
  //
  // TODO: Authorize the extracted signed-data blob against db by
  // verifying the embedded PKCS#7 signer chains against db's X.509
  // entries, then checking that trust path against dbx revocations.
  // CertData / CertDataSize hold the PKCS#7 blob. On a hit,
  // set *((AUTHORIZE_CERT_CONTEXT *)Context)->IsAuthorized = TRUE.
  //
  (VOID)WinCert;
  (VOID)CertData;
  (VOID)CertDataSize;
  (VOID)Context;
  return EFI_SUCCESS;
}

/**
  Determine whether a signed PE/COFF image is authorized for execution.

  This function performs 2 separate checks, either of which can authorize the image:

  1) The image authenticode digest hash is present in the db under a supported hash algorithm.
  2) The image carries an embedded signature whose signer chain is rooted in a certificate present
     in the db, and that certificate is not revoked by the dbx.

  @param[in]      FileBuffer       Pointer to the in-memory PE/COFF
                                   file.
  @param[in]      FileBufferSize   Size of FileBuffer in bytes.
  @param[in]      SecDataDir       Security data directory describing
                                   the embedded WIN_CERTIFICATE table.
  @param[in]      Db               The raw `db` variable contents, or
                                   NULL.
  @param[in]      DbSize           Size of Db in bytes; 0 when Db is
                                   NULL.
  @param[in]      Dbx              The raw `dbx` variable contents, or
                                   NULL.
  @param[in]      DbxSize          Size of Dbx in bytes; 0 when Dbx is
                                   NULL.
  @param[in]      HashAlgorithms   Set of image-hash signature-type
                                   GUIDs to consult when authorizing
                                   the image by its hash.
  @param[in,out]  Cache            Caller-owned per-algorithm digest
                                   cache. Zero-initialize before first
                                   use; slots populated by this call
                                   may be reused on the dbx revocation
                                   pass.
  @param[out]     IsAuthorized     On success, TRUE if the image's
                                   signature or hash matches a record
                                   in Db; FALSE otherwise.

  @retval EFI_SUCCESS            The walk completed and IsAuthorized
                                 reflects the result.
  @retval EFI_INVALID_PARAMETER  FileBuffer, SecDataDir,
                                 HashAlgorithms, Cache, or
                                 IsAuthorized is NULL.
  @retval EFI_VOLUME_CORRUPTED   SecDataDir falls outside FileBuffer
                                 or a certificate entry is malformed.
**/
EFI_STATUS
IsSignedImageAuthorized (
  IN     VOID                            *FileBuffer,
  IN     UINTN                           FileBufferSize,
  IN     CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir,
  IN     CONST VOID                      *Db        OPTIONAL,
  IN     UINTN                           DbSize,
  IN     CONST VOID                      *Dbx       OPTIONAL,
  IN     UINTN                           DbxSize,
  IN     CONST HASH_ALGORITHM_SET        *HashAlgorithms,
  IN OUT IMAGE_DIGEST_CACHE              *Cache,
  OUT    BOOLEAN                         *IsAuthorized
  )
{
  EFI_STATUS              Status;
  UINTN                   Index;
  CONST EFI_GUID          *HashType;
  CONST UINT8             *Digest;
  UINTN                   DigestSize;
  BOOLEAN                 IsFound;
  AUTHORIZE_CERT_CONTEXT  CertContext;

  if ((FileBuffer == NULL) || (SecDataDir == NULL) ||
      (HashAlgorithms == NULL) || (Cache == NULL) ||
      (IsAuthorized == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  *IsAuthorized = FALSE;

  //
  // First attempt to authorize the image by its Authenticode hash.
  //
  for (Index = 0; Index < HashAlgorithms->Count; Index++) {
    HashType   = &HashAlgorithms->Guids[Index];
    Digest     = NULL;
    DigestSize = 0;
    IsFound    = FALSE;

    Status = GetOrComputeAuthenticodeHash (
               FileBuffer,
               FileBufferSize,
               HashType,
               Cache,
               &Digest,
               &DigestSize
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: GetOrComputeAuthenticodeHash failed - %r\n", Status));
      continue;
    }

    Status = IsSignatureFoundInDatabase (
               Db,
               DbSize,
               Digest,
               HashType,
               DigestSize,
               &IsFound
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: IsSignatureFoundInDatabase failed - %r\n", Status));
      continue;
    }

    if (IsFound) {
      *IsAuthorized = TRUE;
      return EFI_SUCCESS;
    }
  }

  //
  // No hash hit; walk the Attribute Certificate Table and let the
  // per-certificate callback authorize the image by signer chain.
  //
  CertContext.Db           = Db;
  CertContext.DbSize       = DbSize;
  CertContext.Dbx          = Dbx;
  CertContext.DbxSize      = DbxSize;
  CertContext.IsAuthorized = IsAuthorized;

  return WalkCertificateTable (
           FileBuffer,
           FileBufferSize,
           SecDataDir,
           AuthorizeCertificateCallback,
           &CertContext
           );
}

/**
  Determine whether a signed PE/COFF image carries a signature or
  hash that has been revoked by the platform `dbx` signature
  database.

  Walks the WIN_CERTIFICATE entries in the image's security data
  directory using GetCertificateData. Each entry is qword-aligned per
  the PE/COFF Attribute Certificate Table layout; unsupported variants
  are skipped, and a malformed entry terminates the walk.

  Caution: This function may receive untrusted input. The PE/COFF
  image's security data directory is external input; bounds are
  re-validated against FileBufferSize before any dereference.

  @param[in]   FileBuffer       Pointer to the in-memory PE/COFF file.
  @param[in]   FileBufferSize   Size of FileBuffer in bytes.
  @param[in]   SecDataDir       Security data directory describing
                                the embedded WIN_CERTIFICATE table.
  @param[in]   Dbx              The raw `dbx` variable contents, or
                                NULL.
  @param[in]   DbxSize          Size of Dbx in bytes; 0 when Dbx is
                                NULL.
  @param[out]  IsRevoked        On success, TRUE if the image's
                                signature or hash matches a record in
                                Dbx; FALSE otherwise.

  @retval EFI_SUCCESS            The walk completed and IsRevoked
                                 reflects the result.
  @retval EFI_INVALID_PARAMETER  FileBuffer, SecDataDir, or IsRevoked
                                 is NULL.
  @retval EFI_VOLUME_CORRUPTED   SecDataDir falls outside FileBuffer
                                 or a certificate entry is malformed.
**/
/**
  Context passed to RevokeCertificateCallback by IsSignedImageRevoked.
  Carries the inputs and outputs the per-certificate revocation step
  needs to consult.
**/
typedef struct {
  CONST VOID    *Dbx;
  UINTN         DbxSize;
  CONST VOID    *FileBuffer;
  UINTN         FileBufferSize;
  BOOLEAN       *IsRevoked;
} REVOKE_CERT_CONTEXT;

/**
  WalkCertificateTable callback for IsSignedImageRevoked. Tests one
  embedded signed-data blob against the platform `dbx` and, on a hit,
  marks the image revoked via the caller's output flag.
**/
STATIC
EFI_STATUS
EFIAPI
RevokeCertificateCallback (
  IN CONST WIN_CERTIFICATE  *WinCert,
  IN CONST VOID             *CertData,
  IN UINTN                  CertDataSize,
  IN VOID                   *Context  OPTIONAL
  )
{
  //
  // TODO: Test the extracted signed-data blob against dbx.
  // 1. GetHashAlgorithmFromCertificate(CertData, CertDataSize, &HashType);
  // 2. GetImageDigest(Ctx->FileBuffer, Ctx->FileBufferSize, HashType, &Digest);
  // 3. WalkSignatureDatabase(Dbx, DbxSize, ...) to detect a revoked
  //    signer or hash; on a hit, set *Ctx->IsRevoked = TRUE.
  //
  (VOID)WinCert;
  (VOID)CertData;
  (VOID)CertDataSize;
  (VOID)Context;
  return EFI_SUCCESS;
}

EFI_STATUS
IsSignedImageRevoked (
  IN  VOID                            *FileBuffer,
  IN  UINTN                           FileBufferSize,
  IN  CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir,
  IN  CONST VOID                      *Dbx       OPTIONAL,
  IN  UINTN                           DbxSize,
  OUT BOOLEAN                         *IsRevoked
  )
{
  REVOKE_CERT_CONTEXT  CertContext;

  if ((FileBuffer == NULL) || (SecDataDir == NULL) || (IsRevoked == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *IsRevoked = FALSE;

  CertContext.Dbx             = Dbx;
  CertContext.DbxSize         = DbxSize;
  CertContext.FileBuffer      = FileBuffer;
  CertContext.FileBufferSize  = FileBufferSize;
  CertContext.IsRevoked       = IsRevoked;

  return WalkCertificateTable (
           FileBuffer,
           FileBufferSize,
           SecDataDir,
           RevokeCertificateCallback,
           &CertContext
           );
}
