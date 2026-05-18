/** @file
  Certificate parsing and signature-database validation helpers for
  the DXE Image Verification Library.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_CERTIFICATE_H_
#define DXE_IMAGE_VERIFICATION_LIB_CERTIFICATE_H_

#include "DxeImageVerificationLib.h"
#include "Support.h"

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
  );

/**
  A callback that is executed by WalkCertificateTable once per
  well-formed, supported WIN_CERTIFICATE entry in the Attribute
  Certificate Table.

  Returning EFI_SUCCESS continues iteration. Returning any other status
  stops the walk and the error is propagated to the caller.

  @param[in]  WinCert       The certificate entry currently being
                            iterated.
  @param[in]  CertData      Embedded signed-data blob extracted from
                            WinCert (e.g. a PKCS#7 SignedData).
  @param[in]  CertDataSize  Size of CertData in bytes.
  @param[in]  Context       Caller-owned opaque pointer passed
                            unmodified through WalkCertificateTable.

  @retval EFI_SUCCESS            The entry was processed successfully.
  @retval other                  Callback-specific error.
**/
typedef
EFI_STATUS
(EFIAPI *CERTIFICATE_CALLBACK)(
  IN CONST WIN_CERTIFICATE  *WinCert,
  IN CONST VOID             *CertData,
  IN UINTN                  CertDataSize,
  IN VOID                   *Context  OPTIONAL
  );

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
  );

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
  );

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
EFI_STATUS
IsSignedImageRevoked (
  IN  VOID                            *FileBuffer,
  IN  UINTN                           FileBufferSize,
  IN  CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir,
  IN  CONST VOID                      *Dbx       OPTIONAL,
  IN  UINTN                           DbxSize,
  OUT BOOLEAN                         *IsRevoked
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_CERTIFICATE_H_
