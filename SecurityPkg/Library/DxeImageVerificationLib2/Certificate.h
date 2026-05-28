/** @file
  Signed image (certificate / Authenticode) validation helpers for the
  DXE Image Verification Library.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_CERTIFICATE_H_
#define DXE_IMAGE_VERIFICATION_LIB_CERTIFICATE_H_

#include "DxeImageVerificationLib.h"
#include "Support.h"
#include "Database.h"
#include "Iterator.h"

#include <Guid/WinCertificate.h>

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
  );

/**
  Determine whether a signed PE/COFF image is revoked by the platform's `dbx` signature database.

  @param[in]      SecDataDir  Security data directory describing the embedded WIN_CERTIFICATE table.
  @param[in]      Dbx         The `dbx` signature database.
  @param[in]      DbxSize     The size of the `dbx`.
  @param[in,out]  Cache       DIGEST_CACHE pointer bound to the image being searched. The cache may
                              be updated during the search.
  @param[in,out]  Action      Updated to reflect the outcome of the revocation check.

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
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_CERTIFICATE_H_
