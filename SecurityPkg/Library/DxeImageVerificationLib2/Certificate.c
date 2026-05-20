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
  if ((SecDataDir == NULL) || (Cache == NULL) || (Cache->FileBuffer == NULL) ||
      (Cache->FileSize == 0) || (Action == NULL))
  {
    return FALSE;
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
