/** @file
  Secureboot DB/DBX/DBT (EFI_SIGNATURE_LIST) helpers for the DXE Image Verification Library.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_
#define DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_

#include "DxeImageVerificationLib.h"
#include <Library/UefiLib.h>

typedef struct _DIGEST_CACHE DIGEST_CACHE;

/**
  Load a Secure Boot Signature Database into a pool-allocated buffer.

  The returned buffer is allocated using AllocatePool(). The caller is responsible for freeing
  this buffer with FreePool().

  @param[in]   DatabaseName  Variable name (e.g. EFI_IMAGE_SECURITY_DATABASE,
                             EFI_IMAGE_SECURITY_DATABASE1).
  @param[out]  Buffer        Pool-allocated copy of the variable contents,
                             or NULL if the variable does not exist.
                             Caller is responsible for freeing this buffer with
                             FreePool when non-NULL.
  @param[out]  BufferSize    BufferSize of *Buffer in bytes, or 0 if the
                             variable does not exist.

  @retval EFI_SUCCESS            The variable was loaded successfully, or it was absent.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval Other                  Status from gRT->GetVariable.
**/
EFI_STATUS
LoadSignatureDatabase (
  IN  CONST CHAR16  *DatabaseName,
  OUT VOID          **Buffer,
  OUT UINTN         *BufferSize
  );

/**
  Search an image signature database buffer for a match against the
  image represented by Cache.

  The database is walked list-by-list. For each known image-hash
  SignatureType, the corresponding image digest is obtained from Cache
  (computing it on first use) and compared against all list entries.

  @param[in]   Database      The raw database contents.
  @param[in]   DatabaseSize  BufferSize of Database in bytes.
  @param[in, out] Cache      DIGEST_CACHE pointer bound to the
                             image being searched. The cache may be
                             updated during the search.
  @param[out]  IsFound       TRUE if a matching digest was located.

  @retval EFI_SUCCESS            Search completed; IsFound is valid.
  @retval EFI_INVALID_PARAMETER  Cache or IsFound is NULL, Cache is not
                                 bound to an image.
  @retval EFI_VOLUME_CORRUPTED   Database is structurally malformed.
  @retval other                  Propagated from
                                 GetHash.
**/
EFI_STATUS
IsImageDigestInDatabase (
  IN     CONST VOID    *Database,
  IN     UINTN         DatabaseSize,
  IN OUT DIGEST_CACHE  *Cache,
  OUT    BOOLEAN       *IsFound
  );

/**
  Load the platform's db and dbx signature databases.

  The returned buffers for Db and Dbx are allocated using AllocatePool(). The caller is responsible for
  freeing these buffers with FreePool().

  @param[out]  Db              Pool-allocated copy of the `db` variable
                               contents, or NULL if `db` is absent.
  @param[out]  DbSize          BufferSize of *Db in bytes; 0 when *Db is NULL.
  @param[out]  Dbx             Pool-allocated copy of the `dbx` variable
                               contents, or NULL if `dbx` is absent.
  @param[out]  DbxSize         BufferSize of *Dbx in bytes; 0 when *Dbx is NULL.
  @retval EFI_SUCCESS            Databases loaded. *Db / *Dbx may still
                                 be NULL if the corresponding variable
                                 was absent.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval Other                  Failure status from gRT->GetVariable.
**/
EFI_STATUS
LoadSignatureDatabases (
  OUT VOID   **Db,
  OUT UINTN  *DbSize,
  OUT VOID   **Dbx,
  OUT UINTN  *DbxSize
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_
