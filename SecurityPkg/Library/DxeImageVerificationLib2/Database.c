/** @file
  Secureboot DB/DBX/DBT (EFI_SIGNATURE_LIST) helpers for the DXE Image Verification Library.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Database.h"
#include "Support.h"

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
  @param[out]  BufferSize    Size of *Buffer in bytes, or 0 if the
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
  )
{
  EFI_STATUS  Status;

  if ((DatabaseName == NULL) || (Buffer == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Buffer     = NULL;
  *BufferSize = 0;

  Status = GetVariable2 (DatabaseName, &gEfiImageSecurityDatabaseGuid, Buffer, BufferSize);
  if (Status == EFI_NOT_FOUND) {
    return EFI_SUCCESS;
  }

  return Status;
}

/**
  Walk a signature-database buffer, invoking Callback for every
  well-formed EFI_SIGNATURE_LIST it contains.

  @param[in]  Buffer      The raw database contents.
  @param[in]  BufferSize  Size of Buffer in bytes.
  @param[in]  Callback    Invoked once per EFI_SIGNATURE_LIST.
  @param[in]  Context     Opaque pointer passed unmodified to Callback.

  @retval EFI_SUCCESS            Buffer was fully consumed and Callback
                                 returned EFI_SUCCESS for every list.
  @retval EFI_INVALID_PARAMETER  Buffer or Callback is NULL.
  @retval EFI_VOLUME_CORRUPTED   Buffer is structurally invalid.
  @retval Other                  First non-EFI_SUCCESS status returned
                                 by Callback. Iteration stops immediately.
**/
EFI_STATUS
WalkSignatureDatabase (
  IN  CONST VOID               *Buffer,
  IN  UINTN                    BufferSize,
  IN  SIGNATURE_LIST_CALLBACK  Callback,
  IN  VOID                     *Context  OPTIONAL
  )
{
  CONST UINT8         *Cursor;
  UINTN               Remaining;
  EFI_SIGNATURE_LIST  *List;
  UINTN               PayloadSize;
  EFI_STATUS          CallbackStatus;

  if ((Buffer == NULL) || (Callback == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor    = (CONST UINT8 *)Buffer;
  Remaining = BufferSize;

  while (Remaining >= sizeof (EFI_SIGNATURE_LIST)) {
    List = (EFI_SIGNATURE_LIST *)(VOID *)Cursor;

    //
    // Outer header bounds: the list must declare at least the header
    // size, and must fit inside what remains of the buffer.
    //
    if ((List->SignatureListSize < sizeof (EFI_SIGNATURE_LIST)) ||
        (List->SignatureListSize > Remaining))
    {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: malformed signature list size.\n"));
      return EFI_VOLUME_CORRUPTED;
    }

    //
    // Header + per-list header must fit within the declared list size,
    // and individual signatures must each be at least an EFI_GUID. The
    // remaining payload must divide evenly into SignatureSize chunks.
    //
    if ((List->SignatureSize < sizeof (EFI_GUID)) ||
        (List->SignatureHeaderSize > List->SignatureListSize - sizeof (EFI_SIGNATURE_LIST)))
    {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: malformed signature list fields.\n"));
      return EFI_VOLUME_CORRUPTED;
    }

    PayloadSize = List->SignatureListSize
                  - sizeof (EFI_SIGNATURE_LIST)
                  - List->SignatureHeaderSize;
    if ((PayloadSize % List->SignatureSize) != 0) {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: signature payload not a multiple of SignatureSize.\n"));
      return EFI_VOLUME_CORRUPTED;
    }

    CallbackStatus = Callback (List, Context);
    if (EFI_ERROR (CallbackStatus)) {
      return CallbackStatus;
    }

    Cursor    += List->SignatureListSize;
    Remaining -= List->SignatureListSize;
  }

  if (Remaining != 0) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: trailing bytes in signature database.\n"));
    return EFI_VOLUME_CORRUPTED;
  }

  return EFI_SUCCESS;
}

//
// Per-walk context for IsImageDigestFoundInDatabase. The caller
// provides Cache and clears Found; the walker callback updates Found
// if a matching entry is encountered.
//
typedef struct {
  IMAGE_DIGEST_CACHE    *Cache;
  BOOLEAN               Found;
} SIGNATURE_SEARCH_CTX;

/**
  Walker callback for IsImageDigestFoundInDatabase.

  Records a match by setting Search->Found to TRUE and returning EFI_ABORTED
  so the walk terminates early.
**/
STATIC
EFI_STATUS
EFIAPI
ImageDigestSearchCallback (
  IN CONST EFI_SIGNATURE_LIST  *List,
  IN VOID                      *Context  OPTIONAL
  )
{
  EFI_STATUS                Status;
  SIGNATURE_SEARCH_CTX      *Search;
  CONST UINT8               *Digest;
  UINTN                     DigestSize;
  UINTN                     EntryCount;
  CONST UINT8               *EntryCursor;
  CONST EFI_SIGNATURE_DATA  *Entry;
  UINTN                     Index;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Search = (SIGNATURE_SEARCH_CTX *)Context;

  if (Search->Cache == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Ignore non-image-hash lists; they are not comparable against an
  // Authenticode digest.
  //
  if (!IsKnownImageHashGuid (&List->SignatureType)) {
    return EFI_SUCCESS;
  }

  Status = GetOrComputeAuthenticodeHash (
             &List->SignatureType,
             Search->Cache,
             &Digest,
             &DigestSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (List->SignatureSize != sizeof (EFI_GUID) + DigestSize) {
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
    if (CompareMem (Entry->SignatureData, Digest, DigestSize) == 0) {
      Search->Found = TRUE;
      return EFI_ABORTED;
    }

    EntryCursor += List->SignatureSize;
  }

  return EFI_SUCCESS;
}

/**
  Search an image signature database buffer for a match against the
  image represented by Cache.

  The database is walked list-by-list. For each known image-hash
  SignatureType, the corresponding image digest is obtained from Cache
  (computing it on first use) and compared against all list entries.

  @param[in]   Database      The raw database contents.
  @param[in]   DatabaseSize  Size of Database in bytes.
  @param[in, out] Cache      IMAGE_DIGEST_CACHE pointer bound to the
                             image being searched. The cache may be
                             updated during the search.
  @param[out]  IsFound       TRUE if a matching digest was located.

  @retval EFI_SUCCESS            Search completed; IsFound is valid.
  @retval EFI_INVALID_PARAMETER  Cache or IsFound is NULL, Cache is not
                                 bound to an image.
  @retval EFI_VOLUME_CORRUPTED   Database is structurally malformed.
  @retval other                  Propagated from
                                 GetOrComputeAuthenticodeHash.
**/
EFI_STATUS
IsImageDigestFoundInDatabase (
  IN  CONST VOID             *Database,
  IN  UINTN                  DatabaseSize,
  IN OUT IMAGE_DIGEST_CACHE  *Cache,
  OUT BOOLEAN                *IsFound
  )
{
  EFI_STATUS            Status;
  SIGNATURE_SEARCH_CTX  Search;

  if ((Cache == NULL) || (IsFound == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Cache->FileBuffer == NULL) || (Cache->FileSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  *IsFound = FALSE;

  if ((DatabaseSize == 0) || (Database == NULL)) {
    return EFI_SUCCESS;
  }

  Search = (SIGNATURE_SEARCH_CTX) {
    .Cache = Cache,
    .Found = FALSE
  };

  Status = WalkSignatureDatabase (
             Database,
             DatabaseSize,
             ImageDigestSearchCallback,
             &Search
             );
  //
  // ImageDigestSearchCallback returns EFI_ABORTED to stop the walk
  // once a match is recorded in Search.Found; translate it back here.
  //
  if (Status == EFI_ABORTED) {
    Status = EFI_SUCCESS;
  }

  if (!EFI_ERROR (Status)) {
    *IsFound = Search.Found;
  }

  return Status;
}

/**
  Load the platform's db and dbx signature databases.

  The returned buffers for Db and Dbx are allocated using AllocatePool().
  The caller is responsible for freeing these buffers with FreePool().

  @param[out]  Db       Pool-allocated copy of the `db` variable
                        contents, or NULL if `db` is absent.
  @param[out]  DbSize   Size of *Db in bytes; 0 when *Db is NULL.
  @param[out]  Dbx      Pool-allocated copy of the `dbx` variable
                        contents, or NULL if `dbx` is absent.
  @param[out]  DbxSize  Size of *Dbx in bytes; 0 when *Dbx is NULL.

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
  )
{
  EFI_STATUS  Status;

  if ((Db == NULL) || (DbSize == NULL) ||
      (Dbx == NULL) || (DbxSize == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  *Db      = NULL;
  *DbSize  = 0;
  *Dbx     = NULL;
  *DbxSize = 0;

  Status = LoadSignatureDatabase (EFI_IMAGE_SECURITY_DATABASE, Db, DbSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: failed to load db - %r\n", Status));
    goto Error;
  }

  Status = LoadSignatureDatabase (EFI_IMAGE_SECURITY_DATABASE1, Dbx, DbxSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: failed to load dbx - %r\n", Status));
    goto Error;
  }

  return EFI_SUCCESS;

Error:
  if (*Db != NULL) {
    FreePool (*Db);
    *Db     = NULL;
    *DbSize = 0;
  }

  if (*Dbx != NULL) {
    FreePool (*Dbx);
    *Dbx     = NULL;
    *DbxSize = 0;
  }

  return Status;
}
