/** @file
  Secureboot DB/DBX/DBT (EFI_SIGNATURE_LIST) helpers for the DXE Image Verification Library.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Database.h"

/**
  Search an image signature database buffer for a match against the image represented by Cache.

  The database is walked list-by-list. For each known image-hash SignatureType, the corresponding
  image digest is obtained from Cache (computing it on first use) and compared against all list
  entries.

  @param[in]   Database      The raw database contents.
  @param[in]   DatabaseSize  The size of the Database in bytes.
  @param[in, out] Cache      DIGEST_CACHE pointer bound to the image being searched. The cache may
                             be updated during the search.
  @param[out]  IsFound       TRUE if a matching digest was located.

  @retval EFI_SUCCESS            Search completed; IsFound is valid.
  @retval EFI_INVALID_PARAMETER  Cache or IsFound is NULL, Cache is not bound to an image.
  @retval EFI_VOLUME_CORRUPTED   Database is structurally malformed.
  @retval other                  Propagated from GetHash.
**/
EFI_STATUS
IsImageDigestInDatabase (
  IN  CONST VOID       *Database,
  IN  UINTN            DatabaseSize,
  IN OUT DIGEST_CACHE  *Cache,
  OUT BOOLEAN          *IsFound
  )
{
  EFI_STATUS                Status;
  SIG_DATABASE_ITER         DbIter;
  SIG_LIST_ITER             ListIter;
  CONST EFI_SIGNATURE_LIST  *List;
  CONST EFI_SIGNATURE_DATA  *Entry;
  CONST UINT8               *Digest;
  UINTN                     DigestSize;

  if ((Cache == NULL) || (IsFound == NULL) ||
      (Cache->Buffer == NULL) || (Cache->BufferSize == 0) ||
      (Cache->Type != DigestCacheTypeImage))
  {
    return EFI_INVALID_PARAMETER;
  }

  *IsFound = FALSE;

  if ((DatabaseSize == 0) || (Database == NULL)) {
    return EFI_SUCCESS;
  }

  Status = DatabaseIterInit (&DbIter, Database, DatabaseSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Iterate over each EFI_SIGNATURE_LIST in the database.
  //
  while ((List = DatabaseIterNext (&DbIter)) != NULL) {
    Status = GetHash (
               &List->SignatureType,
               Cache,
               &Digest,
               &DigestSize
               );

    //
    // Unsupported hash type; skip this list.
    //
    if (Status == EFI_UNSUPPORTED) {
      continue;
    }

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: failed to get image hash - %r\n", Status));
      return Status;
    }

    if (EFI_ERROR (SigListIterInit (&ListIter, List))) {
      continue;
    }

    //
    // Iterate over each Entry in the current EFI_SIGNATURE_LIST.
    //
    while ((Entry = SigListIterNext (&ListIter)) != NULL) {
      if (CompareMem (Entry->SignatureData, Digest, DigestSize) == 0) {
        *IsFound = TRUE;
        return EFI_SUCCESS;
      }
    }
  }

  return EFI_SUCCESS;
}

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
  Load the platform's db and dbx signature databases.

  The returned buffers for Db and Dbx are allocated using AllocatePool(). The caller is responsible
  for freeing these buffers with FreePool().

  @param[out]  Db       Pool-allocated copy of the `db` variable contents, or NULL if `db` is
                        absent.
  @param[out]  DbSize   BufferSize of *Db in bytes; 0 when *Db is NULL.
  @param[out]  Dbx      Pool-allocated copy of the `dbx` variable  contents, or NULL if `dbx` is
                        absent.
  @param[out]  DbxSize  BufferSize of *Dbx in bytes; 0 when *Dbx is NULL.

  @retval EFI_SUCCESS            Databases loaded. *Db / *Dbx may still be NULL if the
                                 corresponding variable was absent.
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

/**
  Determine whether a TBS Certificate hash is present in the `dbx`.

  Iterates over the EFI_SIGNATURE_LISTs in the `dbx` database and checks if any of them contain
  the hash of the TBS Certificate. Any failure to iterate will assume the certificate is in the DBX.

  @param[in]  Cert      DER-encoded X.509 certificate.
  @param[in]  CertSize  BufferSize of Cert in bytes.
  @param[in]  Dbx       Raw dbx contents, or NULL.
  @param[in]  DbxSize   BufferSize of Dbx in bytes; 0 when Dbx is NULL.

  @retval TRUE   The certificate hash was located in dbx, or an error
                 prevented a definitive answer.
  @retval FALSE  The certificate hash is not present in dbx.
**/
BOOLEAN
IsTBSCertHashInDbx (
  IN  CONST UINT8  *TBSCert,
  IN  UINTN        TBSCertSize,
  IN  CONST VOID   *Dbx,
  IN  UINTN        DbxSize
  )
{
  EFI_STATUS                Status;
  UINTN                     DigestSize;
  DIGEST_CACHE              HashCache;
  SIG_DATABASE_ITER         Iter;
  SIG_LIST_ITER             ListIter;
  CONST EFI_SIGNATURE_LIST  *List;
  CONST EFI_SIGNATURE_DATA  *Entry;
  CONST UINT8               *CertDigest;

  //
  // There is no DBX, so it's definitely not in the DBX.
  //
  if ((Dbx == NULL) || (DbxSize == 0)) {
    return FALSE;
  }

  if (EFI_ERROR (DatabaseIterInit (&Iter, Dbx, DbxSize))) {
    DEBUG ((DEBUG_WARN, "DxeImageVerificationLib: dbx is malformed; treating cert as revoked.\n"));
    return TRUE;
  }

  ZeroMem (&HashCache, sizeof (HashCache));
  HashCache.Type       = DigestCacheTypeX509;
  HashCache.Buffer     = TBSCert;
  HashCache.BufferSize = TBSCertSize;

  while ((List = DatabaseIterNext (&Iter)) != NULL) {
    Status = GetHash (&List->SignatureType, &HashCache, &CertDigest, &DigestSize);

    //
    // This EFI_SIGNATURE_LIST in the DBX is not applicable to X509 certicicates.
    //
    if (Status == EFI_UNSUPPORTED) {
      continue;
    }

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "DxeImageVerificationLib: X509 hash computation failed; treating cert as revoked (%r).\n", Status));
      return TRUE;
    }

    if (List->SignatureSize < sizeof (EFI_GUID) + DigestSize) {
      DEBUG ((DEBUG_WARN, "DxeImageVerificationLib: dbx signature size is malformed; treating cert as revoked.\n"));
      return TRUE;
    }

    if (EFI_ERROR (SigListIterInit (&ListIter, List))) {
      DEBUG ((DEBUG_WARN, "DxeImageVerificationLib: failed to iterate dbx signature list; treating cert as revoked.\n"));
      return TRUE;
    }

    while ((Entry = SigListIterNext (&ListIter)) != NULL) {
      if (CompareMem (Entry->SignatureData, CertDigest, DigestSize) == 0) {
        return TRUE;
      }
    }
  }

  return FALSE;
}
