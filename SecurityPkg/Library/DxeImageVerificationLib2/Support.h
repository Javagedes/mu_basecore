/** @file
  Utility functions for DxeImageVerificationLib.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_SUPPORT_H_
#define DXE_IMAGE_VERIFICATION_LIB_SUPPORT_H_

#include "Database.h"
#include <Library/PeCoffLib.h>

//
// A single Authenticode digest slot held in an IMAGE_DIGEST_CACHE.
// The slot's position within IMAGE_DIGEST_CACHE::Entries identifies
// the hash algorithm (matching mKnownImageHashGuids). Size == 0
// marks an empty slot; any non-zero Size identifies a previously
// computed digest of that many bytes stored in Bytes.
//
typedef struct {
  UINT8    Bytes[MAX_DIGEST_SIZE];
  UINTN    Size;
} IMAGE_DIGEST_CACHE_ENTRY;

//
// Caller-owned cache of Authenticode digests, one fixed slot per
// supported image hash algorithm in mKnownImageHashGuids order.
// Zero-initialize the structure before the first call to
// GetOrComputeAuthenticodeHash; each call returns the slot's stored
// digest on a hit or fills the slot on a miss.
//
typedef struct _IMAGE_DIGEST_CACHE {
  CONST VOID                  *FileBuffer;
  UINTN                       FileSize;
  IMAGE_DIGEST_CACHE_ENTRY    Entries[ARRAY_SIZE (mKnownImageHashGuids)];
} IMAGE_DIGEST_CACHE;

/**
  Determines if the given GUID is a supported image hash signature type.

  @param[in]  Guid  Pointer to an EFI_SIGNATURE_LIST::SignatureType
                    value, or any candidate signature-type GUID.

  @retval TRUE   The image hash signature type is supported.
  @retval FALSE  The image hash signature type is not supported.
**/
BOOLEAN
IsKnownImageHashGuid (
  IN CONST EFI_GUID  *Guid
  );

/**
  Look up the position of a known image hash signature-type GUID in
  mKnownImageHashGuids (see DxeImageVerificationLib.h).

  @param[in]   Guid   Candidate signature-type GUID.
  @param[out]  Index  On TRUE return, receives Guid's position in
                      mKnownImageHashGuids. Not modified on FALSE.

  @retval TRUE   Guid matched a known image hash algorithm and *Index
                 holds its position.
  @retval FALSE  Guid is NULL, Index is NULL, or Guid is not in
                 mKnownImageHashGuids.
**/
BOOLEAN
GetKnownImageHashGuidIndex (
  IN  CONST EFI_GUID  *Guid,
  OUT UINTN           *Index
  );

/**
  Locate the EFI_IMAGE_DIRECTORY_ENTRY_SECURITY data directory in the
  PE/COFF image contained in FileBuffer.

  Caution: This function may receive untrusted input. The PE/COFF image
  is external input and is bounds-checked by PeCoffLib before any field
  is dereferenced.

  @param[in]   FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]   FileSize    Size of FileBuffer in bytes.
  @param[out]  SecDataDir  On success, filled with a copy of the image's
                           security data directory entry. Zeroed when
                           the image declares no security directory.

  @retval EFI_SUCCESS            SecDataDir has been populated.
  @retval EFI_INVALID_PARAMETER  FileBuffer or SecDataDir is NULL.
  @retval EFI_LOAD_ERROR         FileBuffer does not contain a valid
                                 PE/COFF image, or PeCoffLib otherwise
                                 rejected the headers.
**/
EFI_STATUS
GetImageSecurityDataDirectory (
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize,
  OUT EFI_IMAGE_DATA_DIRECTORY  *SecDataDir
  );

/**
  Get or compute the Authenticode digest of a PE/COFF image for a specific hashing
  algorithm. The algorithm must be supported, which is determined by mKnownImageHashGuids.

  If the digest for a given HashType is already present in Cache, it is returned without
  recomputation. Otherwise, the digest is computed via GetAuthenticodeHash, stored in Cache, and
  then returned.

  @param[in]      HashType     Signature-type GUID identifying the
                               hash algorithm to use (for example
                               gEfiCertSha256Guid).
  @param[in,out]  Cache        Caller-owned digest cache bound to one
                               image via Cache->FileBuffer /
                               Cache->FileSize.
  @param[out]     Digest       On success, receives a pointer to the
                               cached digest bytes. The pointer is
                               valid for the lifetime of Cache.
  @param[out]     DigestSize   On success, receives the digest length
                               in bytes.

  @retval EFI_SUCCESS            Digest / DigestSize describe a valid
                                 cached digest.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_UNSUPPORTED        HashType is not one of the supported
                                 image hash algorithms enumerated by
                                 mKnownImageHashGuids.
  @retval other                  Forwarded from GetAuthenticodeHash.
**/
EFI_STATUS
GetOrComputeAuthenticodeHash (
  IN     CONST EFI_GUID      *HashType,
  IN OUT IMAGE_DIGEST_CACHE  *Cache,
  OUT    CONST UINT8         **Digest,
  OUT    UINTN               *DigestSize
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_SUPPORT_H_
