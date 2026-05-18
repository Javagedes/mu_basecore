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
  UINT8    Bytes[SHA512_DIGEST_SIZE];
  UINTN    Size;
} IMAGE_DIGEST_CACHE_ENTRY;

//
// Caller-owned cache of Authenticode digests, one fixed slot per
// supported image hash algorithm in mKnownImageHashGuids order.
// Zero-initialize the structure before the first call to
// GetOrComputeAuthenticodeHash; each call returns the slot's stored
// digest on a hit or fills the slot on a miss.
//
typedef struct {
  IMAGE_DIGEST_CACHE_ENTRY    Entries[ARRAY_SIZE (mKnownImageHashGuids)];
} IMAGE_DIGEST_CACHE;

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
  Look up the Authenticode digest of a PE/COFF image for a specific
  hash algorithm in the supplied cache, computing it via
  GetAuthenticodeHash on a miss.

  The cache is caller-owned; zero-initialize it before the first call.
  On a hit, Digest / DigestSize describe the stored digest without
  recomputation. On a miss, the digest is computed, stored in a free
  cache slot, and then returned.

  @param[in]      FileBuffer   Pointer to the in-memory PE/COFF image.
  @param[in]      FileSize     Size of FileBuffer in bytes.
  @param[in]      HashType     Signature-type GUID identifying the
                               hash algorithm to use (for example
                               gEfiCertSha256Guid).
  @param[in,out]  Cache        Caller-owned digest cache.
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
  IN     VOID                *FileBuffer,
  IN     UINTN               FileSize,
  IN     CONST EFI_GUID      *HashType,
  IN OUT IMAGE_DIGEST_CACHE  *Cache,
  OUT    CONST UINT8         **Digest,
  OUT    UINTN               *DigestSize
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_SUPPORT_H_
