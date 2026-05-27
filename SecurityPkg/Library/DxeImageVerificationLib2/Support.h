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
// A single cached digest slot held in a DIGEST_CACHE.
// The slot's position within DIGEST_CACHE::Entries identifies
// the hash algorithm (matching mHashAlgorithms). BufferSize == 0
// marks an empty slot; any non-zero BufferSize identifies a previously
// computed digest of that many bytes stored in Bytes.
//
typedef struct {
  UINT8    Bytes[MAX_DIGEST_SIZE];
  UINTN    BufferSize;
} DIGEST_CACHE_ENTRY;

typedef enum {
  DigestCacheTypeImage,
  DigestCacheTypeX509
} DIGEST_CACHE_TYPE;

//
// Caller-owned digest cache, one fixed slot per supported hash
// algorithm in mHashAlgorithms order.
// Zero-initialize the structure before the first call to
// GetHash; each
// call returns the slot's stored digest on a hit or fills the
// slot on a miss.
//
typedef struct _DIGEST_CACHE {
  DIGEST_CACHE_TYPE     Type;
  CONST VOID            *Buffer;
  UINTN                 BufferSize;
  DIGEST_CACHE_ENTRY    Entries[ARRAY_SIZE (mHashAlgorithms)];
} DIGEST_CACHE;

/**
  Locate the EFI_IMAGE_DIRECTORY_ENTRY_SECURITY data directory in the
  PE/COFF image contained in FileBuffer.

  Caution: This function may receive untrusted input. The PE/COFF image
  is external input and is bounds-checked by PeCoffLib before any field
  is dereferenced.

  @param[in]   FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]   FileSize    BufferSize of FileBuffer in bytes.
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
  Get or compute a cached digest for HashType.

  Cache->Type selects the miss path:
  - DigestCacheTypeImage: compute using GetAuthenticodeHash().
  - DigestCacheTypeX509: compute using the selected algorithm's
    HashAll function.

  HashType must map to mHashAlgorithms and be compatible with
  Cache->Type. For DigestCacheTypeImage, HashType must be one of the
  image-hash GUIDs. For DigestCacheTypeX509, HashType must be one of
  the X.509 cert-hash GUIDs.

  @param[in]      HashType     Signature-type GUID identifying the
                               hash algorithm to use.
  @param[in,out]  Cache        Caller-owned digest cache bound to one
                               buffer via Cache->Buffer /
                               Cache->BufferSize.
  @param[out]     Digest       On success, receives a pointer to the
                               cached digest bytes. The pointer is
                               valid for the lifetime of Cache.
  @param[out]     DigestSize   On success, receives the digest length
                               in bytes.

  @retval EFI_SUCCESS            Digest / DigestSize describe a valid
                                 cached digest.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_UNSUPPORTED        HashType does not map to an entry in
                                 mHashAlgorithms compatible with
                                 Cache->Type.
  @retval EFI_COMPROMISED_DATA   Cache already holds a digest for this
                                 slot but the stored size is invalid.
  @retval EFI_SECURITY_VIOLATION The HashAll operation failed.
  @retval other                  Forwarded from GetAuthenticodeHash.
**/
EFI_STATUS
GetHash (
  IN     CONST EFI_GUID  *HashType,
  IN OUT DIGEST_CACHE    *Cache,
  OUT    CONST UINT8     **Digest,
  OUT    UINTN           *DigestSize
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_SUPPORT_H_
