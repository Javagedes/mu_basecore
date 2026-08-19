/** @file
  Dynamic digest cache for DxeImageVerificationLib.

  Memoizes the digest of a bound buffer under each requested hash-algorithm GUID, allocating one
  entry per algorithm on demand (no fixed-size table). The actual hashing is delegated to HashAll (),
  a local dispatcher over the supported EFI_HASH_ALGORITHM_*_GUIDs that is intended to be replaced by
  an equivalent BaseCryptLib primitive.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Support.h"

//
// One memoized digest: the algorithm GUID it was computed under and the digest bytes. Nodes are
// singly linked so the cache grows one entry per distinct algorithm requested for its buffer.
//
struct DIGEST_CACHE_ENTRY {
  DIGEST_CACHE_ENTRY    *Next;
  CONST EFI_GUID        *Algorithm;
  UINT8                 Digest[MAX_DIGEST_SIZE];
  UINTN                 DigestSize;
};

/**
  Hash a buffer with the algorithm identified by a Protocol/Hash.h algorithm GUID.

  Local one-shot dispatcher over the supported EFI_HASH_ALGORITHM_*_GUIDs, intended to be replaced by
  an equivalent BaseCryptLib primitive.

  @param[in]   HashAlgorithm  An EFI_HASH_ALGORITHM_*_GUID.
  @param[in]   Data           Buffer to hash.
  @param[in]   DataSize       Size of Data in bytes.
  @param[out]  Digest         Caller buffer of at least MAX_DIGEST_SIZE bytes receiving the digest.
  @param[out]  DigestSize     On EFI_SUCCESS, the digest length in bytes.

  @retval EFI_SUCCESS            Digest / DigestSize describe the computed digest.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_UNSUPPORTED        HashAlgorithm is not a recognized algorithm.
  @retval EFI_SECURITY_VIOLATION The hash operation failed.
**/
STATIC
EFI_STATUS
HashAll (
  IN  CONST EFI_GUID  *HashAlgorithm,
  IN  CONST VOID      *Data,
  IN  UINTN           DataSize,
  OUT UINT8           *Digest,
  OUT UINTN           *DigestSize
  )
{
  BOOLEAN  Ok;
  UINTN    Size;

  if ((HashAlgorithm == NULL) || (Data == NULL) || (Digest == NULL) || (DigestSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (CompareGuid (HashAlgorithm, &gEfiHashAlgorithmSha256Guid)) {
    Ok   = Sha256HashAll (Data, DataSize, Digest);
    Size = SHA256_DIGEST_SIZE;
  } else if (CompareGuid (HashAlgorithm, &gEfiHashAlgorithmSha384Guid)) {
    Ok   = Sha384HashAll (Data, DataSize, Digest);
    Size = SHA384_DIGEST_SIZE;
  } else if (CompareGuid (HashAlgorithm, &gEfiHashAlgorithmSha512Guid)) {
    Ok   = Sha512HashAll (Data, DataSize, Digest);
    Size = SHA512_DIGEST_SIZE;
  } else {
    return EFI_UNSUPPORTED;
  }

  if (!Ok) {
    return EFI_SECURITY_VIOLATION;
  }

  *DigestSize = Size;
  return EFI_SUCCESS;
}

/**
  Get or compute the cached digest of the cache's buffer under a hash algorithm.

  On a cache hit the memoized digest is returned; on a miss the buffer is hashed with HashAll () and
  the result is memoized in a newly allocated entry (keyed by HashAlgorithm) before being returned.
  The digest bytes remain valid until FreeDigestCache ().

  @param[in]      HashAlgorithm  Protocol/Hash.h algorithm GUID (EFI_HASH_ALGORITHM_*_GUID).
  @param[in,out]  Cache          Caller-owned cache bound to a buffer via Cache->Buffer /
                                 Cache->BufferSize.
  @param[out]     Digest         On success, a pointer to the cached digest bytes, valid until
                                 FreeDigestCache ().
  @param[out]     DigestSize     On success, the digest length in bytes.

  @retval EFI_SUCCESS            Digest / DigestSize describe a valid cached digest.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_UNSUPPORTED        HashAlgorithm is not a supported algorithm.
  @retval EFI_OUT_OF_RESOURCES   A cache entry could not be allocated.
  @retval EFI_SECURITY_VIOLATION The hash operation failed.
**/
EFI_STATUS
GetHash (
  IN     CONST EFI_GUID  *HashAlgorithm,
  IN OUT DIGEST_CACHE    *Cache,
  OUT    CONST UINT8     **Digest,
  OUT    UINTN           *DigestSize
  )
{
  EFI_STATUS          Status;
  DIGEST_CACHE_ENTRY  *Entry;

  if ((HashAlgorithm == NULL) || (Cache == NULL) || (Cache->Buffer == NULL) ||
      (Digest == NULL) || (DigestSize == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Return a memoized digest if this algorithm has already been computed for the bound buffer.
  //
  for (Entry = Cache->Entries; Entry != NULL; Entry = Entry->Next) {
    if (CompareGuid (Entry->Algorithm, HashAlgorithm)) {
      *Digest     = Entry->Digest;
      *DigestSize = Entry->DigestSize;
      return EFI_SUCCESS;
    }
  }

  //
  // Miss: hash the buffer into a fresh entry. The entry is linked only on success, so a failed hash
  // leaves the cache unchanged.
  //
  Entry = AllocatePool (sizeof (*Entry));
  if (Entry == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = HashAll (HashAlgorithm, Cache->Buffer, Cache->BufferSize, Entry->Digest, &Entry->DigestSize);
  if (EFI_ERROR (Status)) {
    FreePool (Entry);
    return Status;
  }

  Entry->Algorithm = HashAlgorithm;
  Entry->Next      = Cache->Entries;
  Cache->Entries   = Entry;

  *Digest     = Entry->Digest;
  *DigestSize = Entry->DigestSize;
  return EFI_SUCCESS;
}

/**
  Release the memoized digest entries owned by a DIGEST_CACHE.

  Frees every entry GetHash () allocated and resets the cache to empty. Buffer / BufferSize are left
  intact (the buffer is caller-owned). Safe to call on a zero-initialized or already-freed cache.

  @param[in,out]  Cache  Cache whose memoized entries are released, or NULL.
**/
VOID
FreeDigestCache (
  IN OUT DIGEST_CACHE  *Cache
  )
{
  DIGEST_CACHE_ENTRY  *Entry;
  DIGEST_CACHE_ENTRY  *Next;

  if (Cache == NULL) {
    return;
  }

  for (Entry = Cache->Entries; Entry != NULL; Entry = Next) {
    Next = Entry->Next;
    FreePool (Entry);
  }

  Cache->Entries = NULL;
}
