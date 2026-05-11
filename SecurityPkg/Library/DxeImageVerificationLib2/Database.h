/** @file
  Image-signature-database helpers for the DXE Image Verification Library.

  Declares helpers that inspect the `db`, `dbx`, or `dbt` UEFI
  authenticated variables (per UEFI 2.x, Secure Boot) and report which
  hash algorithm signature types are present. Callers use the result to
  decide which image hashes to compute when validating an unsigned
  image.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_
#define DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_

#include <Uefi.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>

//
// Plain image-hash signature-type GUIDs we recognize. Defined in the
// header so the struct below can size itself with ARRAY_SIZE() and
// callers / tests stay in sync automatically when an entry is added.
// X509-with-hash variants are intentionally excluded because they
// identify certificate hashes, not raw image digests.
//
STATIC CONST EFI_GUID  *CONST  mKnownImageHashGuids[] = {
  &gEfiCertSha1Guid,
  &gEfiCertSha256Guid,
  &gEfiCertSha384Guid,
  &gEfiCertSha512Guid
};

/**
  An ordered, deduplicated set of image hash signature-type GUIDs that
  were observed in a signature database variable.

  Use Count as the iteration bound; Guids[0..Count-1] are valid.
**/
typedef struct {
  UINTN       Count;
  EFI_GUID    Guids[ARRAY_SIZE (mKnownImageHashGuids)];
} HASH_ALGORITHM_SET;

/**
  Determine whether a signature-list type GUID identifies a plain image
  hash algorithm (SHA1/256/384/512).

  @param[in]  Guid  Pointer to an EFI_SIGNATURE_LIST::SignatureType
                    value, or any candidate signature-type GUID.

  @retval TRUE   Guid is a recognized plain image hash GUID.
  @retval FALSE  Otherwise (NULL, an X509 cert type, or anything else).
**/
BOOLEAN
IsKnownImageHashGuid (
  IN CONST EFI_GUID  *Guid
  );

/**
  Per-EFI_SIGNATURE_LIST callback consumed by WalkSignatureDatabase.

  Invoked once per signature list contained in the database buffer.
  The walker has already validated that List points inside the buffer
  and that List's internal size fields (SignatureListSize,
  SignatureHeaderSize, SignatureSize) are self-consistent, so the
  callback may safely walk the entries via:

    Header = (UINT8 *)List + sizeof (EFI_SIGNATURE_LIST);
    First  = (EFI_SIGNATURE_DATA *)(Header + List->SignatureHeaderSize);
    Count  = (List->SignatureListSize
              - sizeof (EFI_SIGNATURE_LIST)
              - List->SignatureHeaderSize) / List->SignatureSize;

  Returning EFI_SUCCESS continues iteration. Returning any other status
  stops the walk and is propagated to the caller of
  WalkSignatureDatabase unchanged.

  @param[in]  List     The signature list currently being iterated.
  @param[in]  Context  Caller-owned opaque pointer passed unmodified
                       through WalkSignatureDatabase.
**/
typedef
EFI_STATUS
(EFIAPI *SIGNATURE_LIST_CALLBACK)(
  IN CONST EFI_SIGNATURE_LIST  *List,
  IN VOID                      *Context  OPTIONAL
  );

/**
  Walk a signature-database buffer, invoking Callback for every
  well-formed EFI_SIGNATURE_LIST it contains.

  @param[in]  Buffer      Pointer to the raw database contents (e.g. as
                          returned by GetVariable2).
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
  );

/**
  Report the union of image hash algorithms currently in use across the
  authorized (`db`) and forbidden (`dbx`) image signature databases.

  Reads EFI_IMAGE_SECURITY_DATABASE (L"db") and
  EFI_IMAGE_SECURITY_DATABASE1 (L"dbx") under
  gEfiImageSecurityDatabaseGuid, walks every EFI_SIGNATURE_LIST in each,
  and for each list whose SignatureType is a recognized plain hash GUID
  (IsKnownImageHashGuid returns TRUE) records that GUID in
  HashAlgorithms exactly once. A missing variable contributes nothing.

  Caution: This function consumes external input. Each variable buffer
  is bounds-checked at every step before being dereferenced.

  @param[out]  HashAlgorithms  On success, populated with the
                               deduplicated set of hash signature types
                               observed across `db` and `dbx`. Always
                               zero-initialized first, so two absent
                               variables yield Count == 0.

  @retval EFI_SUCCESS            HashAlgorithms is populated. Count may
                                 be 0 if both variables are missing,
                                 empty, or only contain non-hash
                                 signature types.
  @retval EFI_INVALID_PARAMETER  HashAlgorithms is NULL.
  @retval EFI_OUT_OF_RESOURCES   Could not allocate a buffer for one of
                                 the variables.
  @retval EFI_VOLUME_CORRUPTED   One of the variables' signature lists
                                 is malformed (see WalkSignatureDatabase).
  @retval Other                  Status from gRT->GetVariable other than
                                 EFI_NOT_FOUND / EFI_BUFFER_TOO_SMALL.
**/
EFI_STATUS
GetDatabaseHashAlgorithms (
  OUT HASH_ALGORITHM_SET  *HashAlgorithms
  );

/**
  Search a single image-signature-database UEFI variable for an exact
  signature match.

  Walks the variable named DatabaseName under gEfiImageSecurityDatabaseGuid
  with WalkSignatureDatabase and reports whether any EFI_SIGNATURE_LIST
  whose SignatureType equals SignatureType contains an EFI_SIGNATURE_DATA
  whose SignatureData payload equals the SignatureSize bytes at
  Signature. The walker validates list structure before the callback is
  invoked, and lists whose per-entry size does not match
  (sizeof (EFI_GUID) + SignatureSize) are skipped (they describe a
  different algorithm).

  An absent variable counts as "not found" and returns EFI_SUCCESS with
  *IsFound == FALSE.

  @param[in]   DatabaseName   Variable name (e.g. EFI_IMAGE_SECURITY_DATABASE).
  @param[in]   Signature      Pointer to the raw signature payload to
                              search for (digest bytes for hash types,
                              certificate bytes for x509 types).
  @param[in]   SignatureType  GUID identifying the signature algorithm
                              (e.g. gEfiCertSha256Guid). Lists with a
                              different type are ignored.
  @param[in]   SignatureSize  Size of Signature in bytes. Must be
                              non-zero.
  @param[out]  IsFound        TRUE if the signature was located.
                              Only valid when EFI_SUCCESS is returned.

  @retval EFI_SUCCESS            Search completed; *IsFound is valid.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL or
                                 SignatureSize is 0.
  @retval EFI_VOLUME_CORRUPTED   Variable is structurally malformed.
  @retval Other                  Status from GetVariable2.
**/
EFI_STATUS
IsSignatureFoundInDatabase (
  IN  CONST CHAR16    *DatabaseName,
  IN  CONST UINT8     *Signature,
  IN  CONST EFI_GUID  *SignatureType,
  IN  UINTN           SignatureSize,
  OUT BOOLEAN         *IsFound
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_
