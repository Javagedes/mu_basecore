/** @file
  Image-signature-database helpers for the DXE Image Verification Library.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Database.h"

/**
  Append a GUID to the set if it is not already present.

  @param[in,out]  Set   The set to update.
  @param[in]      Guid  The GUID to insert.
**/
STATIC
VOID
AppendUnique (
  IN OUT HASH_ALGORITHM_SET  *Set,
  IN CONST EFI_GUID          *Guid
  )
{
  UINTN  Index;

  for (Index = 0; Index < Set->Count; Index++) {
    if (CompareGuid (&Set->Guids[Index], Guid)) {
      return;
    }
  }

  ASSERT (Set->Count < ARRAY_SIZE (Set->Guids));
  if (Set->Count < ARRAY_SIZE (Set->Guids)) {
    CopyGuid (&Set->Guids[Set->Count], Guid);
    Set->Count++;
  }
}

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
  )
{
  UINTN  Index;

  if (Guid == NULL) {
    return FALSE;
  }

  for (Index = 0; Index < ARRAY_SIZE (mKnownImageHashGuids); Index++) {
    if (CompareGuid (Guid, mKnownImageHashGuids[Index])) {
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Walk a signature-database buffer, invoking Callback for every
  well-formed EFI_SIGNATURE_LIST it contains.

  @param[in]  Buffer      Pointer to the raw database contents (e.g. as
                          returned by GetVariable2).
  @param[in]  BufferSize  Size of Buffer in bytes.
  @param[in]  Callback    Invoked once per EFI_SIGNATURE_LIST.
  @param[in]  Context     Opaque pointer passed unmodified to Callback.

  @retval EFI_SUCCESS            Buffer was fully consumed and Callback
                                 returned RETURN_SUCCESS for every list.
  @retval EFI_INVALID_PARAMETER  Buffer or Callback is NULL.
  @retval EFI_VOLUME_CORRUPTED   Buffer is structurally invalid.
  @retval Other                  First non-RETURN_SUCCESS status returned
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
  RETURN_STATUS       CallbackStatus;

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
    if (CallbackStatus != RETURN_SUCCESS) {
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

/**
  Walker callback for GetDatabaseHashAlgorithms: appends the list's
  SignatureType to the caller's set if it is a recognized image hash
  GUID. Always returns RETURN_SUCCESS to keep iterating.
**/
STATIC
RETURN_STATUS
EFIAPI
CollectHashAlgorithmCallback (
  IN CONST EFI_SIGNATURE_LIST  *List,
  IN VOID                      *Context  OPTIONAL
  )
{
  HASH_ALGORITHM_SET  *Set;

  Set = (HASH_ALGORITHM_SET *)Context;

  if (IsKnownImageHashGuid (&List->SignatureType)) {
    AppendUnique (Set, &List->SignatureType);
  }

  return RETURN_SUCCESS;
}

/**
  Read a single image-signature-database UEFI variable and add every
  recognized image-hash signature-type GUID it contains to
  HashAlgorithms (deduplicated).

  HashAlgorithms is updated in place and is left in a partially-merged
  state if WalkSignatureDatabase reports EFI_VOLUME_CORRUPTED.

  @param[in]      DatabaseName    Variable name (e.g. EFI_IMAGE_SECURITY_DATABASE,
                                  EFI_IMAGE_SECURITY_DATABASE1).
  @param[in]      VendorGuid      Vendor GUID for DatabaseName, typically
                                  gEfiImageSecurityDatabaseGuid.
  @param[in,out]  HashAlgorithms  Caller-owned set to merge into. Must
                                  already be initialized (e.g. by
                                  ZeroMem) by the caller.

  @retval EFI_SUCCESS            Variable read (or absent) and merged.
  @retval EFI_VOLUME_CORRUPTED   Variable is structurally malformed; see
                                 WalkSignatureDatabase.
  @retval Other                  Status from GetVariable2 other than
                                 EFI_NOT_FOUND.
**/
STATIC
EFI_STATUS
AddHashAlgorithms (
  IN     CONST CHAR16        *DatabaseName,
  IN     CONST EFI_GUID      *VendorGuid,
  IN OUT HASH_ALGORITHM_SET  *HashAlgorithms
  )
{
  EFI_STATUS  Status;
  VOID        *Buffer;
  UINTN       BufferSize;

  Buffer     = NULL;
  BufferSize = 0;
  Status     = GetVariable2 (DatabaseName, VendorGuid, &Buffer, &BufferSize);
  if (Status == EFI_NOT_FOUND) {
    Status = EFI_SUCCESS;
    goto Done;
  }

  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Status = WalkSignatureDatabase (
             Buffer,
             BufferSize,
             CollectHashAlgorithmCallback,
             HashAlgorithms
             );

Done:
  if (Buffer != NULL) {
    FreePool (Buffer);
  }

  return Status;
}

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
  )
{
  EFI_STATUS  Status;

  if (HashAlgorithms == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (HashAlgorithms, sizeof (*HashAlgorithms));

  Status = AddHashAlgorithms (
             EFI_IMAGE_SECURITY_DATABASE,
             &gEfiImageSecurityDatabaseGuid,
             HashAlgorithms
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return AddHashAlgorithms (
           EFI_IMAGE_SECURITY_DATABASE1,
           &gEfiImageSecurityDatabaseGuid,
           HashAlgorithms
           );
}
