/** @file
  Top-level implementation of the DXE Image Verification Library.

  This library is a NULL library: it has no public class interface.
  Linking it into a DXE driver runs DxeImageVerificationLibConstructor,
  which registers a Security2 verification handler
  (DxeImageVerificationHandler). Everything else lives in supporting
  source files (Policy.c, ...).

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "DxeImageVerificationLib.h"
#include "Policy.h"

/**
  Provide verification service for signed images.

  See DxeImageVerificationLib.h for the full contract.

  @param[in]  AuthenticationStatus  Unused (stub).
  @param[in]  File                  Device path describing the image origin.
  @param[in]  FileBuffer            Unused (stub).
  @param[in]  FileSize              Unused (stub).
  @param[in]  BootPolicy            Unused (stub).

  @retval EFI_SUCCESS            The image is authorized to execute by
                                 platform policy (ALWAYS_EXECUTE).
  @retval EFI_INVALID_PARAMETER  File is NULL.
  @retval EFI_UNSUPPORTED        The remainder of the verification
                                 service is not yet implemented in this
                                 library.
**/
EFI_STATUS
EFIAPI
DxeImageVerificationHandler (
  IN  UINT32                          AuthenticationStatus,
  IN  CONST EFI_DEVICE_PATH_PROTOCOL  *File  OPTIONAL,
  IN  VOID                            *FileBuffer,
  IN  UINTN                           FileSize,
  IN  BOOLEAN                         BootPolicy
  )
{
  EFI_STATUS  Status;
  UINT32      Policy;

  //
  // Sanity check.
  //
  if (File == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Resolve the platform authorization policy from the image's origin.
  //
  Status = GetExecutionPolicy (File, &Policy);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // If policy unconditionally permits execution, return directly.
  //
  if (Policy == ALWAYS_EXECUTE) {
    return EFI_SUCCESS;
  }

  return EFI_UNSUPPORTED;
}

/**
  Register the image verification security measurement handler.

  See DxeImageVerificationLib.h for the full contract.

  @param[in]  ImageHandle  Unused (stub).
  @param[in]  SystemTable  Unused (stub).

  @retval EFI_UNSUPPORTED  Registration is not yet implemented in this
                           library.
**/
EFI_STATUS
EFIAPI
DxeImageVerificationLibConstructor (
  IN  EFI_HANDLE        ImageHandle,
  IN  EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return RegisterSecurity2Handler (
           DxeImageVerificationHandler,
           EFI_AUTH_OPERATION_VERIFY_IMAGE | EFI_AUTH_OPERATION_IMAGE_REQUIRED
           );
}
