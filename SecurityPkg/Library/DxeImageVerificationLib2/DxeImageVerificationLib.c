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

  This handler exists solely to enforce UEFI Secure Boot. When Secure
  Boot is not enabled, no verification is required and the handler
  returns EFI_SUCCESS without inspecting the image.

  The platform authorization policy is resolved before the Secure Boot
  state is read. The overwhelming majority of dispatched images are
  firmware-volume drivers, which short-circuit to ALWAYS_EXECUTE; that
  resolution is much cheaper than reading the `SecureBoot` UEFI
  variable, so the cheap check runs first and the variable is only
  consulted when the policy did not already authorize the image.

  See DxeImageVerificationLib.h for the full contract.

  @param[in]  AuthenticationStatus  Unused (stub).
  @param[in]  File                  Device path describing the image origin.
  @param[in]  FileBuffer            Unused (stub).
  @param[in]  FileSize              Unused (stub).
  @param[in]  BootPolicy            Unused (stub).

  @retval EFI_SUCCESS            The image is permitted to execute,
                                 either because the platform policy
                                 unconditionally allows it (e.g. an FV
                                 image -> ALWAYS_EXECUTE) or because
                                 Secure Boot is not enabled and this
                                 handler has nothing to enforce.
  @retval EFI_INVALID_PARAMETER  File is NULL.
  @retval EFI_UNSUPPORTED        Secure Boot is enabled and the
                                 verification path required to make a
                                 decision is not yet implemented in
                                 this library.
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
  // This runs before the Secure Boot variable check because it is much
  // cheaper, and the common case (FV-dispatched drivers) short-circuits
  // if the policy is ALWAYS_EXECUTE.
  //
  Status = GetExecutionPolicy (File, &Policy);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Policy unconditionally permits execution; no further checks needed.
  //
  if (Policy == ALWAYS_EXECUTE) {
    return EFI_SUCCESS;
  }

  //
  // This handler only enforces UEFI Secure Boot. If Secure Boot is not
  // enabled there is nothing for us to verify.
  //
  if (!IsSecureBootEnabled ()) {
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
