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

/**
  Provide verification service for signed images.

  See DxeImageVerificationLib.h for the full contract.

  @param[in]  AuthenticationStatus  Unused (stub).
  @param[in]  File                  Unused (stub).
  @param[in]  FileBuffer            Unused (stub).
  @param[in]  FileSize              Unused (stub).
  @param[in]  BootPolicy            Unused (stub).

  @retval EFI_UNSUPPORTED  The verification service is not yet
                           implemented in this library.
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
