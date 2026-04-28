/** @file
  Internal declarations for the DXE Image Verification Library.

  This header is consumed by the library's source files (and its unit
  tests) to share prototypes for the constructor and the Security2
  verification handler.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_H_
#define DXE_IMAGE_VERIFICATION_LIB_H_

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/SecurityManagementLib.h>
#include <Protocol/DevicePath.h>

/**
  Provide verification service for signed images, which include both
  signature validation and platform policy control. For signature types,
  both UEFI WIN_CERTIFICATE_UEFI_GUID and MSFT Authenticode type
  signatures are supported.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its
  data structure within this image buffer before use.

  @param[in]  AuthenticationStatus  Authentication status returned from
                                    the security measurement services
                                    for the input file.
  @param[in]  File                  Device path of the file being
                                    dispatched. Optional; used for
                                    logging.
  @param[in]  FileBuffer            File buffer matching the input file
                                    device path.
  @param[in]  FileSize              Size of FileBuffer in bytes.
  @param[in]  BootPolicy            BootPolicy that was used to call the
                                    LoadImage() UEFI service.

  @retval EFI_SUCCESS            The file authenticated and the platform
                                 policy permits execution.
  @retval EFI_SECURITY_VIOLATION The file did not authenticate; the
                                 platform policy places it in the
                                 untrusted state.
  @retval EFI_ACCESS_DENIED      The file did not authenticate and the
                                 platform policy forbids execution.
  @retval EFI_INVALID_PARAMETER  Invalid input was supplied.
  @retval EFI_UNSUPPORTED        The verification service is not yet
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
  );

/**
  Register the image verification security measurement handler.

  @param[in]  ImageHandle  Image handle of the loaded driver.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS      The handlers were registered successfully.
  @retval EFI_UNSUPPORTED  Registration is not yet implemented in this
                           library.
**/
EFI_STATUS
EFIAPI
DxeImageVerificationLibConstructor (
  IN  EFI_HANDLE        ImageHandle,
  IN  EFI_SYSTEM_TABLE  *SystemTable
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_H_
