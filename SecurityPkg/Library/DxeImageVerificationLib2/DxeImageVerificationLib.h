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
#include <Guid/ImageAuthentication.h>
#include <IndustryStandard/PeImage.h>
#include <Protocol/DevicePath.h>
#include <UefiSecureBoot.h>
#include <Library/DebugLib.h>
#include <Library/SecureBootVariableLib.h>
#include <Library/SecurityManagementLib.h>
#include <Library/BaseCryptLib.h>

/**
  Validate an unsigned PE/COFF image against the platform signature
  databases.

  Fetches the union of image-hash algorithms enrolled in `db` and
  `dbx` via GetDatabaseHashAlgorithms. For each enrolled algorithm,
  computes the image's Authenticode digest and queries dbx, then db.
  A hit in dbx denies the image immediately. A hit in db is recorded
  but the loop continues so that a later iteration can still find a
  revoking entry in dbx for a different algorithm (FR-3 — dbx
  overrides db, including across algorithms). After the loop, the
  image is authorized only if at least one db hit was recorded and
  no dbx hit ever occurred. If no algorithm produces a hit in either
  database the image is denied.

  @param[in]  FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]  FileSize    Size of FileBuffer in bytes.

  @retval EFI_SUCCESS        The image's hash was found in db (and not
                             in dbx) under at least one enrolled
                             algorithm.
  @retval EFI_ACCESS_DENIED  The image was rejected: either no hash
                             algorithm is enrolled, the digest is
                             present in dbx, the digest is not present
                             in db, or a database lookup failed.
**/
EFI_STATUS
ValidateUnsignedImage (
  IN  VOID   *FileBuffer,
  IN  UINTN  FileSize
  );

/**
  Validate a signed PE/COFF image's embedded Authenticode/UEFI signatures
  against the platform signature databases.

  TODO: Not yet implemented. The handler currently calls this stub when
  Secure Boot is enabled and the dispatched image declares a non-empty
  security data directory.

  @param[in]  FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]  FileSize    Size of FileBuffer in bytes.
  @param[in]  SecDataDir  Security data directory describing the
                          embedded WIN_CERTIFICATE table.

  @retval EFI_UNSUPPORTED  The signed-image verification path is not yet
                           implemented.
**/
EFI_STATUS
ValidateSignedImage (
  IN  VOID                            *FileBuffer,
  IN  UINTN                           FileSize,
  IN  CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir
  );

/**
  Provide verification service for signed images, which include both
  signature validation and platform policy control. For signature types,
  both UEFI WIN_CERTIFICATE_UEFI_GUID and MSFT Authenticode type
  signatures are supported.

  This handler exists solely to enforce UEFI Secure Boot. When Secure
  Boot is not enabled, the handler has no work to do and returns
  EFI_SUCCESS without inspecting the image.

  The platform authorization policy is resolved before the Secure Boot
  state is read because the overwhelming majority of dispatched images
  are firmware-volume drivers, for which the policy short-circuits to
  ALWAYS_EXECUTE. Resolving that policy is much cheaper than reading the
  `SecureBoot` UEFI variable, so the cheap check runs first.

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

  @retval EFI_SUCCESS            The image is permitted to execute,
                                 either because the platform policy
                                 unconditionally allows it or because
                                 Secure Boot is not enabled and this
                                 handler has nothing to enforce.
  @retval EFI_SECURITY_VIOLATION The file did not authenticate; the
                                 platform policy places it in the
                                 untrusted state.
  @retval EFI_ACCESS_DENIED      The file did not authenticate and the
                                 platform policy forbids execution.
  @retval EFI_INVALID_PARAMETER  Invalid input was supplied.
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
