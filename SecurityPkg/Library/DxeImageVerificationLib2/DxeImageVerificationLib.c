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
#include "Database.h"
#include "Image.h"
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
  @param[in]  FileBuffer            Pointer to the in-memory PE/COFF image.
  @param[in]  FileSize              Size of FileBuffer in bytes.
  @param[in]  BootPolicy            Unused (stub).

  @retval EFI_SUCCESS            The image is permitted to execute,
                                 either because the platform policy
                                 unconditionally allows it (e.g. an FV
                                 image -> ALWAYS_EXECUTE) or because
                                 Secure Boot is not enabled and this
                                 handler has nothing to enforce.
  @retval EFI_ACCESS_DENIED      The image's PE/COFF headers could not
                                 be parsed.
  @retval EFI_INVALID_PARAMETER  File is NULL.
  @retval Other                  Status returned from
                                 ValidateSignedImage or
                                 ValidateUnsignedImage.
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
  EFI_STATUS                Status;
  UINT32                    Policy;
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

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

  //
  // Inspect the image to locate its security data directory. Any failure
  // to parse the PE/COFF headers is treated as a verification failure.
  //
  Status = GetImageSecurityDataDirectory (FileBuffer, FileSize, &SecDataDir);
  if (EFI_ERROR (Status)) {
    return EFI_ACCESS_DENIED;
  }

  //
  // Dispatch to the appropriate verification path based on whether the
  // image carries an embedded signature.
  //
  if (SecDataDir.Size == 0) {
    return ValidateUnsignedImage (FileBuffer, FileSize);
  }

  return ValidateSignedImage (FileBuffer, FileSize, &SecDataDir);
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

/**
  Validate an unsigned PE/COFF image against the platform signature
  databases.

  See DxeImageVerificationLib.h for the full contract.
**/
EFI_STATUS
ValidateUnsignedImage (
  IN  VOID   *FileBuffer,
  IN  UINTN  FileSize
  )
{
  EFI_STATUS          Status;
  HASH_ALGORITHM_SET  HashAlgorithms;

  //
  // Determine which image-hash algorithms are currently in use across
  // db and dbx. If neither database enrolls any recognized hash type,
  // there is no algorithm with which to authorize an unsigned image,
  // so refuse to dispatch it.
  //
  Status = GetDatabaseHashAlgorithms (&HashAlgorithms);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: GetDatabaseHashAlgorithms failed - %r\n", Status));
    return EFI_ACCESS_DENIED;
  }

  if (HashAlgorithms.Count == 0) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: no hash algorithms enrolled in db/dbx; rejecting unsigned image.\n"));
    return EFI_ACCESS_DENIED;
  }

  //
  // TODO: hash FileBuffer with each algorithm in HashAlgorithms and
  // check membership against db (must hit) and dbx (must miss).
  //
  return EFI_UNSUPPORTED;
}

/**
  Validate a signed PE/COFF image's embedded signatures against the
  platform signature databases.

  See DxeImageVerificationLib.h for the full contract.
**/
EFI_STATUS
ValidateSignedImage (
  IN  VOID                            *FileBuffer,
  IN  UINTN                           FileSize,
  IN  CONST EFI_IMAGE_DATA_DIRECTORY  *SecDataDir
  )
{
  //
  // TODO: implement Authenticode/UEFI signature verification.
  //
  return EFI_UNSUPPORTED;
}
