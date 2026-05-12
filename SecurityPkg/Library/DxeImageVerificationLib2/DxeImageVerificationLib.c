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

  For each image-hash algorithm enrolled in db or dbx, computes the
  image's Authenticode digest and checks dbx then db. A dbx hit denies
  the image. The image is authorized only if it is found in db and
  never in dbx.

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
  )
{
  EFI_STATUS          Status;
  HASH_ALGORITHM_SET  HashAlgorithms;
  UINTN               Index;
  CONST EFI_GUID      *HashType;
  UINTN               DigestSize;
  UINT8               ImageDigest[SHA512_DIGEST_SIZE];
  BOOLEAN             IsFound;
  BOOLEAN             IsFoundInDb;
  VOID                *Db;
  UINTN               DbSize;
  VOID                *Dbx;
  UINTN               DbxSize;

  Db  = NULL;
  Dbx = NULL;

  //
  // Load the authorized (db) and forbidden (dbx) signature databases.
  //
  Status = LoadSignatureDatabase (EFI_IMAGE_SECURITY_DATABASE, &Db, &DbSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: failed to load db - %r\n", Status));
    Status = EFI_ACCESS_DENIED;
    goto Exit;
  }

  Status = LoadSignatureDatabase (EFI_IMAGE_SECURITY_DATABASE1, &Dbx, &DbxSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: failed to load dbx - %r\n", Status));
    Status = EFI_ACCESS_DENIED;
    goto Exit;
  }

  //
  // Determine which image-hash algorithms are currently in use across
  // db and dbx. If neither database enrolls any recognized hash type,
  // there is no algorithm with which to authorize an unsigned image,
  // so refuse to dispatch it.
  //
  Status = GetDatabaseHashAlgorithms (Db, DbSize, Dbx, DbxSize, &HashAlgorithms);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: GetDatabaseHashAlgorithms failed - %r\n", Status));
    Status = EFI_ACCESS_DENIED;
    goto Exit;
  }

  if (HashAlgorithms.Count == 0) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: no hash algorithms enrolled in db/dbx; rejecting unsigned image.\n"));
    Status = EFI_ACCESS_DENIED;
    goto Exit;
  }

  //
  // For each algorithm in use, compute the image's Authenticode digest and query the dbx / db.
  // A hit in the dbx immediately denies the image. If no dbx hit occurs across all algorithms,
  // the image is authorized or denied based on whether at least one db hit was recorded.
  //
  IsFoundInDb = FALSE;
  for (Index = 0; Index < HashAlgorithms.Count; Index++) {
    HashType = &HashAlgorithms.Guids[Index];

    Status = GetAuthenticodeHash (FileBuffer, FileSize, HashType, ImageDigest, &DigestSize);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: GetAuthenticodeHash failed - %r\n", Status));
      Status = EFI_ACCESS_DENIED;
      goto Exit;
    }

    Status = IsSignatureFoundInDatabase (
               Dbx,
               DbxSize,
               ImageDigest,
               HashType,
               DigestSize,
               &IsFound
               );
    if (EFI_ERROR (Status) || IsFound) {
      DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: Image is not signed and image is forbidden by DBX.\n"));
      Status = EFI_ACCESS_DENIED;
      goto Exit;
    }

    if (IsFoundInDb) {
      continue;
    }

    Status = IsSignatureFoundInDatabase (
               Db,
               DbSize,
               ImageDigest,
               HashType,
               DigestSize,
               &IsFound
               );
    if (!EFI_ERROR (Status) && IsFound) {
      IsFoundInDb = TRUE;
    }
  }

  Status = IsFoundInDb ? EFI_SUCCESS : EFI_ACCESS_DENIED;

Exit:
  if (Db != NULL) {
    FreePool (Db);
  }

  if (Dbx != NULL) {
    FreePool (Dbx);
  }

  return Status;
}

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
  )
{
  //
  // TODO: implement Authenticode/UEFI signature verification.
  //
  return EFI_UNSUPPORTED;
}
