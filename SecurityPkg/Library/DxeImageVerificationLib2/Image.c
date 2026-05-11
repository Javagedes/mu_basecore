/** @file
  PE/COFF image inspection helpers for the DXE Image Verification Library.

  Caution: This module receives untrusted input. The PE/COFF image is
  external input; PeCoffLib validates the headers and bounds-checks the
  security data directory before delivering it via callback.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Image.h"

//
// Caller-owned state passed through PeCoffLoaderGetImageInfo() to
// SecurityDirectoryCallback() and back.
//
typedef struct {
  EFI_IMAGE_DATA_DIRECTORY    SecDataDir;
} SECURITY_DIR_CALLBACK_CTX;

/**
  PE_COFF_LOADER_DATA_DIRECTORY_CALLBACK that captures the
  EFI_IMAGE_DIRECTORY_ENTRY_SECURITY entry into the caller's context
  and asks PeCoffLib to keep iterating remaining entries.

  @param[in]  Index            Data directory slot.
  @param[in]  DataDirectory    The directory entry being delivered.
  @param[in]  CallbackContext  Pointer to a SECURITY_DIR_CALLBACK_CTX.

  @retval RETURN_SUCCESS  Always.
**/
STATIC
RETURN_STATUS
EFIAPI
SecurityDirectoryCallback (
  IN UINT32                          Index,
  IN CONST EFI_IMAGE_DATA_DIRECTORY  *DataDirectory,
  IN VOID                            *CallbackContext  OPTIONAL
  )
{
  SECURITY_DIR_CALLBACK_CTX  *Ctx;

  if (Index != EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
    return RETURN_SUCCESS;
  }

  Ctx             = (SECURITY_DIR_CALLBACK_CTX *)CallbackContext;
  Ctx->SecDataDir = *DataDirectory;
  return RETURN_SUCCESS;
}

/**
  Locate the EFI_IMAGE_DIRECTORY_ENTRY_SECURITY data directory in the
  PE/COFF image contained in FileBuffer.

  See Image.h for the full contract.

  @param[in]   FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]   FileSize    Size of FileBuffer in bytes.
  @param[out]  SecDataDir  On success, filled with a copy of the image's
                           security data directory entry. Zeroed when
                           the image declares no security directory.

  @retval EFI_SUCCESS            SecDataDir has been populated.
  @retval EFI_INVALID_PARAMETER  FileBuffer or SecDataDir is NULL.
  @retval EFI_LOAD_ERROR         FileBuffer does not contain a valid
                                 PE/COFF image, or PeCoffLib otherwise
                                 rejected the headers.
**/
EFI_STATUS
GetImageSecurityDataDirectory (
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize,
  OUT EFI_IMAGE_DATA_DIRECTORY  *SecDataDir
  )
{
  RETURN_STATUS                 PeCoffStatus;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;
  SECURITY_DIR_CALLBACK_CTX     CallbackCtx;

  if ((FileBuffer == NULL) || (SecDataDir == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (SecDataDir, sizeof (*SecDataDir));
  ZeroMem (&CallbackCtx, sizeof (CallbackCtx));

  //
  // Delegate header parsing, signature validation, optional-header
  // magic checks, and security-directory bounds checking to PeCoffLib.
  // The callback receives the validated security data directory entry.
  //
  ZeroMem (&ImageContext, sizeof (ImageContext));
  ImageContext.Handle                       = FileBuffer;
  ImageContext.ImageRead                    = PeCoffLoaderImageReadFromMemory;
  ImageContext.DataDirectoryCallback        = SecurityDirectoryCallback;
  ImageContext.DataDirectoryCallbackContext = &CallbackCtx;

  PeCoffStatus = PeCoffLoaderGetImageInfo (&ImageContext);
  if (RETURN_ERROR (PeCoffStatus)) {
    DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: PeImage invalid (0x%lx).\n", (UINT64)PeCoffStatus));
    return EFI_LOAD_ERROR;
  }

  *SecDataDir = CallbackCtx.SecDataDir;
  return EFI_SUCCESS;
}
