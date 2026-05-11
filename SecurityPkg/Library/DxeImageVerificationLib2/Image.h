/** @file
  PE/COFF image inspection helpers for the DXE Image Verification Library.

  This header declares helpers that extract image-format metadata from a
  PE/COFF file buffer. They are intentionally minimal and read-only: they
  perform their own bounds checking and never modify the supplied buffer.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_IMAGE_H_
#define DXE_IMAGE_VERIFICATION_LIB_IMAGE_H_

#include <Uefi.h>
#include <IndustryStandard/PeImage.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PeCoffLib.h>

/**
  Locate the EFI_IMAGE_DIRECTORY_ENTRY_SECURITY data directory in the
  PE/COFF image contained in FileBuffer.

  Header parsing, signature validation, optional-header magic checks,
  and bounds checking of the security data directory are delegated to
  PeCoffLib via PeCoffLoaderGetImageInfo() and the data-directory
  callback hook on PE_COFF_LOADER_IMAGE_CONTEXT. If the image is valid
  but does not declare a security data directory, SecDataDir is filled
  with zeros and EFI_SUCCESS is returned; callers must check
  SecDataDir->Size to distinguish unsigned images.

  Caution: This function may receive untrusted input. The PE/COFF image
  is external input and is bounds-checked by PeCoffLib before any field
  is dereferenced.

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
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_IMAGE_H_
