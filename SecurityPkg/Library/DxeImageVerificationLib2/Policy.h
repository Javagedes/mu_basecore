/** @file
  Image verification policy helpers for the DXE Image Verification Library.

  Data types, image source classifications, and APIs that resolve an
  EFI_DEVICE_PATH_PROTOCOL into an authorization policy that the verification
  handler should apply. The current policy is intentionally minimal: images
  loaded from a Firmware Volume are always allowed to execute; everything else is
  denied if validation fails.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_POLICY_H_
#define DXE_IMAGE_VERIFICATION_LIB_POLICY_H_

#include "DxeImageVerificationLib.h"

#include <Pi/PiFirmwareFile.h>
#include <Pi/PiFirmwareVolume.h>
#include <Protocol/FirmwareVolume2.h>

//
// Authorization policy bit definition
//
#define ALWAYS_EXECUTE                      0x00000000
#define DENY_EXECUTE_ON_SECURITY_VIOLATION  0x00000001

//
// Image type definitions
//
#define IMAGE_UNKNOWN  0x00000000
#define IMAGE_FROM_FV  0x00000001

/**
  Resolve an image's authorization policy.

  @param[in]   File    Device path describing the image origin.
  @param[out]  Policy  On success, filled with the resolved policy value.

  @retval EFI_SUCCESS            Policy contains a valid policy value.
  @retval EFI_INVALID_PARAMETER  File or Policy is NULL.
**/
EFI_STATUS
GetExecutionPolicy (
  IN  CONST EFI_DEVICE_PATH_PROTOCOL  *File,
  OUT UINT32                          *Policy
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_POLICY_H_
