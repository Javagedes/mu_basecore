/** @file
  Image verification policy helpers for the DXE Image Verification Library.

  This header declares the data types, image source classifications, and
  helper APIs that resolve an EFI_DEVICE_PATH_PROTOCOL describing the
  origin of an image into an authorization policy that the verification
  handler should apply.

  The current policy is intentionally minimal: images loaded from a
  Firmware Volume are always allowed to execute; everything else is
  denied unless additional verification succeeds.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_POLICY_H_
#define DXE_IMAGE_VERIFICATION_LIB_POLICY_H_

#include <Uefi.h>
#include <Protocol/DevicePath.h>

//
// Image source type definitions. These describe where an image was loaded
// from and are the input to the policy decision performed by the
// verification handler.
//
#define IMAGE_UNKNOWN  0x00000000
#define IMAGE_FROM_FV  0x00000001

//
// Authorization policy values produced by GetPolicyForImageType /
// GetExecutionPolicy.
//
#define ALWAYS_EXECUTE                      0x00000000
#define DENY_EXECUTE_ON_SECURITY_VIOLATION  0x00000001

/**
  Determine whether the given device path resolves to a Firmware Volume.

  @param[in]   File       Device path describing the image origin.
  @param[out]  ImageType  On success, set to IMAGE_FROM_FV.

  @retval EFI_SUCCESS            ImageType has been set to IMAGE_FROM_FV.
  @retval EFI_INVALID_PARAMETER  File or ImageType is NULL.
  @retval EFI_NOT_FOUND          The device path does not resolve to a
                                 Firmware Volume.
**/
EFI_STATUS
GetFirmwareVolumeImageType (
  IN  CONST EFI_DEVICE_PATH_PROTOCOL  *File,
  OUT UINT32                          *ImageType
  );

/**
  Classify an image based on its device path.

  Currently only firmware volume images are recognized; all other device
  paths are reported as IMAGE_UNKNOWN.

  @param[in]   File       Device path describing the image origin.
  @param[out]  ImageType  On success, filled with IMAGE_FROM_FV when the
                          image was loaded from a firmware volume, or
                          IMAGE_UNKNOWN otherwise.

  @retval EFI_SUCCESS            ImageType contains a valid value.
  @retval EFI_INVALID_PARAMETER  File or ImageType is NULL.
**/
EFI_STATUS
GetImageType (
  IN  CONST EFI_DEVICE_PATH_PROTOCOL  *File,
  OUT UINT32                          *ImageType
  );

/**
  Look up the configured authorization policy for the given image source.

  IMAGE_FROM_FV is mapped to ALWAYS_EXECUTE; every other source maps to
  the fail-closed value DENY_EXECUTE_ON_SECURITY_VIOLATION.

  @param[in]  ImageType  An IMAGE_* image source classification value.

  @return  ALWAYS_EXECUTE or DENY_EXECUTE_ON_SECURITY_VIOLATION.
**/
UINT32
GetPolicyForImageType (
  IN UINT32  ImageType
  );

/**
  Resolve an image's authorization policy directly from its device path.

  This composes GetImageType() and GetPolicyForImageType() and is the
  primary entry point used by the verification handler.

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
