/** @file
  Unit tests for the Image Verification Library policy resolution helpers.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockUefiBootServicesTableLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/DebugLib.h>
  #include <Protocol/DevicePath.h>

  #include "../Policy.h"
}

using ::testing::_;
using ::testing::Return;

//
// A minimal stand-in for an EFI_DEVICE_PATH_PROTOCOL. The address is the
// only thing the helpers care about because LocateDevicePath /
// OpenProtocol are fully mocked.
//
static EFI_DEVICE_PATH_PROTOCOL  mDevicePath;

class PolicyTest : public ::testing::Test {
protected:
  MockUefiBootServicesTableLib BsMock;
};

// ---------------------------------------------------------------------------
// GetFirmwareVolumeImageType
// ---------------------------------------------------------------------------

TEST_F (PolicyTest, GetFirmwareVolumeImageType_NullArgs_ReturnsInvalidParameter) {
  UINT32  ImageType = IMAGE_UNKNOWN;

  EXPECT_EQ (GetFirmwareVolumeImageType (NULL, &ImageType), EFI_INVALID_PARAMETER);
  EXPECT_EQ (GetFirmwareVolumeImageType (&mDevicePath, NULL), EFI_INVALID_PARAMETER);
}

TEST_F (PolicyTest, GetFirmwareVolumeImageType_LocateFails_ReturnsNotFound) {
  UINT32  ImageType = IMAGE_UNKNOWN;

  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_NOT_FOUND));

  EXPECT_EQ (GetFirmwareVolumeImageType (&mDevicePath, &ImageType), EFI_NOT_FOUND);
}

TEST_F (PolicyTest, GetFirmwareVolumeImageType_OpenFails_ReturnsNotFound) {
  UINT32  ImageType = IMAGE_UNKNOWN;

  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_SUCCESS));
  EXPECT_CALL (BsMock, gBS_OpenProtocol)
    .WillOnce (Return (EFI_UNSUPPORTED));

  EXPECT_EQ (GetFirmwareVolumeImageType (&mDevicePath, &ImageType), EFI_NOT_FOUND);
}

TEST_F (PolicyTest, GetFirmwareVolumeImageType_Success_SetsFv) {
  UINT32  ImageType = IMAGE_UNKNOWN;

  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_SUCCESS));
  EXPECT_CALL (BsMock, gBS_OpenProtocol)
    .WillOnce (Return (EFI_SUCCESS));

  EXPECT_EQ (GetFirmwareVolumeImageType (&mDevicePath, &ImageType), EFI_SUCCESS);
  EXPECT_EQ (ImageType, (UINT32)IMAGE_FROM_FV);
}

// ---------------------------------------------------------------------------
// GetImageType
// ---------------------------------------------------------------------------

TEST_F (PolicyTest, GetImageType_NullArgs_ReturnsInvalidParameter) {
  UINT32  ImageType = IMAGE_UNKNOWN;

  EXPECT_EQ (GetImageType (NULL, &ImageType), EFI_INVALID_PARAMETER);
  EXPECT_EQ (GetImageType (&mDevicePath, NULL), EFI_INVALID_PARAMETER);
}

TEST_F (PolicyTest, GetImageType_FirmwareVolume_ReturnsFv) {
  UINT32  ImageType = IMAGE_UNKNOWN;

  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_SUCCESS));
  EXPECT_CALL (BsMock, gBS_OpenProtocol)
    .WillOnce (Return (EFI_SUCCESS));

  EXPECT_EQ (GetImageType (&mDevicePath, &ImageType), EFI_SUCCESS);
  EXPECT_EQ (ImageType, (UINT32)IMAGE_FROM_FV);
}

TEST_F (PolicyTest, GetImageType_NotFv_ReturnsUnknown) {
  UINT32  ImageType = IMAGE_FROM_FV; // Pre-populate to confirm reset.

  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_NOT_FOUND));

  EXPECT_EQ (GetImageType (&mDevicePath, &ImageType), EFI_SUCCESS);
  EXPECT_EQ (ImageType, (UINT32)IMAGE_UNKNOWN);
}

// ---------------------------------------------------------------------------
// GetPolicyForImageType
// ---------------------------------------------------------------------------

TEST_F (PolicyTest, GetPolicyForImageType_Fv_ReturnsAlwaysExecute) {
  EXPECT_EQ (GetPolicyForImageType (IMAGE_FROM_FV), (UINT32)ALWAYS_EXECUTE);
}

TEST_F (PolicyTest, GetPolicyForImageType_Unknown_FailsClosed) {
  EXPECT_EQ (
    GetPolicyForImageType (IMAGE_UNKNOWN),
    (UINT32)DENY_EXECUTE_ON_SECURITY_VIOLATION
    );
}

TEST_F (PolicyTest, GetPolicyForImageType_OtherValue_FailsClosed) {
  EXPECT_EQ (
    GetPolicyForImageType (0xDEADBEEF),
    (UINT32)DENY_EXECUTE_ON_SECURITY_VIOLATION
    );
}

// ---------------------------------------------------------------------------
// GetExecutionPolicy
// ---------------------------------------------------------------------------

TEST_F (PolicyTest, GetExecutionPolicy_NullArgs_ReturnsInvalidParameter) {
  UINT32  Policy = ALWAYS_EXECUTE;

  EXPECT_EQ (GetExecutionPolicy (NULL, &Policy), EFI_INVALID_PARAMETER);
  EXPECT_EQ (GetExecutionPolicy (&mDevicePath, NULL), EFI_INVALID_PARAMETER);
}

TEST_F (PolicyTest, GetExecutionPolicy_FirmwareVolume_ReturnsAlwaysExecute) {
  UINT32  Policy = DENY_EXECUTE_ON_SECURITY_VIOLATION;

  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_SUCCESS));
  EXPECT_CALL (BsMock, gBS_OpenProtocol)
    .WillOnce (Return (EFI_SUCCESS));

  EXPECT_EQ (GetExecutionPolicy (&mDevicePath, &Policy), EFI_SUCCESS);
  EXPECT_EQ (Policy, (UINT32)ALWAYS_EXECUTE);
}

TEST_F (PolicyTest, GetExecutionPolicy_NonFv_FailsClosed) {
  UINT32  Policy = ALWAYS_EXECUTE;

  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_NOT_FOUND));

  EXPECT_EQ (GetExecutionPolicy (&mDevicePath, &Policy), EFI_SUCCESS);
  EXPECT_EQ (Policy, (UINT32)DENY_EXECUTE_ON_SECURITY_VIOLATION);
}
