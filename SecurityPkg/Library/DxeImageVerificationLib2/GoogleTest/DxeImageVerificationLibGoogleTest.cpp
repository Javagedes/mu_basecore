/** @file
  Unit tests for the implementation of DxeImageVerificationLib.

  Copyright (c) 2025, Yandex. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockUefiLib.h>
#include <GoogleTest/Library/MockUefiRuntimeServicesTableLib.h>
#include <GoogleTest/Library/MockUefiBootServicesTableLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/DebugLib.h>
  #include <Protocol/DevicePath.h>

  #include "DxeImageVerificationLibGoogleTest.h"
  #include "../DxeImageVerificationLib.h"
  #include "../Policy.h"
}

using ::testing::_;
using ::testing::Return;

int
main (
  int   argc,
  char  *argv[]
  )
{
  testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}

//
// A minimal stand-in for an EFI_DEVICE_PATH_PROTOCOL. The address is the
// only thing the handler cares about because LocateDevicePath /
// OpenProtocol are fully mocked.
//
static EFI_DEVICE_PATH_PROTOCOL  mHandlerDevicePath;

class DxeImageVerificationHandlerTest : public ::testing::Test {
protected:
  MockUefiBootServicesTableLib BsMock;
};

// ---------------------------------------------------------------------------
// DxeImageVerificationHandler
// ---------------------------------------------------------------------------

TEST_F (DxeImageVerificationHandlerTest, NullFile_ReturnsInvalidParameter) {
  EXPECT_EQ (
    DxeImageVerificationHandler (0, NULL, NULL, 0, FALSE),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (DxeImageVerificationHandlerTest, FvImage_ReturnsSuccess) {
  //
  // FV classification path => GetPolicyForImageType returns ALWAYS_EXECUTE.
  //
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_SUCCESS));
  EXPECT_CALL (BsMock, gBS_OpenProtocol)
    .WillOnce (Return (EFI_SUCCESS));

  EXPECT_EQ (
    DxeImageVerificationHandler (0, &mHandlerDevicePath, NULL, 0, FALSE),
    EFI_SUCCESS
    );
}

TEST_F (DxeImageVerificationHandlerTest, NonFvImage_ReturnsUnsupported) {
  //
  // Non-FV image is classified as IMAGE_UNKNOWN, which maps to the
  // fail-closed DENY_EXECUTE_ON_SECURITY_VIOLATION policy. The handler
  // stub returns EFI_UNSUPPORTED for that case.
  //
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_NOT_FOUND));

  EXPECT_EQ (
    DxeImageVerificationHandler (0, &mHandlerDevicePath, NULL, 0, FALSE),
    EFI_UNSUPPORTED
    );
}
