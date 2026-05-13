/** @file
  Unit tests for the implementation of DxeImageVerificationLib.

  Copyright (c) 2025, Yandex. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockUefiLib.h>
#include <GoogleTest/Library/MockUefiRuntimeServicesTableLib.h>
#include <GoogleTest/Library/MockUefiBootServicesTableLib.h>
#include <GoogleTest/Library/MockSecureBootVariableLib.h>
#include <GoogleTest/Library/MockDevicePathLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/DebugLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include <Protocol/DevicePath.h>

  #include "DxeImageVerificationLibGoogleTest.h"
  #include "../DxeImageVerificationLib.h"
  #include "../Policy.h"
}

using ::testing::_;
using ::testing::Invoke;
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
// A minimal stand-in for an EFI_DEVICE_PATH_PROTOCOL. A single
// END_ENTIRE node so GetDevicePathSize() can walk it.
//
static EFI_DEVICE_PATH_PROTOCOL  mHandlerDevicePath = {
  END_DEVICE_PATH_TYPE,
  END_ENTIRE_DEVICE_PATH_SUBTYPE,
  { (UINT8)sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 }
};

class DxeImageVerificationHandlerTest : public ::testing::Test {
protected:
  MockUefiBootServicesTableLib BsMock;
  MockUefiLib UefiLibMock;
  MockSecureBootVariableLib SbMock;
  MockDevicePathLib DpMock;
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

TEST_F (DxeImageVerificationHandlerTest, NonFvImage_SecureBootEnabled_NullBuffer_ReturnsInvalidParameter) {
  //
  // Non-FV image with Secure Boot enabled: the handler tries to parse
  // the PE/COFF image, which fails because FileBuffer is NULL, and
  // surfaces EFI_INVALID_PARAMETER from the PE parser. The handler
  // also records an entry in the EFI Image Execution Info Table for
  // any non-success outcome.
  //
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_NOT_FOUND));
  EXPECT_CALL (SbMock, IsSecureBootEnabled)
    .WillOnce (Return ((BOOLEAN)TRUE));
  EXPECT_CALL (UefiLibMock, EfiGetSystemConfigurationTable (_, _))
    .WillOnce (Return (EFI_NOT_FOUND));
  EXPECT_CALL (DpMock, GetDevicePathSize (_))
    .WillOnce (Return ((UINTN)sizeof (EFI_DEVICE_PATH_PROTOCOL)));
  //
  // The mock takes ownership of the buffer (production gBS would), so
  // free it here to keep LeakSanitizer happy.
  //
  EXPECT_CALL (BsMock, gBS_InstallConfigurationTable (_, _))
    .WillOnce (
       Invoke (
         [] (EFI_GUID *Guid, VOID *Table) -> EFI_STATUS {
    (VOID)Guid;
    FreePool (Table);
    return EFI_SUCCESS;
  }
         )
       );

  EXPECT_EQ (
    DxeImageVerificationHandler (0, &mHandlerDevicePath, NULL, 0, FALSE),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (DxeImageVerificationHandlerTest, NonFvImage_SecureBootDisabled_ReturnsSuccess) {
  //
  // Non-FV image but Secure Boot is disabled: the handler must skip
  // verification and return EFI_SUCCESS.
  //
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_NOT_FOUND));
  EXPECT_CALL (SbMock, IsSecureBootEnabled)
    .WillOnce (Return ((BOOLEAN)FALSE));

  EXPECT_EQ (
    DxeImageVerificationHandler (0, &mHandlerDevicePath, NULL, 0, FALSE),
    EFI_SUCCESS
    );
}

TEST_F (DxeImageVerificationHandlerTest, FvImage_DoesNotConsultSecureBoot) {
  //
  // The ALWAYS_EXECUTE short-circuit must run before IsSecureBootEnabled
  // is consulted. Setting no expectation on SbMock plus StrictMock-style
  // EXPECT_CALL omission verifies it is never invoked.
  //
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (Return (EFI_SUCCESS));
  EXPECT_CALL (BsMock, gBS_OpenProtocol)
    .WillOnce (Return (EFI_SUCCESS));
  EXPECT_CALL (SbMock, IsSecureBootEnabled)
    .Times (0);

  EXPECT_EQ (
    DxeImageVerificationHandler (0, &mHandlerDevicePath, NULL, 0, FALSE),
    EFI_SUCCESS
    );
}
