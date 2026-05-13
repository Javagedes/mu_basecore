/** @file
  Helpers for the EFI Image Execution Information Table.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_EXECUTION_INFO_H_
#define DXE_IMAGE_VERIFICATION_LIB_EXECUTION_INFO_H_

#include <Uefi.h>
#include <Guid/ImageAuthentication.h>

/**
  Install an empty EFI_IMAGE_EXECUTION_INFO_TABLE in the EFI System
  Configuration Table under gEfiImageSecurityDatabaseGuid.

  If a table is already installed under that GUID this routine is a
  no-op.

  @retval EFI_SUCCESS           A table is installed (either freshly
                                installed by this call or pre-existing).
  @retval EFI_OUT_OF_RESOURCES  Allocation of the empty table failed.
  @retval Other                 InstallConfigurationTable failed.
**/
EFI_STATUS
InstallImageExecutionInfoTable (
  VOID
  );

/**
  Append a new entry recording that the firmware took `Action` on the
  image whose origin is described by `DevicePath`.

  The new entry has an empty Name and no embedded signature; only the
  Action and DevicePath fields are populated. If no execution info
  table is currently installed, this routine installs a fresh one
  before appending.

  @param[in]  Action      The action taken by the firmware on the image.
  @param[in]  DevicePath  Device path describing the image origin. Must
                          not be NULL.
**/
VOID
RecordImageExecutionInfo (
  IN EFI_IMAGE_EXECUTION_ACTION       Action,
  IN CONST EFI_DEVICE_PATH_PROTOCOL  *DevicePath
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_EXECUTION_INFO_H_
