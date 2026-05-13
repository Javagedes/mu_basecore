/** @file
  Helpers for the EFI Image Execution Information Table.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "ExecutionInfo.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

/**
  Compute the size in bytes of the given EFI_IMAGE_EXECUTION_INFO_TABLE,
  walking its variable-length entries.

  @param[in]  Table  Table to measure.

  @return  Total size of Table in bytes.
**/
STATIC
UINTN
GetTableSize (
  IN EFI_IMAGE_EXECUTION_INFO_TABLE  *Table
  )
{
  UINTN                     Index;
  EFI_IMAGE_EXECUTION_INFO  *Entry;
  UINTN                     TotalSize;

  Entry     = (EFI_IMAGE_EXECUTION_INFO *)(Table + 1);
  TotalSize = sizeof (EFI_IMAGE_EXECUTION_INFO_TABLE);
  for (Index = 0; Index < Table->NumberOfImages; Index++) {
    TotalSize += ReadUnaligned32 ((UINT32 *)&Entry->InfoSize);
    Entry      = (EFI_IMAGE_EXECUTION_INFO *)((UINT8 *)Entry + ReadUnaligned32 ((UINT32 *)&Entry->InfoSize));
  }

  return TotalSize;
}

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
  )
{
  EFI_STATUS                      Status;
  EFI_IMAGE_EXECUTION_INFO_TABLE  *Table;

  Table  = NULL;
  Status = EfiGetSystemConfigurationTable (&gEfiImageSecurityDatabaseGuid, (VOID **)&Table);
  if (!EFI_ERROR (Status) && (Table != NULL)) {
    return EFI_SUCCESS;
  }

  Table = (EFI_IMAGE_EXECUTION_INFO_TABLE *)AllocateRuntimePool (sizeof (EFI_IMAGE_EXECUTION_INFO_TABLE));
  if (Table == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Table->NumberOfImages = 0;

  Status = gBS->InstallConfigurationTable (&gEfiImageSecurityDatabaseGuid, (VOID *)Table);
  if (EFI_ERROR (Status)) {
    FreePool (Table);
  }

  return Status;
}

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
  )
{
  EFI_STATUS                      Status;
  EFI_IMAGE_EXECUTION_INFO_TABLE  *OldTable;
  EFI_IMAGE_EXECUTION_INFO_TABLE  *NewTable;
  EFI_IMAGE_EXECUTION_INFO        *Entry;
  UINTN                           OldTableSize;
  UINTN                           DevicePathSize;
  UINTN                           NewEntrySize;
  CHAR16                          *NameField;

  if (DevicePath == NULL) {
    return;
  }

  OldTable = NULL;
  Status   = EfiGetSystemConfigurationTable (&gEfiImageSecurityDatabaseGuid, (VOID **)&OldTable);
  if (EFI_ERROR (Status) || (OldTable == NULL)) {
    OldTable     = NULL;
    OldTableSize = sizeof (EFI_IMAGE_EXECUTION_INFO_TABLE);
  } else {
    OldTableSize = GetTableSize (OldTable);
  }

  DevicePathSize = GetDevicePathSize (DevicePath);
  //
  // One empty CHAR16 for the Name field, the device path, and no signature.
  //
  NewEntrySize = sizeof (EFI_IMAGE_EXECUTION_INFO) + sizeof (CHAR16) + DevicePathSize;

  NewTable = (EFI_IMAGE_EXECUTION_INFO_TABLE *)AllocateRuntimePool (OldTableSize + NewEntrySize);
  if (NewTable == NULL) {
    return;
  }

  if (OldTable != NULL) {
    CopyMem (NewTable, OldTable, OldTableSize);
  } else {
    NewTable->NumberOfImages = 0;
  }

  Entry = (EFI_IMAGE_EXECUTION_INFO *)((UINT8 *)NewTable + OldTableSize);
  WriteUnaligned32 ((UINT32 *)&Entry->Action, Action);
  WriteUnaligned32 ((UINT32 *)&Entry->InfoSize, (UINT32)NewEntrySize);

  NameField    = (CHAR16 *)(Entry + 1);
  NameField[0] = L'\0';
  CopyMem ((UINT8 *)NameField + sizeof (CHAR16), DevicePath, DevicePathSize);

  NewTable->NumberOfImages++;

  Status = gBS->InstallConfigurationTable (&gEfiImageSecurityDatabaseGuid, (VOID *)NewTable);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DxeImageVerificationLib: InstallConfigurationTable failed - %r\n", Status));
    FreePool (NewTable);
    return;
  }

  if (OldTable != NULL) {
    FreePool (OldTable);
  }
}
