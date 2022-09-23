/** @file
  Definitions for the verified policy libraries.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _VERIFIED_POLICY_H_
#define _VERIFIED_POLICY_H_

#define VERIFIED_POLICY_LIB_VERSION  1

#pragma pack(1)

typedef struct _VERIFIED_POLICY_HEADER {
  UINT64    Signature;
  UINT16    MajorVersion;
  UINT16    MinorVersion;
  UINT32    Size;
} VERIFIED_POLICY_HEADER;

#pragma pack()

typedef VERIFIED_POLICY_HEADER VERIFIED_POLICY_DESCRIPTOR;

/**
  Retrieves a verified policy of the given type from the policy store.

  @param[in]    PolicyGuid      The GUID of policy in the policy store.

  @param[in]    Descriptor      The descriptor for the verified policy data
                                structure.

  @param[out]   Attributes      Returns the attributes of the policy in the
                                policy store.

  @param[out]   DataHandle      Returns the handle to the verified policy.

  @retval   EFI_SUCCESS               The policy was successfully retrieved.
  @retval   EFI_BAD_BUFFER_SIZE       The policy was an unexpected size.
  @retval   EFI_INCOMPATIBLE_VERSION  The verified policy major version did not
                                      match.
  @retval   EFI_OUT_OF_RESOURCES      Failed to allocate memory.
**/
RETURN_STATUS
EFIAPI
GetVerifiedPolicy (
  IN CONST EFI_GUID                    *PolicyGuid,
  IN CONST VERIFIED_POLICY_DESCRIPTOR  *Descriptor,
  OUT UINT64                           *Attributes OPTIONAL,
  OUT EFI_HANDLE                       *DataHandle
  );

/**
  Creates a new verified policy data structure.

  @param[in]  Descriptor    The descriptor of the verified policy data structure
                            to be created.

  @param[out] DataHandle    The handle to the newly created verified policy data
                            structure.

  @retval     EFI_SUCCESS           The data structure was successfully created.
  @retval     EFI_OUT_OF_RESOURCES  Failed to allocate memory.
**/
RETURN_STATUS
EFIAPI
CreateVerifiedPolicy (
  IN CONST VERIFIED_POLICY_DESCRIPTOR  *Descriptor,
  OUT EFI_HANDLE                       *DataHandle
  );

/**
  Write a verified policy to the policy store.

  @param[in]    PolicyGuid      The GUID of policy in the policy store.

  @param[in]    Attributes      The attributes to set in the policy store.

  @param[in]    DataHandle      The handle to the policy data.

  @retval   EFI_SUCCESS               The policy was successfully retrieved.
  @retval   EFI_INVALID_PARAMETER     DataHandle is NULL.
  @retval   EFI_BAD_BUFFER_SIZE       The policy is too large.
**/
RETURN_STATUS
EFIAPI
SetVerifiedPolicy (
  IN CONST EFI_GUID  *PolicyGuid,
  IN UINT64          Attributes,
  IN EFI_HANDLE      DataHandle
  );

/**
  Closes a policy data handle.

  @param[in]    DataHandle      The policy handle to be closed.

  @retval       EFI_SUCCESS             The policy handle was successfully
                                        closed.
  @retval       EFI_INVALID_PARAMETER   The data handle is NULL.
**/
RETURN_STATUS
EFIAPI
CloseVerifiedPolicy (
  IN EFI_HANDLE  DataHandle
  );

/**
  Records access to a policy data structure used by autogenerated code. This
  function should not be manually called.

  @param[in]    DataHandle      The policy handle where the access was made.
  @param[in]    CallerGuid      The file guid of the caller for tracking access.
  @param[in]    Offset          The offset into the policy data for the access.
  @param[in]    Size            The size of the access.
  @param[in]    Write           Indicates if the policy was written to.

**/
VOID
EFIAPI
ReportVerifiedPolicyAccess (
  IN EFI_HANDLE      DataHandle,
  IN CONST EFI_GUID  *CallerGuid,
  IN UINT32          Offset,
  IN UINT32          Size,
  IN BOOLEAN         Write
  );

#endif