/** @file
  Internal declarations for the DXE Image Verification Library.

  This header is consumed by the library's source files (and its unit
  tests) to share prototypes for the constructor and the Security2
  verification handler.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_H_
#define DXE_IMAGE_VERIFICATION_LIB_H_

#include <Uefi.h>
#include <UefiSecureBoot.h>
#include <Guid/ImageAuthentication.h>
#include <IndustryStandard/PeImage.h>
#include <Library/SecureBootVariableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/SecurityManagementLib.h>
#include <Pi/PiFirmwareFile.h>
#include <Pi/PiFirmwareVolume.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/DevicePath.h>

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

#define MAX_DIGEST_SIZE  SHA512_DIGEST_SIZE

//
// Type definition for all information necessary to describe hash algorithm usage in this library.
//
typedef struct {
  CONST CHAR8       *Name;
  CONST EFI_GUID    *ImageHashGuid;
  CONST EFI_GUID    *X509CertHashGuid;
} HASH_ALGORITHM;

//
// All supported hash algorithms for secureboot validation. Adding a new algorithm to this list
// will add support for that algorithm across the entire library.
//
STATIC CONST HASH_ALGORITHM  mHashAlgorithms[] = {
  { "SHA256", &gEfiCertSha256Guid, &gEfiCertX509Sha256Guid },
  { "SHA384", &gEfiCertSha384Guid, &gEfiCertX509Sha384Guid },
  { "SHA512", &gEfiCertSha512Guid, &gEfiCertX509Sha512Guid },
};

//
// The `db` authority that authorized an image. Data references the
// EFI_SIGNATURE_DATA entry inside the signature database that authorized the
// image; Data is NULL and Size is 0 when no authority was found.
//
typedef struct {
  CONST EFI_SIGNATURE_DATA    *Data;
  UINTN                       Size;
} IMAGE_AUTHORITY;

//
// A single Secure Boot authority entry that has been measured into PCR 7.
// VariableName / VendorGuid reference canonical storage owned by the library;
// Data is a pool-allocated copy of the EFI_SIGNATURE_DATA that authorized an
// image.
//
typedef struct {
  CHAR16      *VariableName;
  EFI_GUID    *VendorGuid;
  VOID        *Data;
  UINTN       Size;
} MEASURED_VARIABLE;

//
// Tracks the set of authority entries that have been measured into PCR 7
// during this boot so that no single entry is measured more than once. The
// only instance of this structure is the module global owned by Measurement.c
// and obtained through GetMeasuredAuthorities ().
//
typedef struct {
  MEASURED_VARIABLE    *List;
  UINTN                Count;
  UINTN                Max;
} MEASURED_AUTHORITIES;

/**
  Return the module-global authority measurement state.

  The returned pointer references storage that persists for the lifetime of
  the module so that measurement de-duplication is maintained across every
  image the verification handler processes.

  @return  Pointer to the module-global MEASURED_AUTHORITIES instance.
**/
MEASURED_AUTHORITIES *
GetMeasuredAuthorities (
  VOID
  );

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

/**
  Provide verification service for signed images, which include both signature validation
  and platform policy control. For signature types, both UEFI WIN_CERTIFICATE_UEFI_GUID and
  MSFT Authenticode type signatures are supported.

  In this implementation, only verify external executables when in USER MODE.
  Executables from FV is bypass, so pass in AuthenticationStatus is ignored.

  The image verification policy is:
    If the image is signed,
      At least one valid signature or at least one hash value of the image must match a record
      in the security database "db", and no valid signature nor any hash value of the image may
      be reflected in the security database "dbx".
    Otherwise, the image is not signed,
      The hash value of the image must match a record in the security database "db", and
      not be reflected in the security data base "dbx".

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its data structure
  within this image buffer before use.

  @param[in]    AuthenticationStatus
                           This is the authentication status returned from the security
                           measurement services for the input file.
  @param[in]    File       This is a pointer to the device path of the file that is
                           being dispatched. This will optionally be used for logging.
  @param[in]    FileBuffer File buffer matches the input file device path.
  @param[in]    FileSize   Size of File buffer matches the input file device path.
  @param[in]    BootPolicy A boot policy that was used to call LoadImage() UEFI service.

  @retval EFI_SUCCESS            The file specified by DevicePath and non-NULL
                                 FileBuffer did authenticate, and the platform policy dictates
                                 that the DXE Foundation may use the file.
  @retval EFI_SUCCESS            The device path specified by NULL device path DevicePath
                                 and non-NULL FileBuffer did authenticate, and the platform
                                 policy dictates that the DXE Foundation may execute the image in
                                 FileBuffer.
  @retval EFI_ACCESS_DENIED      The file specified by File and FileBuffer did not
                                 authenticate, and the DXE Foundation may not use File. The
                                 image has been added to the file execution table.

**/
EFI_STATUS
EFIAPI
DxeImageVerificationHandler (
  IN  UINT32                          AuthenticationStatus,
  IN  CONST EFI_DEVICE_PATH_PROTOCOL  *File  OPTIONAL,
  IN  VOID                            *FileBuffer,
  IN  UINTN                           FileSize,
  IN  BOOLEAN                         BootPolicy
  );

/**
  Register security measurement handler.

  @param  ImageHandle   ImageHandle of the loaded driver.
  @param  SystemTable   Pointer to the EFI System Table.

  @retval EFI_SUCCESS   The handlers were registered successfully.
**/
EFI_STATUS
EFIAPI
DxeImageVerificationLibConstructor (
  IN  EFI_HANDLE        ImageHandle,
  IN  EFI_SYSTEM_TABLE  *SystemTable
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_H_
