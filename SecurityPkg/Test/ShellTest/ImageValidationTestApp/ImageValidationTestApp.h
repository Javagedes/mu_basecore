/** @file
  Header for the Image Validation unit test application.

  Defines the data structures and helpers used to drive high level secure boot image
  validation scenarios. Each scenario points the GetVariable() hook at a `db` / `dbx`
  signature database, selects one of the built-in PE/COFF images, calls gBS->LoadImage(),
  and asserts the EFI_STATUS LoadImage() returns.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef IMAGE_VALIDATION_TEST_APP_H_
#define IMAGE_VALIDATION_TEST_APP_H_

#include <Uefi.h>
#include <Library/UnitTestLib.h>

///
/// Selects which built-in PE/COFF image a scenario loads. The scenario runner converts this
/// into the corresponding image buffer and size.
///
typedef enum {
  IMAGE_TYPE_UNSIGNED,      ///< A valid but unsigned PE/COFF image.
  IMAGE_TYPE_SIGNED,        ///< An Authenticode-signed image (one signature).
  IMAGE_TYPE_DUAL_SIGNED,   ///< An image carrying two signatures.
  IMAGE_TYPE_MAX
} IMAGE_TYPE;

///
/// Bit flags describing the contents of a `db` or `dbx` signature database. The scenario
/// runner builds a serialized set of EFI_SIGNATURE_LISTs from these flags.
///
#define DB_STATE_EMPTY         0x00000000  ///< No signature lists (absent variable).
#define DB_STATE_IMAGE_DIGEST  0x00000001  ///< Include the loaded image's digest (EFI_CERT_SHA256_GUID).
#define DB_STATE_SIGNER1_LEAF_CERT          0x00000002  ///< Include signer 1 leaf certificate (EFI_CERT_X509_GUID).
#define DB_STATE_SIGNER1_INTERMEDIATE_CERT  0x00000004  ///< Include signer 1 intermediate (inner) CA certificate.
#define DB_STATE_SIGNER1_ROOT_CERT          0x00000008  ///< Include signer 1 root CA certificate.
#define DB_STATE_SIGNER2_CERT               0x00000010  ///< Include signer 2 certificate (dual-signed only).
#define DB_STATE_SIGNER1_LEAF_TBS_HASH          0x00000020  ///< Include signer 1 leaf TBS SHA-256 hash (EFI_CERT_X509_SHA256_GUID).
#define DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH  0x00000040  ///< Include signer 1 intermediate TBS SHA-256 hash.
#define DB_STATE_SIGNER1_ROOT_TBS_HASH          0x00000080  ///< Include signer 1 root TBS SHA-256 hash.
#define DB_STATE_SIGNER2_TBS_HASH               0x00000100  ///< Include signer 2 TBS SHA-256 hash (dual-signed only).

///
/// Describes a single secure boot image validation scenario.
///
typedef struct {
  ///
  /// Which built-in image to load (see IMAGE_TYPE).
  ///
  IMAGE_TYPE      ImageType;
  ///
  /// DB_STATE_* flags describing the contents of the `db` database to build.
  ///
  UINT32          DbState;
  ///
  /// DB_STATE_* flags describing the contents of the `dbx` database to build.
  ///
  UINT32          DbxState;
  ///
  /// EFI_STATUS gBS->LoadImage() is expected to return for this scenario.
  ///
  EFI_STATUS      ExpectedStatus;
} SECURE_BOOT_IMAGE_TEST_SCENARIO;

/**
  Convenience initializer for a SECURE_BOOT_IMAGE_TEST_SCENARIO.

  Scenario descriptions are always auto-generated from DbState, DbxState, and
  ExpectedStatus at test-suite registration time. This macro keeps scenario definitions
  concise while preserving tabular readability.
**/
#define TEST_SCENARIO(ImageType, DbState, DbxState, ExpectedStatus)  \
  {                                                                   \
    (ImageType),                                                      \
    (DbState),                                                        \
    (DbxState),                                                       \
    (ExpectedStatus)                                                  \
  }

///
/// A named group of scenarios registered together as one unit test suite. The suites (one
/// per image type) are defined in Scenarios.c.
///
typedef struct {
  ///
  /// Suite title shown in the report (user presentation).
  ///
  CONST CHAR8                            *Title;
  ///
  /// Suite class name for xUnit-style reporting (e.g. "SecurityPkg.ImageValidation.Signed").
  ///
  CONST CHAR8                            *ClassName;
  ///
  /// The scenarios that belong to this suite.
  ///
  CONST SECURE_BOOT_IMAGE_TEST_SCENARIO  *Scenarios;
  ///
  /// Number of entries in Scenarios.
  ///
  UINTN                                  ScenarioCount;
} SECURE_BOOT_TEST_SUITE;

//
// The image validation suites (unsigned, signed, dual-signed), defined in Scenarios.c.
//
extern CONST SECURE_BOOT_TEST_SUITE  mTestSuites[];
extern CONST UINTN                   mTestSuiteCount;

/**
  Unit test body that drives a single secure boot image validation scenario.

  This function is registered as the test case routine for every scenario. It reads the
  SECURE_BOOT_IMAGE_TEST_SCENARIO passed through Context, resolves the image from ImageType,
  builds `db` / `dbx` from the DbState / DbxState flags, points the GetVariable() hook at
  those databases, calls gBS->LoadImage() on the image, unloads the image if it loaded, and
  asserts that the returned EFI_STATUS matches SECURE_BOOT_IMAGE_TEST_SCENARIO.ExpectedStatus.

  @param[in]  Context  A pointer to the SECURE_BOOT_IMAGE_TEST_SCENARIO that describes the
                       inputs and expected result.

  @retval  UNIT_TEST_PASSED             LoadImage() returned the expected status.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  LoadImage() returned an unexpected status.
**/
UNIT_TEST_STATUS
EFIAPI
RunImageValidationScenario (
  IN UNIT_TEST_CONTEXT  Context
  );

#endif // IMAGE_VALIDATION_TEST_APP_H_
