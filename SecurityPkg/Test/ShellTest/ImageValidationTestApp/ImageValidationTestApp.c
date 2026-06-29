/** @file
  Image Validation unit test application.

  This UEFI application exercises the platform's secure boot image Validation at a high
  level. For each scenario it:
    1. Installs a GetVariable() hook that returns scenario-specific `db` and `dbx`
       signature databases and reports `SecureBoot` as enabled (so the handler enforces
       Validation), falling back to the real GetVariable() for all other variables.
    2. Calls gBS->LoadImage() on a built-in PE/COFF image. On a platform with Secure Boot
       enabled, the DXE core invokes the registered image Validation handler, which reads
       the `db` / `dbx` served by the hook.
    3. Asserts that LoadImage() returns the expected EFI_STATUS.

  Because Validation is performed by the platform's already-registered handler (reached
  through gBS->LoadImage()), the application itself needs no security or cryptography
  libraries.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UnitTestLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Guid/ImageAuthentication.h>
#include <Guid/GlobalVariable.h>
#include <Protocol/DevicePath.h>

#include "ImageValidationTestApp.h"
#include "TestData.h"

#define UNIT_TEST_NAME     "Image Validation Test App"
#define UNIT_TEST_VERSION  "0.1"

//
// SignatureOwner GUID stamped into every EFI_SIGNATURE_DATA this test builds.
//
STATIC CONST EFI_GUID  mTestSignatureOwner = {
  0x6f9a1c44, 0x2d8b, 0x4e3a, { 0x9b, 0x21, 0x0c, 0x7d, 0x5e, 0x14, 0xa8, 0x3f }
};


//
// A fake device path to result in an unknown image source allowing the Image Validation handler
// to be fully invoked.
//
#pragma pack (1)
typedef struct {
  MEMMAP_DEVICE_PATH          MemMap;
  EFI_DEVICE_PATH_PROTOCOL    End;
} TEST_IMAGE_DEVICE_PATH;
#pragma pack ()

STATIC TEST_IMAGE_DEVICE_PATH  mTestImageDevicePath = {
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_MEMMAP_DP,
      { (UINT8)sizeof (MEMMAP_DEVICE_PATH), (UINT8)(sizeof (MEMMAP_DEVICE_PATH) >> 8) }
    },
    EfiBootServicesData,
    0,
    0
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { (UINT8)sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 }
  }
};

//
// GetVariable() hook state.
//
// mOriginalGetVariable holds the runtime services GetVariable() that was present before the
// hook was installed; the hook chains to it for every variable it does not synthesize.
// mActiveDb / mActiveDbx point at the `db` / `dbx` databases the scenario runner built for
// the test currently executing, so the hook knows what to return for those two variables.
//
STATIC EFI_GET_VARIABLE  mOriginalGetVariable = NULL;
STATIC CONST UINT8       *mActiveDb           = NULL;
STATIC UINTN             mActiveDbSize        = 0;
STATIC CONST UINT8       *mActiveDbx          = NULL;
STATIC UINTN             mActiveDbxSize       = 0;

//
// Value served for the `SecureBoot` variable. The Validation handler skips Validation
// (returns EFI_SUCCESS) when `SecureBoot` is absent or disabled, so the hook always reports
// it enabled to force the handler down the real signature/hash validation path regardless
// of the platform's actual state.
//
STATIC CONST UINT8  mSecureBootEnabled = SECURE_BOOT_MODE_ENABLE;


/**
  Copy the source buffer holding a variable value into the caller's buffer.

  Update the attributes and data size as needed.

  @param[in]      Source            Buffer holding the variable value, or NULL if the
                                    variable does not exist.
  @param[in]      SourceSize        Size, in bytes, of Source.
  @param[in]      SourceAttributes  Attributes to report for the variable.
  @param[out]     Attributes        Optional. Receives SourceAttributes.
  @param[in, out] DataSize          On input, the size of Data. On output, the size of the
                                    variable value.
  @param[out]     Data              Optional. Receives the variable value.

  @retval EFI_SUCCESS            The value was returned in Data.
  @retval EFI_NOT_FOUND          Source is NULL or SourceSize is 0.
  @retval EFI_BUFFER_TOO_SMALL   Data was too small; DataSize has been updated.
  @retval EFI_INVALID_PARAMETER  Data was NULL but the buffer was large enough.
**/
STATIC
EFI_STATUS
ServeVariable (
  IN     CONST UINT8  *Source,
  IN     UINTN        SourceSize,
  IN     UINT32       SourceAttributes,
  OUT    UINT32       *Attributes  OPTIONAL,
  IN OUT UINTN        *DataSize,
  OUT    VOID         *Data         OPTIONAL
  )
{
  if ((Source == NULL) || (SourceSize == 0)) {
    return EFI_NOT_FOUND;
  }

  if (Attributes != NULL) {
    *Attributes = SourceAttributes;
  }

  if (*DataSize < SourceSize) {
    *DataSize = SourceSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if (Data == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Data, Source, SourceSize);
  *DataSize = SourceSize;
  return EFI_SUCCESS;
}

/**
  GetVariable() hook that returns scenario-specific secure boot databases instead of the real ones.

  Falls back to the original GetVariable() implementation for all other variables.

  @param[in]      VariableName  The name of the variable to read.
  @param[in]      VendorGuid    The vendor GUID of the variable.
  @param[out]     Attributes    Optional. Receives the variable attributes.
  @param[in, out] DataSize      On input, the size of Data; on output, the size of the
                                variable value.
  @param[out]     Data          Optional. Receives the variable value.

  @return The status of the synthesized or forwarded GetVariable() call.
**/
STATIC
EFI_STATUS
EFIAPI
HookedGetVariable (
  IN     CHAR16    *VariableName,
  IN     EFI_GUID  *VendorGuid,
  OUT    UINT32    *Attributes  OPTIONAL,
  IN OUT UINTN     *DataSize,
  OUT    VOID      *Data         OPTIONAL
  )
{
  if ((VariableName == NULL) || (VendorGuid == NULL) || (DataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE) == 0) &&
      CompareGuid (VendorGuid, &gEfiImageSecurityDatabaseGuid))
  {
    return ServeVariable (
             mActiveDb,
             mActiveDbSize,
             EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
             Attributes,
             DataSize,
             Data
             );
  }

  if ((StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE1) == 0) &&
      CompareGuid (VendorGuid, &gEfiImageSecurityDatabaseGuid))
  {
    return ServeVariable (
             mActiveDbx,
             mActiveDbxSize,
             EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
             Attributes,
             DataSize,
             Data
             );
  }

  if ((StrCmp (VariableName, EFI_SECURE_BOOT_MODE_NAME) == 0) &&
      CompareGuid (VendorGuid, &gEfiGlobalVariableGuid))
  {
    //
    // Force Secure Boot to appear enabled so the Validation handler enforces
    // Validation instead of short-circuiting to EFI_SUCCESS.
    //
    return ServeVariable (
             &mSecureBootEnabled,
             sizeof (mSecureBootEnabled),
             EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
             Attributes,
             DataSize,
             Data
             );
  }

  return mOriginalGetVariable (VariableName, VendorGuid, Attributes, DataSize, Data);
}


/**
  Install the GetVariable() hook.
**/
STATIC
VOID
InstallGetVariableHook (
  VOID
  )
{
  if (mOriginalGetVariable == NULL) {
    mOriginalGetVariable  = gRT->GetVariable;
    gRT->GetVariable      = HookedGetVariable;
  }
}

/**
  Restore the original GetVariable() implementation.
**/
STATIC
VOID
RestoreGetVariableHook (
  VOID
  )
{
  if (mOriginalGetVariable != NULL) {
    gRT->GetVariable      = mOriginalGetVariable;
    mOriginalGetVariable  = NULL;
  }

  mActiveDb      = NULL;
  mActiveDbSize  = 0;
  mActiveDbx     = NULL;
  mActiveDbxSize = 0;
}

/**
  Convert a DB_STATE combination to a human-readable string.

  This function builds a comma-separated list of the individual state names (e.g.,
  "Image Digest, Leaf, Root"). An empty state (DB_STATE_EMPTY) returns "Empty".

  @param[in]  DbState  A combination of DB_STATE_* flags.
  @param[out] Buffer   A caller-allocated string buffer to receive the result.
  @param[in]  BufSize  The size, in bytes, of Buffer.

  @retval EFI_SUCCESS        The description was written to Buffer.
  @retval EFI_BUFFER_TOO_SMALL  Buffer was too small for the description.
**/
STATIC
EFI_STATUS
DbStateToString (
  IN  UINT32  DbState,
  OUT CHAR8   *Buffer,
  IN  UINTN   BufSize
  )
{
  typedef struct {
    UINT32  Flag;
    CONST CHAR8 *Name;
  } DB_STATE_NAME_ENTRY;

  CONST DB_STATE_NAME_ENTRY  StateNames[] = {
    { DB_STATE_IMAGE_DIGEST, "Image Digest" },
    { DB_STATE_SIGNER1_LEAF_CERT, "Signer 1 Leaf Cert" },
    { DB_STATE_SIGNER1_INTERMEDIATE_CERT, "Signer 1 Intermediate Cert" },
    { DB_STATE_SIGNER1_ROOT_CERT, "Signer 1 Root Cert" },
    { DB_STATE_SIGNER2_CERT, "Signer 2 Cert" },
    { DB_STATE_SIGNER1_LEAF_TBS_HASH, "Signer 1 Leaf TBS Hash" },
    { DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH, "Signer 1 Intermediate TBS Hash" },
    { DB_STATE_SIGNER1_ROOT_TBS_HASH, "Signer 1 Root TBS Hash" },
    { DB_STATE_SIGNER2_TBS_HASH, "Signer 2 TBS Hash" }
  };

  UINTN  Index;
  UINTN  Offset;
  UINTN  NameLen;
  BOOLEAN  FirstFlag;

  if ((Buffer == NULL) || (BufSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  if (DbState == DB_STATE_EMPTY) {
    if (BufSize < 6) {
      return EFI_BUFFER_TOO_SMALL;
    }
    AsciiStrCpyS (Buffer, BufSize, "Empty");
    return EFI_SUCCESS;
  }

  Offset    = 0;
  FirstFlag = TRUE;

  for (Index = 0; Index < ARRAY_SIZE (StateNames); Index++) {
    if ((DbState & StateNames[Index].Flag) != 0) {
      NameLen = AsciiStrLen (StateNames[Index].Name);

      // Account for separator (", ") if not the first flag
      if (!FirstFlag) {
        NameLen += 2;  // for ", "
      }

      if (Offset + NameLen >= BufSize) {
        return EFI_BUFFER_TOO_SMALL;
      }

      if (FirstFlag) {
        //
        // For the first flag, copy the name directly (initializes buffer).
        //
        AsciiStrCpyS (Buffer, BufSize, StateNames[Index].Name);
        FirstFlag = FALSE;
      } else {
        //
        // For subsequent flags, append with a separator.
        //
        AsciiStrCatS (Buffer, BufSize, ", ");
        AsciiStrCatS (Buffer, BufSize, StateNames[Index].Name);
      }

      Offset += NameLen;
    }
  }

  return EFI_SUCCESS;
}

/**
  Convert an EFI_STATUS value to a human-readable string for test reporting.

  @param[in]  Status  The EFI_STATUS to convert.

  @return A pointer to a constant string describing the status.
**/
STATIC
CONST CHAR8 *
StatusToString (
  IN EFI_STATUS  Status
  )
{
  switch (Status) {
    case EFI_SUCCESS:
      return "Approved";
    case EFI_ACCESS_DENIED:
      return "Denied";
    case EFI_SECURITY_VIOLATION:
      return "Security Violation";
    default:
      return "Unknown";
  }
}

/**
  Generate a scenario description from the database states and expected result.

  This function builds a concise scenario name in the format:
  "DB: [<DB state>], DBX: [<DBX state>], Expected: <Expected result>"

  @param[in]  DbState        The DB_STATE_* flags for the `db` database.
  @param[in]  DbxState       The DB_STATE_* flags for the `dbx` database.
  @param[in]  ExpectedStatus The expected EFI_STATUS from LoadImage().
  @param[out] Buffer         A caller-allocated string buffer to receive the result.
  @param[in]  BufSize        The size, in bytes, of Buffer.

  @retval EFI_SUCCESS        The description was written to Buffer.
  @retval EFI_BUFFER_TOO_SMALL  Buffer was too small for the description.
**/
STATIC
EFI_STATUS
GenerateScenarioDescription (
  IN  UINT32  DbState,
  IN  UINT32  DbxState,
  IN  EFI_STATUS  ExpectedStatus,
  OUT CHAR8   *Buffer,
  IN  UINTN   BufSize
  )
{
  CHAR8      DbString[128];
  CHAR8      DbxString[128];
  CONST CHAR8 *StatusString;
  EFI_STATUS Status;

  if ((Buffer == NULL) || (BufSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  // Convert DB state to string
  Status = DbStateToString (DbState, DbString, sizeof (DbString));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Convert DBX state to string
  Status = DbStateToString (DbxState, DbxString, sizeof (DbxString));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Get status string
  StatusString = StatusToString (ExpectedStatus);

  // Build the final description with labeled DB/DBX/Expected fields.
  Status = AsciiSPrint (
             Buffer,
             BufSize,
             "DB: [%a], DBX: [%a], Expected: %a",
             DbString,
             DbxString,
             StatusString
             );

  return Status;
}

/**
  Resolve a scenario's IMAGE_TYPE into the matching built-in image buffer.

  @param[in]   ImageType  The image selector from the scenario.
  @param[out]  Image      Receives a pointer to the image buffer.
  @param[out]  ImageSize  Receives the size, in bytes, of the image buffer.

  @retval EFI_SUCCESS            The image was resolved.
  @retval EFI_INVALID_PARAMETER  ImageType was not a recognized value.
**/
STATIC
EFI_STATUS
GetImageForType (
  IN  IMAGE_TYPE   ImageType,
  OUT CONST UINT8  **Image,
  OUT UINTN        *ImageSize
  )
{
  switch (ImageType) {
    case IMAGE_TYPE_UNSIGNED:
      *Image     = mUnsignedImage;
      *ImageSize = mUnsignedImageSize;
      return EFI_SUCCESS;
    case IMAGE_TYPE_SIGNED:
      *Image     = mSignedImage;
      *ImageSize = mSignedImageSize;
      return EFI_SUCCESS;
    case IMAGE_TYPE_DUAL_SIGNED:
      *Image     = mDualSignedImage;
      *ImageSize = mDualSignedImageSize;
      return EFI_SUCCESS;
    default:
      return EFI_INVALID_PARAMETER;
  }
}

/**
  Resolve a scenario's IMAGE_TYPE into the matching Authenticode image digest.

  @param[in]   ImageType   The image selector from the scenario.
  @param[out]  Digest      Receives a pointer to the digest bytes.
  @param[out]  DigestSize  Receives the size, in bytes, of the digest.

  @retval EFI_SUCCESS            The digest was resolved.
  @retval EFI_INVALID_PARAMETER  ImageType was not a recognized value.
**/
STATIC
EFI_STATUS
GetImageDigestForType (
  IN  IMAGE_TYPE   ImageType,
  OUT CONST UINT8  **Digest,
  OUT UINTN        *DigestSize
  )
{
  switch (ImageType) {
    case IMAGE_TYPE_UNSIGNED:
      *Digest     = mUnsignedImageDigest;
      *DigestSize = mUnsignedImageDigestSize;
      return EFI_SUCCESS;
    case IMAGE_TYPE_SIGNED:
      *Digest     = mSignedImageDigest;
      *DigestSize = mSignedImageDigestSize;
      return EFI_SUCCESS;
    case IMAGE_TYPE_DUAL_SIGNED:
      *Digest     = mDualSignedImageDigest;
      *DigestSize = mDualSignedImageDigestSize;
      return EFI_SUCCESS;
    default:
      return EFI_INVALID_PARAMETER;
  }
}

///
/// One signature list to emit while building a signature database.
///
typedef struct {
  CONST EFI_GUID  *Type;      ///< Signature type GUID (SHA-256 or X.509).
  CONST UINT8     *Data;      ///< Signature payload (digest bytes or certificate).
  UINTN           DataSize;   ///< Size, in bytes, of Data.
} SIG_LIST_SPEC;

/**
  Compute a certificate's TBSCertificate SHA-256 digest.

  @param[in]  Cert         DER-encoded X.509 certificate.
  @param[in]  CertSize     Size, in bytes, of Cert.
  @param[out] TbsHash      Receives the 32-byte SHA-256 digest.
  @param[in]  TbsHashSize  Size of TbsHash; must be SHA256_DIGEST_SIZE.

  @retval EFI_SUCCESS            The digest was computed.
  @retval EFI_INVALID_PARAMETER  A required pointer was NULL or output size was invalid.
  @retval EFI_ABORTED            TBSCertificate extraction or hashing failed.
**/
STATIC
EFI_STATUS
ComputeTbsCertSha256 (
  IN  CONST UINT8  *Cert,
  IN  UINTN        CertSize,
  OUT UINT8        *TbsHash,
  IN  UINTN        TbsHashSize
  )
{
  UINT8  *TbsCert;
  UINTN  TbsCertSize;

  if ((Cert == NULL) || (TbsHash == NULL) || (TbsHashSize != SHA256_DIGEST_SIZE)) {
    return EFI_INVALID_PARAMETER;
  }

  if (!X509GetTBSCert (Cert, CertSize, &TbsCert, &TbsCertSize)) {
    return EFI_ABORTED;
  }

  if (!Sha256HashAll (TbsCert, TbsCertSize, TbsHash)) {
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}

/**
  Build a serialized set of EFI_SIGNATURE_LISTs from DB_STATE_* flags.

  Each set flag contributes one EFI_SIGNATURE_LIST holding a single EFI_SIGNATURE_DATA entry.

  The caller owns the returned buffer and must release it with FreeSignatureDatabase().

  @param[in]   StateFlags     Bitwise-OR of DB_STATE_* values.
  @param[in]   ImageType      The image whose digest to use for
                              DB_STATE_IMAGE_DIGEST.
  @param[out]  Database       Receives the allocated database buffer, or NULL when
                              StateFlags is DB_STATE_EMPTY.
  @param[out]  DatabaseSize   Receives the size, in bytes, of the database.

  @retval EFI_SUCCESS            The database was built (possibly empty).
  @retval EFI_INVALID_PARAMETER  ImageType was invalid.
  @retval EFI_OUT_OF_RESOURCES   The database buffer could not be allocated.
**/
STATIC
EFI_STATUS
BuildSignatureDatabase (
  IN  UINT32      StateFlags,
  IN  IMAGE_TYPE  ImageType,
  OUT UINT8       **Database,
  OUT UINTN       *DatabaseSize
  )
{
  SIG_LIST_SPEC       Specs[10];
  UINTN               Count;
  UINTN               Index;
  UINTN               TotalSize;
  UINT8               *Buffer;
  UINT8               *Cursor;
  CONST UINT8         *Digest;
  UINTN               DigestSize;
  EFI_STATUS          Status;
  UINT8               LeafTbsHash[SHA256_DIGEST_SIZE];
  UINT8               IntermediateTbsHash[SHA256_DIGEST_SIZE];
  UINT8               RootTbsHash[SHA256_DIGEST_SIZE];
  UINT8               Signer2TbsHash[SHA256_DIGEST_SIZE];
  EFI_SIGNATURE_LIST  *List;
  EFI_SIGNATURE_DATA  *SigData;

  *Database     = NULL;
  *DatabaseSize = 0;
  Count         = 0;

  if (StateFlags == DB_STATE_EMPTY) {
    return EFI_SUCCESS;
  }

  if ((StateFlags & DB_STATE_IMAGE_DIGEST) != 0) {
    Status = GetImageDigestForType (ImageType, &Digest, &DigestSize);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Specs[Count].Type     = &gEfiCertSha256Guid;
    Specs[Count].Data     = Digest;
    Specs[Count].DataSize = DigestSize;
    Count++;
  }

  if ((StateFlags & DB_STATE_SIGNER1_LEAF_CERT) != 0) {
    Specs[Count].Type     = &gEfiCertX509Guid;
    Specs[Count].Data     = mLeafCert;
    Specs[Count].DataSize = mLeafCertSize;
    Count++;
  }

  if ((StateFlags & DB_STATE_SIGNER1_INTERMEDIATE_CERT) != 0) {
    Specs[Count].Type     = &gEfiCertX509Guid;
    Specs[Count].Data     = mIntermediateCert;
    Specs[Count].DataSize = mIntermediateCertSize;
    Count++;
  }

  if ((StateFlags & DB_STATE_SIGNER1_ROOT_CERT) != 0) {
    Specs[Count].Type     = &gEfiCertX509Guid;
    Specs[Count].Data     = mRootCert;
    Specs[Count].DataSize = mRootCertSize;
    Count++;
  }

  if ((StateFlags & DB_STATE_SIGNER2_CERT) != 0) {
    Specs[Count].Type     = &gEfiCertX509Guid;
    Specs[Count].Data     = mSigner2Cert;
    Specs[Count].DataSize = mSigner2CertSize;
    Count++;
  }

  if ((StateFlags & DB_STATE_SIGNER1_LEAF_TBS_HASH) != 0) {
    Status = ComputeTbsCertSha256 (mLeafCert, mLeafCertSize, LeafTbsHash, sizeof (LeafTbsHash));
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Specs[Count].Type     = &gEfiCertX509Sha256Guid;
    Specs[Count].Data     = LeafTbsHash;
    Specs[Count].DataSize = sizeof (LeafTbsHash);
    Count++;
  }

  if ((StateFlags & DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH) != 0) {
    Status = ComputeTbsCertSha256 (mIntermediateCert, mIntermediateCertSize, IntermediateTbsHash, sizeof (IntermediateTbsHash));
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Specs[Count].Type     = &gEfiCertX509Sha256Guid;
    Specs[Count].Data     = IntermediateTbsHash;
    Specs[Count].DataSize = sizeof (IntermediateTbsHash);
    Count++;
  }

  if ((StateFlags & DB_STATE_SIGNER1_ROOT_TBS_HASH) != 0) {
    Status = ComputeTbsCertSha256 (mRootCert, mRootCertSize, RootTbsHash, sizeof (RootTbsHash));
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Specs[Count].Type     = &gEfiCertX509Sha256Guid;
    Specs[Count].Data     = RootTbsHash;
    Specs[Count].DataSize = sizeof (RootTbsHash);
    Count++;
  }

  if ((StateFlags & DB_STATE_SIGNER2_TBS_HASH) != 0) {
    Status = ComputeTbsCertSha256 (mSigner2Cert, mSigner2CertSize, Signer2TbsHash, sizeof (Signer2TbsHash));
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Specs[Count].Type     = &gEfiCertX509Sha256Guid;
    Specs[Count].Data     = Signer2TbsHash;
    Specs[Count].DataSize = sizeof (Signer2TbsHash);
    Count++;
  }

  TotalSize = 0;
  for (Index = 0; Index < Count; Index++) {
    TotalSize += sizeof (EFI_SIGNATURE_LIST) + sizeof (EFI_GUID) + Specs[Index].DataSize;
  }

  Buffer = AllocateZeroPool (TotalSize);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Cursor = Buffer;
  for (Index = 0; Index < Count; Index++) {
    List = (EFI_SIGNATURE_LIST *)Cursor;
    CopyGuid (&List->SignatureType, Specs[Index].Type);
    List->SignatureHeaderSize = 0;
    List->SignatureSize       = (UINT32)(sizeof (EFI_GUID) + Specs[Index].DataSize);
    List->SignatureListSize   = (UINT32)(sizeof (EFI_SIGNATURE_LIST) + List->SignatureSize);

    SigData = (EFI_SIGNATURE_DATA *)(List + 1);
    CopyGuid (&SigData->SignatureOwner, &mTestSignatureOwner);
    CopyMem (SigData->SignatureData, Specs[Index].Data, Specs[Index].DataSize);

    Cursor += List->SignatureListSize;
  }

  *Database     = Buffer;
  *DatabaseSize = TotalSize;
  return EFI_SUCCESS;
}

/**
  Release a database allocated by BuildSignatureDatabase().

  @param[in]  Database  The database buffer, which may be NULL.
**/
STATIC
VOID
FreeSignatureDatabase (
  IN UINT8  *Database
  )
{
  if (Database != NULL) {
    FreePool (Database);
  }
}

/**
  Unit test body that drives a single secure boot image validation scenario.

  See ImageValidationTestApp.h for the full contract.

  @param[in]  Context  A pointer to the SECURE_BOOT_IMAGE_TEST_SCENARIO that describes the
                       inputs and expected result.

  @retval  UNIT_TEST_PASSED             LoadImage() returned the expected status.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  LoadImage() returned an unexpected status.
**/
UNIT_TEST_STATUS
EFIAPI
RunImageValidationScenario (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  SECURE_BOOT_IMAGE_TEST_SCENARIO  *Scenario;
  EFI_STATUS                             Status;
  EFI_HANDLE                             LoadedImageHandle;
  CONST UINT8                            *Image;
  UINTN                                  ImageSize;
  UINT8                                  *Db;
  UINTN                                  DbSize;
  UINT8                                  *Dbx;
  UINTN                                  DbxSize;

  Scenario          = (SECURE_BOOT_IMAGE_TEST_SCENARIO *)Context;
  LoadedImageHandle = NULL;
  Db                = NULL;
  Dbx               = NULL;
  UT_ASSERT_NOT_NULL (Scenario);

  //
  // Resolve the image to load and build the db / dbx databases this scenario describes.
  //
  UT_ASSERT_NOT_EFI_ERROR (GetImageForType (Scenario->ImageType, &Image, &ImageSize));
  UT_ASSERT_NOT_EFI_ERROR (BuildSignatureDatabase (Scenario->DbState, Scenario->ImageType, &Db, &DbSize));
  UT_ASSERT_NOT_EFI_ERROR (BuildSignatureDatabase (Scenario->DbxState, Scenario->ImageType, &Dbx, &DbxSize));

  //
  // Point the GetVariable() hook at the databases just built so the platform's Validation
  // handler sees the db / dbx this scenario wants.
  //
  mActiveDb      = Db;
  mActiveDbSize  = DbSize;
  mActiveDbx     = Dbx;
  mActiveDbxSize = DbxSize;

  //
  // Load the built-in image from memory. On a Secure Boot enabled platform the DXE core
  // invokes the registered image Validation handler, which consults the db / dbx served by
  // our GetVariable() hook. The status returned here is the result of that Validation.
  //
  Status = gBS->LoadImage (
                  FALSE,
                  gImageHandle,
                  (EFI_DEVICE_PATH_PROTOCOL *)&mTestImageDevicePath,
                  (VOID *)Image,
                  ImageSize,
                  &LoadedImageHandle
                  );

  //
  // Detach the databases from the hook before freeing them so a stray GetVariable() call
  // can never observe a dangling pointer.
  //
  mActiveDb      = NULL;
  mActiveDbSize  = 0;
  mActiveDbx     = NULL;
  mActiveDbxSize = 0;

  FreeSignatureDatabase (Db);
  FreeSignatureDatabase (Dbx);

  //
  // LoadImage() may load an image yet still report EFI_SECURITY_VIOLATION (untrusted). In
  // every case where a handle was produced, unload it so the test leaves no image resident.
  //
  if (LoadedImageHandle != NULL) {
    gBS->UnloadImage (LoadedImageHandle);
  }

  UT_ASSERT_STATUS_EQUAL (Status, Scenario->ExpectedStatus);

  return UNIT_TEST_PASSED;
}

/**
  Initialize the unit test framework, register every image validation suite and its
  scenarios, and run them.

  @retval  EFI_SUCCESS           All test cases were dispatched.
  @retval  EFI_OUT_OF_RESOURCES  Resources were unavailable to initialize the unit tests.
**/
EFI_STATUS
EFIAPI
UefiTestMain (
  VOID
  )
{
  EFI_STATUS                     Status;
  UNIT_TEST_FRAMEWORK_HANDLE     Framework;
  UNIT_TEST_SUITE_HANDLE         SuiteHandle;
  CONST SECURE_BOOT_TEST_SUITE   *TestSuite;
  UINTN                          SuiteIndex;
  UINTN                          ScenarioIndex;

  Framework = NULL;

  DEBUG ((DEBUG_INFO, "%a v%a\n", UNIT_TEST_NAME, UNIT_TEST_VERSION));

  Status = InitUnitTestFramework (&Framework, UNIT_TEST_NAME, gEfiCallerBaseName, UNIT_TEST_VERSION);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in InitUnitTestFramework. Status = %r\n", Status));
    goto EXIT;
  }

  //
  // Register one suite per image type (unsigned, signed, dual-signed) and add each suite's
  // scenarios as test cases.
  //
  for (SuiteIndex = 0; SuiteIndex < mTestSuiteCount; SuiteIndex++) {
    TestSuite = &mTestSuites[SuiteIndex];

    Status = CreateUnitTestSuite (
               &SuiteHandle,
               Framework,
               (CHAR8 *)TestSuite->Title,
               (CHAR8 *)TestSuite->ClassName,
               NULL,
               NULL
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed in CreateUnitTestSuite for %a\n", TestSuite->Title));
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }

    for (ScenarioIndex = 0; ScenarioIndex < TestSuite->ScenarioCount; ScenarioIndex++) {
      CHAR8      ScenarioDescription[256];
      EFI_STATUS GenerateStatus;

      //
      // Always auto-generate the scenario description from DB state, DBX state, and
      // expected status.
      //
      GenerateStatus = GenerateScenarioDescription (
                         TestSuite->Scenarios[ScenarioIndex].DbState,
                         TestSuite->Scenarios[ScenarioIndex].DbxState,
                         TestSuite->Scenarios[ScenarioIndex].ExpectedStatus,
                         ScenarioDescription,
                         sizeof (ScenarioDescription)
                         );

      if (EFI_ERROR (GenerateStatus)) {
        DEBUG ((
          DEBUG_ERROR,
          "Failed to generate scenario description for suite %a scenario %u. Status=%r\n",
          TestSuite->Title,
          (UINT32)ScenarioIndex,
          GenerateStatus
          ));
        Status = GenerateStatus;
        goto EXIT;
      }

      AddTestCase (
        SuiteHandle,
        ScenarioDescription,
        "ImageValidationScenario",
        RunImageValidationScenario,
        NULL,
        NULL,
        (UNIT_TEST_CONTEXT)&TestSuite->Scenarios[ScenarioIndex]
        );
    }
  }

  //
  // Install the GetVariable() hook for the duration of the run, then restore it so the
  // application leaves the platform exactly as it found it.
  //
  InstallGetVariableHook ();
  Status = RunAllTestSuites (Framework);
  RestoreGetVariableHook ();

EXIT:
  if (Framework != NULL) {
    FreeUnitTestFramework (Framework);
  }

  return Status;
}

/**
  Standard UEFI entry point for the image Validation unit test application.

  @param[in]  ImageHandle  The firmware allocated handle for the EFI image.
  @param[in]  SystemTable  A pointer to the EFI System Table.

  @retval  EFI_SUCCESS  The entry point executed successfully.
  @retval  other        An error occurred while running the unit tests.
**/
EFI_STATUS
EFIAPI
DxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return UefiTestMain ();
}
