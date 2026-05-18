/** @file
  Unit tests for helpers in DxeImageVerificationLib's Certificate.{c,h}.

  GetCertificateData: constructs synthetic WIN_CERTIFICATE buffers and
  verifies parsing of the supported PKCS / PKCS#7 variants along with
  the malformed and unsupported cases.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>

#include <vector>
#include <cstring>

extern "C" {
  #include <Uefi.h>
  #include <IndustryStandard/PeImage.h>
  #include <Library/BaseMemoryLib.h>
  #include "../Certificate.h"
}

// ---------------------------------------------------------------------------
// GetCertificateData
// ---------------------------------------------------------------------------

class GetCertificateDataTest : public ::testing::Test { };

//
// Builds a WIN_CERT_TYPE_PKCS_SIGNED_DATA certificate buffer with the
// supplied payload bytes laid out immediately after the WIN_CERTIFICATE
// header. dwLength is set to the total buffer size.
//
static std::vector<UINT8>
BuildPkcsSignedDataCert (
  const std::vector<UINT8>  &Payload
  )
{
  std::vector<UINT8>  Buf (sizeof (WIN_CERTIFICATE) + Payload.size (), 0);
  WIN_CERTIFICATE     *Hdr = reinterpret_cast<WIN_CERTIFICATE *> (Buf.data ());

  Hdr->dwLength         = static_cast<UINT32> (Buf.size ());
  Hdr->wRevision        = 0x0200;
  Hdr->wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA;

  if (!Payload.empty ()) {
    std::memcpy (
           Buf.data () + sizeof (WIN_CERTIFICATE),
           Payload.data (),
           Payload.size ()
           );
  }

  return Buf;
}

//
// Builds a WIN_CERT_TYPE_EFI_GUID certificate buffer wrapping the given
// inner CertType. Payload bytes follow the CertType GUID. dwLength is
// set to the total buffer size.
//
static std::vector<UINT8>
BuildEfiGuidCert (
  const EFI_GUID            &CertType,
  const std::vector<UINT8>  &Payload
  )
{
  const UINTN                HdrSize = OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  std::vector<UINT8>         Buf (HdrSize + Payload.size (), 0);
  WIN_CERTIFICATE_UEFI_GUID  *Cert =
    reinterpret_cast<WIN_CERTIFICATE_UEFI_GUID *> (Buf.data ());

  Cert->Hdr.dwLength         = static_cast<UINT32> (Buf.size ());
  Cert->Hdr.wRevision        = 0x0200;
  Cert->Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
  CopyGuid (&Cert->CertType, &CertType);

  if (!Payload.empty ()) {
    std::memcpy (Buf.data () + HdrSize, Payload.data (), Payload.size ());
  }

  return Buf;
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

TEST_F (GetCertificateDataTest, NullWinCert_ReturnsInvalidParameter) {
  CONST VOID  *Data = nullptr;
  UINTN       Size  = 0;

  EXPECT_EQ (
    GetCertificateData (NULL, sizeof (WIN_CERTIFICATE), &Data, &Size),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (GetCertificateDataTest, NullCertData_ReturnsInvalidParameter) {
  std::vector<UINT8>  Cert = BuildPkcsSignedDataCert ({ 0xAA, 0xBB });
  UINTN               Size = 0;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      Cert.size (),
      NULL,
      &Size
      ),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (GetCertificateDataTest, NullCertDataSize_ReturnsInvalidParameter) {
  std::vector<UINT8>  Cert  = BuildPkcsSignedDataCert ({ 0xAA, 0xBB });
  CONST VOID          *Data = nullptr;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      Cert.size (),
      &Data,
      NULL
      ),
    EFI_INVALID_PARAMETER
    );
}

// ---------------------------------------------------------------------------
// Malformed inputs
// ---------------------------------------------------------------------------

TEST_F (GetCertificateDataTest, RemainingSmallerThanHeader_ReturnsCorrupted) {
  std::vector<UINT8>  Cert  = BuildPkcsSignedDataCert ({ 0xAA });
  CONST VOID          *Data = nullptr;
  UINTN               Size  = 0;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      sizeof (WIN_CERTIFICATE) - 1,
      &Data,
      &Size
      ),
    EFI_VOLUME_CORRUPTED
    );
  EXPECT_EQ (Data, nullptr);
  EXPECT_EQ (Size, (UINTN)0);
}

TEST_F (GetCertificateDataTest, DwLengthSmallerThanHeader_ReturnsCorrupted) {
  std::vector<UINT8>  Cert = BuildPkcsSignedDataCert ({ 0xAA });
  WIN_CERTIFICATE     *Hdr = reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ());

  Hdr->dwLength = sizeof (WIN_CERTIFICATE) - 1;

  CONST VOID  *Data = nullptr;
  UINTN       Size  = 0;

  EXPECT_EQ (
    GetCertificateData (Hdr, Cert.size (), &Data, &Size),
    EFI_VOLUME_CORRUPTED
    );
  EXPECT_EQ (Data, nullptr);
  EXPECT_EQ (Size, (UINTN)0);
}

TEST_F (GetCertificateDataTest, DwLengthExceedsRemainingSize_ReturnsCorrupted) {
  std::vector<UINT8>  Cert  = BuildPkcsSignedDataCert ({ 0xAA });
  CONST VOID          *Data = nullptr;
  UINTN               Size  = 0;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      Cert.size () - 1,
      &Data,
      &Size
      ),
    EFI_VOLUME_CORRUPTED
    );
  EXPECT_EQ (Data, nullptr);
  EXPECT_EQ (Size, (UINTN)0);
}

// ---------------------------------------------------------------------------
// WIN_CERT_TYPE_PKCS_SIGNED_DATA
// ---------------------------------------------------------------------------

TEST_F (GetCertificateDataTest, PkcsSignedData_ReturnsPayloadAndSize) {
  const std::vector<UINT8>  Payload { 0x11, 0x22, 0x33, 0x44, 0x55 };
  std::vector<UINT8>        Cert  = BuildPkcsSignedDataCert (Payload);
  CONST VOID                *Data = nullptr;
  UINTN                     Size  = 0;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      Cert.size (),
      &Data,
      &Size
      ),
    EFI_SUCCESS
    );
  EXPECT_EQ (
    Data,
    reinterpret_cast<CONST VOID *> (Cert.data () + sizeof (WIN_CERTIFICATE))
    );
  EXPECT_EQ (Size, Payload.size ());
  EXPECT_EQ (std::memcmp (Data, Payload.data (), Payload.size ()), 0);
}

TEST_F (GetCertificateDataTest, PkcsSignedData_DwLengthEqualsHeader_ReturnsCorrupted) {
  //
  // A PKCS_SIGNED_DATA certificate with dwLength == sizeof(WIN_CERTIFICATE)
  // carries no payload bytes and is rejected as malformed.
  //
  std::vector<UINT8>  Cert  = BuildPkcsSignedDataCert ({ });
  CONST VOID          *Data = nullptr;
  UINTN               Size  = 0;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      Cert.size (),
      &Data,
      &Size
      ),
    EFI_VOLUME_CORRUPTED
    );
  EXPECT_EQ (Data, nullptr);
  EXPECT_EQ (Size, (UINTN)0);
}

// ---------------------------------------------------------------------------
// WIN_CERT_TYPE_EFI_GUID
// ---------------------------------------------------------------------------

TEST_F (GetCertificateDataTest, EfiGuidPkcs7_ReturnsPayloadAndSize) {
  const std::vector<UINT8>  Payload { 0xAA, 0xBB, 0xCC, 0xDD };
  std::vector<UINT8>        Cert  = BuildEfiGuidCert (gEfiCertPkcs7Guid, Payload);
  CONST VOID                *Data = nullptr;
  UINTN                     Size  = 0;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      Cert.size (),
      &Data,
      &Size
      ),
    EFI_SUCCESS
    );
  EXPECT_EQ (
    Data,
    reinterpret_cast<CONST VOID *> (
                                    Cert.data () + OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)
                                    )
    );
  EXPECT_EQ (Size, Payload.size ());
  EXPECT_EQ (std::memcmp (Data, Payload.data (), Payload.size ()), 0);
}

TEST_F (GetCertificateDataTest, EfiGuidNonPkcs7_ReturnsUnsupported) {
  //
  // EFI_GUID-wrapped certificate whose inner CertType is not the PKCS#7
  // GUID must be reported as unsupported (and the outputs must remain
  // cleared).
  //
  std::vector<UINT8>  Cert  = BuildEfiGuidCert (gEfiCertX509Guid, { 0x01, 0x02, 0x03 });
  CONST VOID          *Data = nullptr;
  UINTN               Size  = 0;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      Cert.size (),
      &Data,
      &Size
      ),
    EFI_UNSUPPORTED
    );
  EXPECT_EQ (Data, nullptr);
  EXPECT_EQ (Size, (UINTN)0);
}

TEST_F (GetCertificateDataTest, EfiGuidDwLengthEqualsHeader_ReturnsCorrupted) {
  //
  // dwLength == OFFSET_OF(..., CertData) means there is no inner
  // payload at all; the certificate is malformed.
  //
  std::vector<UINT8>  Cert  = BuildEfiGuidCert (gEfiCertPkcs7Guid, { });
  CONST VOID          *Data = nullptr;
  UINTN               Size  = 0;

  EXPECT_EQ (
    GetCertificateData (
      reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ()),
      Cert.size (),
      &Data,
      &Size
      ),
    EFI_VOLUME_CORRUPTED
    );
  EXPECT_EQ (Data, nullptr);
  EXPECT_EQ (Size, (UINTN)0);
}

// ---------------------------------------------------------------------------
// Unknown certificate type
// ---------------------------------------------------------------------------

TEST_F (GetCertificateDataTest, UnknownCertificateType_ReturnsUnsupported) {
  std::vector<UINT8>  Cert = BuildPkcsSignedDataCert ({ 0x55 });
  WIN_CERTIFICATE     *Hdr = reinterpret_cast<WIN_CERTIFICATE *> (Cert.data ());

  Hdr->wCertificateType = 0x1234;

  CONST VOID  *Data = nullptr;
  UINTN       Size  = 0;

  EXPECT_EQ (
    GetCertificateData (Hdr, Cert.size (), &Data, &Size),
    EFI_UNSUPPORTED
    );
  EXPECT_EQ (Data, nullptr);
  EXPECT_EQ (Size, (UINTN)0);
}
