/** @file
  Unit tests for GetImageSecurityDataDirectory in the
  DxeImageVerificationLib.

  These tests construct minimal-but-valid PE/COFF images in memory and
  exercise the real PeCoffLib through GetImageSecurityDataDirectory so
  that the data-directory callback path is covered end-to-end.

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
  #include "../Image.h"
}

//
// Layout constants for the synthetic PE32+ image.
//
// The buffer is a single contiguous blob laid out as:
//   [DOS hdr][NT64 hdrs][1 section hdr][padding to SizeOfHeaders][image body]
//
// All sizes are picked to satisfy PeCoffLoaderGetImageInfo's
// consistency checks (NumberOfRvaAndSizes, SizeOfOptionalHeader,
// SectionHeaderOffset, SizeOfHeaders < SizeOfImage, last-byte reads of
// SizeOfHeaders and the security directory).
//
static constexpr UINT32  kDosHdrSize    = sizeof (EFI_IMAGE_DOS_HEADER);
static constexpr UINT32  kNt64Size      = sizeof (EFI_IMAGE_NT_HEADERS64);
static constexpr UINT32  kPeCoffOffset  = kDosHdrSize;
static constexpr UINT32  kSizeOfHeaders = 0x200;
static constexpr UINT32  kSizeOfImage   = 0x400;
static constexpr UINT32  kSecDirVa      = 0x300;
static constexpr UINT32  kSecDirSize    = 0x100;

/**
  Build a minimal valid PE32+ image in heap-backed storage.

  When IncludeSecurityDir is true, the returned image's
  EFI_IMAGE_DIRECTORY_ENTRY_SECURITY entry points at [kSecDirVa,
  kSecDirVa + kSecDirSize). Otherwise that entry is left zero.
**/
static std::vector<UINT8>
BuildPe32PlusImage (
  bool  IncludeSecurityDir
  )
{
  std::vector<UINT8>  Image (kSizeOfImage, 0);

  EFI_IMAGE_DOS_HEADER    *Dos = (EFI_IMAGE_DOS_HEADER *)Image.data ();
  EFI_IMAGE_NT_HEADERS64  *Nt  = (EFI_IMAGE_NT_HEADERS64 *)(Image.data () + kPeCoffOffset);

  Dos->e_magic  = EFI_IMAGE_DOS_SIGNATURE;
  Dos->e_lfanew = kPeCoffOffset;

  Nt->Signature                          = EFI_IMAGE_NT_SIGNATURE;
  Nt->FileHeader.Machine                 = IMAGE_FILE_MACHINE_X64;
  Nt->FileHeader.NumberOfSections        = 1;
  Nt->FileHeader.SizeOfOptionalHeader    = sizeof (EFI_IMAGE_OPTIONAL_HEADER64);
  Nt->OptionalHeader.Magic               = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt->OptionalHeader.SizeOfImage         = kSizeOfImage;
  Nt->OptionalHeader.SizeOfHeaders       = kSizeOfHeaders;
  Nt->OptionalHeader.SectionAlignment    = 0x200;
  Nt->OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;

  if (IncludeSecurityDir) {
    Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = kSecDirVa;
    Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size           = kSecDirSize;
  }

  return Image;
}

class GetImageSecurityDataDirectoryTest : public ::testing::Test {
};

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

TEST_F (GetImageSecurityDataDirectoryTest, NullFileBuffer_ReturnsInvalidParameter) {
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (NULL, 0x100, &SecDataDir),
    EFI_INVALID_PARAMETER
    );
}

TEST_F (GetImageSecurityDataDirectoryTest, NullSecDataDir_ReturnsInvalidParameter) {
  std::vector<UINT8>  Image = BuildPe32PlusImage (false);

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), NULL),
    EFI_INVALID_PARAMETER
    );
}

// ---------------------------------------------------------------------------
// Malformed images
// ---------------------------------------------------------------------------

TEST_F (GetImageSecurityDataDirectoryTest, GarbageBuffer_ReturnsLoadError) {
  //
  // A buffer that is large enough to attempt header parsing but does
  // not actually carry valid DOS/NT signatures must be rejected.
  //
  std::vector<UINT8>        Buffer (kSizeOfImage, 0xAB);
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Buffer.data (), Buffer.size (), &SecDataDir),
    EFI_LOAD_ERROR
    );
}

// ---------------------------------------------------------------------------
// Happy paths exercised through real PeCoffLib + the data-directory callback
// ---------------------------------------------------------------------------

TEST_F (GetImageSecurityDataDirectoryTest, ValidImageWithoutSecurityDir_ReturnsZeroedDir) {
  std::vector<UINT8>        Image = BuildPe32PlusImage (false);
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  //
  // Pre-poison SecDataDir so we can prove the function actually wrote
  // back zeros (rather than leaving stale caller-supplied bytes).
  //
  SetMem (&SecDataDir, sizeof (SecDataDir), 0xCD);

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), &SecDataDir),
    EFI_SUCCESS
    );
  EXPECT_EQ (SecDataDir.VirtualAddress, 0u);
  EXPECT_EQ (SecDataDir.Size, 0u);
}

TEST_F (GetImageSecurityDataDirectoryTest, ValidImageWithSecurityDir_ReturnsCapturedDir) {
  std::vector<UINT8>        Image = BuildPe32PlusImage (true);
  EFI_IMAGE_DATA_DIRECTORY  SecDataDir;

  EXPECT_EQ (
    GetImageSecurityDataDirectory (Image.data (), Image.size (), &SecDataDir),
    EFI_SUCCESS
    );
  EXPECT_EQ (SecDataDir.VirtualAddress, kSecDirVa);
  EXPECT_EQ (SecDataDir.Size, kSecDirSize);
}
