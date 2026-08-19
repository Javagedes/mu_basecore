/** @file
  Utility functions for DxeImageVerificationLib.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Support.h"

//
// Image Handle that contains the image bytes and size.
//
typedef struct {
  CONST UINT8    *Base;
  UINTN          BufferSize;
} PE_COFF_IMAGE_HANDLE;

/**
  Buffer size aware implementation of PE_COFF_LOADER_READ_FILE.

  Truncates reads for requests that start within the image bounds, but extends beyond the image
  bounds. Sets read size to 0 for requests that start beyond the image bounds.

  @param[in]      FileHandle  Pointer to a PE_COFF_IMAGE_HANDLE describing
                              the image bytes available to PeCoffLib.
  @param[in]      FileOffset  Byte offset within the image to read from.
  @param[in,out]  ReadSize    On input, bytes requested. On output, bytes
                              actually copied (may be 0 or less than
                              requested if the range extends past EOF).
  @param[out]     Buffer      Destination buffer of at least the input
                              *ReadSize bytes.

  @retval RETURN_SUCCESS            Read succeeded; *ReadSize is the
                                    number of bytes copied.
  @retval RETURN_INVALID_PARAMETER  FileHandle, ReadSize, or Buffer was
                                    NULL.
**/
STATIC
RETURN_STATUS
EFIAPI
BoundedImageRead (
  IN     VOID   *FileHandle,
  IN     UINTN  FileOffset,
  IN OUT UINTN  *ReadSize,
  OUT    VOID   *Buffer
  )
{
  CONST PE_COFF_IMAGE_HANDLE  *Handle;
  UINTN                       Available;

  if ((FileHandle == NULL) || (ReadSize == NULL) || (Buffer == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }

  Handle = (CONST PE_COFF_IMAGE_HANDLE *)FileHandle;

  if (FileOffset >= Handle->BufferSize) {
    *ReadSize = 0;
    return RETURN_SUCCESS;
  }

  Available = Handle->BufferSize - FileOffset;
  if (*ReadSize > Available) {
    *ReadSize = Available;
  }

  CopyMem (Buffer, Handle->Base + FileOffset, *ReadSize);
  return RETURN_SUCCESS;
}

/**
  Locate the EFI_IMAGE_DIRECTORY_ENTRY_SECURITY data directory in the
  PE/COFF image contained in FileBuffer.

  Caution: This function may receive untrusted input. The PE/COFF image
  is external input and is bounds-checked by PeCoffLib before any field
  is dereferenced.

  @param[in]   FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]   FileSize    BufferSize of FileBuffer in bytes.
  @param[out]  SecDataDir  On success, filled with a copy of the image's
                           security data directory entry. Zeroed when
                           the image declares no security directory.

  @retval EFI_SUCCESS            SecDataDir has been populated.
  @retval EFI_INVALID_PARAMETER  FileBuffer or SecDataDir is NULL.
  @retval EFI_LOAD_ERROR         FileBuffer does not contain a valid
                                 PE/COFF image, or PeCoffLib otherwise
                                 rejected the headers.
**/
EFI_STATUS
GetImageSecurityDataDirectory (
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize,
  OUT EFI_IMAGE_DATA_DIRECTORY  *SecDataDir
  )
{
  RETURN_STATUS                 PeCoffStatus;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;
  PE_COFF_IMAGE_HANDLE          Handle;

  if ((FileBuffer == NULL) || (SecDataDir == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (SecDataDir, sizeof (*SecDataDir));

  Handle.Base       = (CONST UINT8 *)FileBuffer;
  Handle.BufferSize = FileSize;

  //
  // Delegate header parsing, signature validation, optional-header
  // magic checks, and security-directory bounds checking to PeCoffLib.
  // PeCoffLib records the validated security data directory entry in the
  // image context, leaving it zeroed when the image declares no security
  // directory.
  //
  ZeroMem (&ImageContext, sizeof (ImageContext));
  ImageContext.Handle    = &Handle;
  ImageContext.ImageRead = BoundedImageRead;

  PeCoffStatus = PeCoffLoaderGetImageInfo (&ImageContext);
  if (RETURN_ERROR (PeCoffStatus)) {
    DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: PeImage invalid (0x%lx).\n", (UINT64)PeCoffStatus));
    return EFI_LOAD_ERROR;
  }

  *SecDataDir = ImageContext.SecurityDataDirectory;
  return EFI_SUCCESS;
}

/**
  Append a region of the image to the assembled Authenticode message, with bounds checks.

  @param[in]      FileBuffer  The image bytes.
  @param[in]      FileSize    Size of FileBuffer, and the capacity of Out.
  @param[in]      Offset      Start of the region within FileBuffer.
  @param[in]      Size        Length of the region in bytes.
  @param[out]     Out         Destination buffer of FileSize bytes.
  @param[in,out]  OutPos      Current write position in Out; advanced by Size on success.

  @retval EFI_SUCCESS     The region was copied (or Size was 0).
  @retval EFI_LOAD_ERROR  The region falls outside FileBuffer or would overflow Out.
**/
STATIC
EFI_STATUS
AppendImageRegion (
  IN     CONST UINT8  *FileBuffer,
  IN     UINTN        FileSize,
  IN     UINTN        Offset,
  IN     UINTN        Size,
  OUT    UINT8        *Out,
  IN OUT UINTN        *OutPos
  )
{
  if (Size == 0) {
    return EFI_SUCCESS;
  }

  //
  // The source region must lie within the image, and the copy must fit the output buffer (a
  // malformed image with overlapping regions could otherwise write past Out).
  //
  if ((Offset > FileSize) || (Size > FileSize - Offset) || (Size > FileSize - *OutPos)) {
    return EFI_LOAD_ERROR;
  }

  CopyMem (Out + *OutPos, FileBuffer + Offset, Size);
  *OutPos += Size;
  return EFI_SUCCESS;
}

/**
  Assemble the Authenticode image (the byte stream the Windows Authenticode algorithm hashes) for a
  PE/COFF image.

  Produces the exact bytes hashed for the Authenticode digest: the image with the optional-header
  CheckSum field, the Certificate Table data-directory entry, and the trailing attribute-certificate
  table excluded.

  Caution: FileBuffer is attacker-controlled; every region is bounds-checked before it is copied.

  @param[in]   FileBuffer     In-memory PE/COFF image.
  @param[in]   FileSize       Size of FileBuffer in bytes.
  @param[out]  AuthImage      On success, a pool-allocated buffer (caller frees with FreePool ())
                              holding the assembled Authenticode image.
  @param[out]  AuthImageSize  On success, the length of AuthImage in bytes.

  @retval EFI_SUCCESS            AuthImage / AuthImageSize were populated.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL or FileSize is 0.
  @retval EFI_LOAD_ERROR         FileBuffer is not a well-formed PE/COFF image.
  @retval EFI_OUT_OF_RESOURCES   An allocation failed.
**/
EFI_STATUS
BuildAuthenticodeImage (
  IN  VOID   *FileBuffer,
  IN  UINTN  FileSize,
  OUT UINT8  **AuthImage,
  OUT UINTN  *AuthImageSize
  )
{
  CONST UINT8                     *Image;
  CONST EFI_IMAGE_DOS_HEADER      *DosHdr;
  CONST EFI_IMAGE_NT_HEADERS32    *Nt32;
  CONST EFI_IMAGE_NT_HEADERS64    *Nt64;
  CONST EFI_IMAGE_SECTION_HEADER  *SectionTable;
  EFI_IMAGE_SECTION_HEADER        *Sorted;
  UINT8                           *Out;
  UINT32                          PeOffset;
  UINT16                          Magic;
  UINT16                          NumberOfSections;
  UINT16                          SizeOfOptionalHeader;
  UINT32                          NumberOfRvaAndSizes;
  UINT32                          SizeOfHeaders;
  UINT32                          CertSize;
  UINTN                           ChecksumOffset;
  UINTN                           SecDirOffset;
  UINTN                           SectionTableOffset;
  UINTN                           OutPos;
  UINTN                           SumOfBytesHashed;
  UINTN                           Remaining;
  UINTN                           Index;
  UINTN                           Pos;
  EFI_STATUS                      Status;

  if ((FileBuffer == NULL) || (AuthImage == NULL) || (AuthImageSize == NULL) || (FileSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  *AuthImage     = NULL;
  *AuthImageSize = 0;
  Image          = (CONST UINT8 *)FileBuffer;
  Nt64           = NULL;
  Sorted         = NULL;
  Out            = NULL;

  //
  // Locate the PE header (past the optional DOS stub) and require the full PE32 NT headers before
  // dereferencing any optional-header field.
  //
  if (FileSize < sizeof (EFI_IMAGE_DOS_HEADER)) {
    return EFI_LOAD_ERROR;
  }

  DosHdr   = (CONST EFI_IMAGE_DOS_HEADER *)Image;
  PeOffset = (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) ? DosHdr->e_lfanew : 0;

  if ((PeOffset > FileSize) || (FileSize - PeOffset < sizeof (EFI_IMAGE_NT_HEADERS32))) {
    return EFI_LOAD_ERROR;
  }

  Nt32 = (CONST EFI_IMAGE_NT_HEADERS32 *)(Image + PeOffset);
  if (Nt32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    return EFI_LOAD_ERROR;
  }

  Magic = Nt32->OptionalHeader.Magic;
  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    NumberOfRvaAndSizes = Nt32->OptionalHeader.NumberOfRvaAndSizes;
    SizeOfHeaders       = Nt32->OptionalHeader.SizeOfHeaders;
    ChecksumOffset      = (CONST UINT8 *)&Nt32->OptionalHeader.CheckSum - Image;
    SecDirOffset        = (CONST UINT8 *)&Nt32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY] - Image;
    CertSize            = (NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_SECURITY)
                          ? Nt32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size : 0;
  } else if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    if (FileSize - PeOffset < sizeof (EFI_IMAGE_NT_HEADERS64)) {
      return EFI_LOAD_ERROR;
    }

    Nt64                = (CONST EFI_IMAGE_NT_HEADERS64 *)(Image + PeOffset);
    NumberOfRvaAndSizes = Nt64->OptionalHeader.NumberOfRvaAndSizes;
    SizeOfHeaders       = Nt64->OptionalHeader.SizeOfHeaders;
    ChecksumOffset      = (CONST UINT8 *)&Nt64->OptionalHeader.CheckSum - Image;
    SecDirOffset        = (CONST UINT8 *)&Nt64->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY] - Image;
    CertSize            = (NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_SECURITY)
                          ? Nt64->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size : 0;
  } else {
    return EFI_LOAD_ERROR;
  }

  NumberOfSections     = Nt32->FileHeader.NumberOfSections;
  SizeOfOptionalHeader = Nt32->FileHeader.SizeOfOptionalHeader;
  SectionTableOffset   = (UINTN)PeOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + SizeOfOptionalHeader;

  if ((SectionTableOffset > FileSize) ||
      ((FileSize - SectionTableOffset) / sizeof (EFI_IMAGE_SECTION_HEADER) < NumberOfSections))
  {
    return EFI_LOAD_ERROR;
  }

  SectionTable = (CONST EFI_IMAGE_SECTION_HEADER *)(Image + SectionTableOffset);

  //
  // The message only omits bytes (the checksum, the security directory entry, and the attribute
  // certificate table), so it never exceeds the image size.
  //
  Out = AllocatePool (FileSize);
  if (Out == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  OutPos = 0;

  //
  // Header up to the CheckSum field (the 4-byte CheckSum is then skipped).
  //
  Status = AppendImageRegion (Image, FileSize, 0, ChecksumOffset, Out, &OutPos);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
    //
    // No Certificate Table directory entry: append the rest of the headers.
    //
    if (SizeOfHeaders < ChecksumOffset + sizeof (UINT32)) {
      Status = EFI_LOAD_ERROR;
      goto Done;
    }

    Status = AppendImageRegion (Image, FileSize, ChecksumOffset + sizeof (UINT32), SizeOfHeaders - (ChecksumOffset + sizeof (UINT32)), Out, &OutPos);
    if (EFI_ERROR (Status)) {
      goto Done;
    }
  } else {
    //
    // Append from after the CheckSum to the Certificate Table directory entry, skip that 8-byte
    // entry, then append the remaining headers.
    //
    if (SecDirOffset < ChecksumOffset + sizeof (UINT32)) {
      Status = EFI_LOAD_ERROR;
      goto Done;
    }

    Status = AppendImageRegion (Image, FileSize, ChecksumOffset + sizeof (UINT32), SecDirOffset - (ChecksumOffset + sizeof (UINT32)), Out, &OutPos);
    if (EFI_ERROR (Status)) {
      goto Done;
    }

    if (SizeOfHeaders < SecDirOffset + sizeof (EFI_IMAGE_DATA_DIRECTORY)) {
      Status = EFI_LOAD_ERROR;
      goto Done;
    }

    Status = AppendImageRegion (Image, FileSize, SecDirOffset + sizeof (EFI_IMAGE_DATA_DIRECTORY), SizeOfHeaders - (SecDirOffset + sizeof (EFI_IMAGE_DATA_DIRECTORY)), Out, &OutPos);
    if (EFI_ERROR (Status)) {
      goto Done;
    }
  }

  SumOfBytesHashed = SizeOfHeaders;

  //
  // Append each section's raw data in ascending PointerToRawData order.
  //
  if (NumberOfSections > 0) {
    Sorted = AllocateZeroPool ((UINTN)NumberOfSections * sizeof (EFI_IMAGE_SECTION_HEADER));
    if (Sorted == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    for (Index = 0; Index < NumberOfSections; Index++) {
      Pos = Index;
      while ((Pos > 0) && (SectionTable[Index].PointerToRawData < Sorted[Pos - 1].PointerToRawData)) {
        CopyMem (&Sorted[Pos], &Sorted[Pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
        Pos--;
      }

      CopyMem (&Sorted[Pos], &SectionTable[Index], sizeof (EFI_IMAGE_SECTION_HEADER));
    }

    for (Index = 0; Index < NumberOfSections; Index++) {
      if (Sorted[Index].SizeOfRawData == 0) {
        continue;
      }

      Status = AppendImageRegion (Image, FileSize, Sorted[Index].PointerToRawData, Sorted[Index].SizeOfRawData, Out, &OutPos);
      if (EFI_ERROR (Status)) {
        goto Done;
      }

      SumOfBytesHashed += Sorted[Index].SizeOfRawData;
    }
  }

  //
  // Trailing data after the sections, excluding the attribute-certificate table (CertSize bytes).
  //
  if (FileSize > SumOfBytesHashed) {
    Remaining = FileSize - SumOfBytesHashed;
    if (Remaining > CertSize) {
      Status = AppendImageRegion (Image, FileSize, SumOfBytesHashed, Remaining - CertSize, Out, &OutPos);
      if (EFI_ERROR (Status)) {
        goto Done;
      }
    } else if (Remaining < CertSize) {
      Status = EFI_LOAD_ERROR;
      goto Done;
    }
  }

  *AuthImage     = Out;
  *AuthImageSize = OutPos;
  Out            = NULL;
  Status         = EFI_SUCCESS;

Done:
  if (Sorted != NULL) {
    FreePool (Sorted);
  }

  if (Out != NULL) {
    FreePool (Out);
  }

  return Status;
}

/**
  Populate Authority with a newly allocated V1 EFI_SIGNATURE_DATA that wraps a certificate payload.

  The allocation is a 16-byte SignatureOwner followed by a copy of Payload. It is owned by the
  caller and released with FreeImageAuthority (). Authority->SignatureType is left unchanged so the
  caller can record the authorizing list's signature type independently.

  @param[in]   Owner        SignatureOwner GUID to store, or NULL to store a zeroed GUID (used for a
                            matching V2 EFI_SIGNATURE_V2_DATA entry, which carries no owner).
  @param[in]   Payload      The certificate (or other signature payload) to copy.
  @param[in]   PayloadSize  Size of Payload in bytes.
  @param[out]  Authority    On success, Authority->Data references the allocated EFI_SIGNATURE_DATA
                            and Authority->Size is its total length.

  @retval EFI_SUCCESS            Authority was populated.
  @retval EFI_INVALID_PARAMETER  Payload or Authority is NULL, or PayloadSize is 0 or too large.
  @retval EFI_OUT_OF_RESOURCES   The allocation failed.
**/
EFI_STATUS
BuildImageAuthority (
  IN  CONST EFI_GUID   *Owner  OPTIONAL,
  IN  CONST UINT8      *Payload,
  IN  UINTN            PayloadSize,
  OUT IMAGE_AUTHORITY  *Authority
  )
{
  EFI_SIGNATURE_DATA  *SigData;
  UINTN               TotalSize;

  if ((Payload == NULL) || (PayloadSize == 0) || (Authority == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Reject a payload large enough to overflow the header addition. PayloadSize is derived from
  // attacker-controlled db/dbx and image data, so the bound is checked before allocation.
  //
  if (PayloadSize > MAX_UINTN - OFFSET_OF (EFI_SIGNATURE_DATA, SignatureData)) {
    return EFI_INVALID_PARAMETER;
  }

  TotalSize = OFFSET_OF (EFI_SIGNATURE_DATA, SignatureData) + PayloadSize;

  SigData = AllocateZeroPool (TotalSize);
  if (SigData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // A NULL Owner leaves the zeroed SignatureOwner from AllocateZeroPool in place (V2 source entry).
  //
  if (Owner != NULL) {
    CopyGuid (&SigData->SignatureOwner, Owner);
  }

  CopyMem (SigData->SignatureData, Payload, PayloadSize);

  Authority->Data = SigData;
  Authority->Size = TotalSize;

  return EFI_SUCCESS;
}

/**
  Release the allocation owned by an IMAGE_AUTHORITY.

  Frees Authority->Data (if any) and clears Authority->Data / Authority->Size. Authority->SignatureType
  is left intact. Safe to call on an already-empty authority or a NULL pointer.

  @param[in,out]  Authority  Authority whose owned Data is released.
**/
VOID
FreeImageAuthority (
  IN OUT IMAGE_AUTHORITY  *Authority
  )
{
  if (Authority == NULL) {
    return;
  }

  if (Authority->Data != NULL) {
    FreePool (Authority->Data);
    Authority->Data = NULL;
  }

  Authority->Size = 0;
}
