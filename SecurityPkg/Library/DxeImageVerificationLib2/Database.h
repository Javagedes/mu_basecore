/** @file
  Secureboot DB/DBX/DBT (EFI_SIGNATURE_LIST) helpers, including signed-image
  (certificate / Authenticode) validation, for the DXE Image Verification Library.

  Copyright (C) Microsoft Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_
#define DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_

#include "DxeImageVerificationLib.h"
#include "Iterator.h"
#include "Support.h"
#include <Library/UefiLib.h>
#include <Guid/WinCertificate.h>

//
// The platform's Secure Boot signature databases (`db` and `dbx`). Db / Dbx
// are pool-allocated copies owned by the caller; either may be NULL when the
// corresponding variable is absent, in which case its size is 0.
//
typedef struct {
  VOID     *Db;
  UINTN    DbSize;
  VOID     *Dbx;
  UINTN    DbxSize;
} SIGNATURE_DATABASES;

//
// The verdict from evaluating a single image WIN_CERTIFICATE against the `db`
// and `dbx` databases.
//
typedef enum {
  //
  // A `db` trust anchor authorized the image and no certificate in its verified
  // signer->anchor chain is revoked by the `dbx`.
  //
  ImageCertApproved,
  //
  // A `db` trust anchor verified the image, but a certificate in its verified
  // chain is enrolled in the `dbx`. No un-revoked anchor authorized the image.
  //
  ImageCertRevokedByDbx,
  //
  // No `db` trust anchor verifies the image's signature.
  //
  ImageCertNotInDb,
  //
  // The WIN_CERTIFICATE could not be evaluated: an unsupported certificate
  // type, a malformed PKCS#7 payload, an unrecognized Authenticode hash
  // algorithm, or another failure before trust-anchor evaluation.
  //
  ImageCertUnusable
} IMAGE_CERT_VERDICT;

//
// The result of EvaluateImageCertificate: the evaluation verdict plus the
// authority responsible for it - the `db` entry that authorized the image
// (ImageCertApproved, for measurement) or the `dbx` entry that revoked it
// (ImageCertRevokedByDbx).
//
typedef struct {
  IMAGE_CERT_VERDICT    Verdict;
  //
  // Authority.Data is non-NULL when Verdict is ImageCertApproved (it references
  // the authorizing `db` EFI_SIGNATURE_DATA entry) or ImageCertRevokedByDbx (it
  // references the revoking `dbx` entry); it is NULL for every other verdict.
  // Authority.SignatureType carries the image-hash algorithm once it has been
  // determined, regardless of verdict.
  //
  IMAGE_AUTHORITY       Authority;
} IMAGE_CERT_EVALUATION;

/**
  Load the platform's db and dbx signature databases.

  The Db / Dbx buffers in the returned structure are allocated using AllocatePool(). The caller is
  responsible for freeing them with FreePool().

  @param[out]  Databases  On success, receives pool-allocated copies of the `db` and `dbx`
                          variable contents. Either Db or Dbx may be NULL (with a 0 size) if the
                          corresponding variable is absent.

  @retval EFI_SUCCESS            Databases loaded. Db / Dbx may still be NULL if the
                                 corresponding variable was absent.
  @retval EFI_INVALID_PARAMETER  Databases is NULL.
  @retval Other                  Failure status from gRT->GetVariable.
**/
EFI_STATUS
LoadSignatureDatabases (
  OUT SIGNATURE_DATABASES  *Databases
  );

/**
  Determine whether the subject bound to Cache is present in a `db`-style allow-list.

  The subject is described by Cache->Type: an image (DigestCacheTypeImage) is matched by its digest
  under each list's hash algorithm; a certificate (DigestCacheTypeX509) is matched either by exact
  DER bytes against an EFI_CERT_X509_GUID list or by its TBSCertificate digest against a cert-hash
  list.

  As an allow-list search this is best-effort: if the database is malformed partway through, the
  valid prefix is still honored (a trailing malformed entry can only remove a potential authorizer,
  never add one).

  @param[in,out]  Cache      Digest cache bound to the subject (image or certificate).
  @param[in]      Db         Raw `db` contents, or NULL for an empty database.
  @param[in]      DbSize     Size of Db in bytes; 0 when Db is NULL.
  @param[out]     Authority  Optional. On a match, receives the matching entry (for PCR 7
                             measurement). Zeroed when no match is found.

  @retval TRUE   The subject matches an entry in the valid prefix of Db.
  @retval FALSE  The subject is not present, or Cache is unusable.
**/
BOOLEAN
IsInDb (
  IN OUT DIGEST_CACHE     *Cache,
  IN     CONST VOID       *Db,
  IN     UINTN            DbSize,
  OUT    IMAGE_AUTHORITY  *Authority  OPTIONAL
  );

/**
  Determine whether the subject bound to Cache is present in a `dbx`-style deny-list.

  The subject is described by Cache exactly as for IsInDb.

  As a deny-list search this fails closed: if the database cannot be fully parsed (a malformed
  entry truncates the walk, a required hash cannot be computed, or Cache is unusable), the subject
  is treated as present, because a dropped entry might have matched it.

  @param[in,out]  Cache      Digest cache bound to the subject (image or certificate).
  @param[in]      Dbx        Raw `dbx` contents, or NULL for an empty database.
  @param[in]      DbxSize    Size of Dbx in bytes; 0 when Dbx is NULL.
  @param[out]     Authority  Optional. On an actual match, receives the revoking entry (for
                             rejection reporting). Zeroed when the TRUE result is due to
                             fail-closed truncation rather than a specific entry.

  @retval TRUE   The subject matches an entry in Dbx, or the database could not be fully parsed.
  @retval FALSE  The subject is definitively absent from Dbx (including an absent/empty Dbx).
**/
BOOLEAN
IsInDbx (
  IN OUT DIGEST_CACHE     *Cache,
  IN     CONST VOID       *Dbx,
  IN     UINTN            DbxSize,
  OUT    IMAGE_AUTHORITY  *Authority  OPTIONAL
  );

/**
  Evaluate a single image WIN_CERTIFICATE against the `db` / `dbx` databases.

  Consolidates PKCS#7 extraction, image-hash computation, `db` authorization, and chain-relative
  `dbx` revocation into one pass. The certificate authorizes the image when some `db` trust anchor
  verifies the image's signature and no certificate in the verified signer->anchor chain is
  enrolled in the `dbx`.

  The EFI_STATUS return reports whether evaluation could be performed, not the security outcome;
  the outcome is reported in Evaluation->Verdict.

  @param[in]      Cert        The WIN_CERTIFICATE to evaluate.
  @param[in,out]  Cache       Image digest cache bound to the image buffer; the cache may memoize
                              one digest per algorithm across calls.
  @param[in]      Databases   The `db` / `dbx` signature databases to evaluate against.
  @param[out]     Evaluation  On EFI_SUCCESS, receives the verdict and (when approved) the
                              authorizing `db` authority.

  @retval EFI_SUCCESS            Evaluation completed; inspect Evaluation->Verdict.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval other                  The image's Authenticode hash could not be computed (propagated
                                 from GetHash); no verdict was produced.
**/
EFI_STATUS
EvaluateImageCertificate (
  IN     CONST WIN_CERTIFICATE      *Cert,
  IN OUT DIGEST_CACHE               *Cache,
  IN     CONST SIGNATURE_DATABASES  *Databases,
  OUT    IMAGE_CERT_EVALUATION      *Evaluation
  );

#endif // DXE_IMAGE_VERIFICATION_LIB_DATABASE_H_
