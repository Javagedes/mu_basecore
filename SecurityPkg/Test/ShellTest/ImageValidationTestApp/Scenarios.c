/** @file
  Secure boot image validation test scenarios, grouped into one suite per image type
  (unsigned, signed, dual-signed).

  Each scenario selects an image (IMAGE_TYPE_*) and describes the `db` / `dbx` contents to
  build (DB_STATE_* flags), then specifies the EFI_STATUS that gBS->LoadImage() is expected to
  return. DB_STATE flags may be OR-combined to place multiple signature lists in one
  database.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "ImageValidationTestApp.h"

//
// Unsigned image scenarios. An unsigned image can only be authorized by its image digest in
// db, and is denied when db is empty or the digest is revoked.
//
STATIC CONST SECURE_BOOT_IMAGE_TEST_SCENARIO  mUnsignedScenarios[] = {
  // Unsigned image is denied when no allowlist or denylist entries are present.
  TEST_SCENARIO (
    IMAGE_TYPE_UNSIGNED,
    DB_STATE_EMPTY,
    DB_STATE_EMPTY,
    EFI_ACCESS_DENIED
    ),
  // Unsigned image is approved when its digest is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_UNSIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Unsigned image is denied when its digest appears in both db and dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_UNSIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Unsigned image is denied when a signer 1 leaf TBS hash is enrolled in db (no signature to authorize).
  TEST_SCENARIO (
    IMAGE_TYPE_UNSIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_ACCESS_DENIED
    ),
};

//
// Signed image scenarios. The signed image is signed by a leaf certificate whose chain is
// root CA -> intermediate CA -> leaf, so enrolling any cert in that chain (leaf,
// intermediate, or root) in db authorizes it. Revoking any chain cert via dbx denies the
// (single) signature regardless of which cert authorized it in db, but the image-digest
// authorization path is independent of cert revocation.
//
STATIC CONST SECURE_BOOT_IMAGE_TEST_SCENARIO  mSignedScenarios[] = {
  // Signed image is denied when no allowlist or denylist entries are present.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_EMPTY,
    DB_STATE_EMPTY,
    EFI_ACCESS_DENIED
    ),
  // Signed image is approved when signer 1 leaf certificate is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Signed image is approved when signer 1 intermediate certificate is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Signed image is approved when signer 1 root certificate is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Signed image is approved when signer 1 leaf TBS hash is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Signed image is denied when only signer 2 TBS hash is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_ACCESS_DENIED
    ),
  // Signed image is approved when only signer 1 intermediate TBS hash is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Signed image is approved when only signer 1 root TBS hash is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Signed image is approved when its image digest is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Signed image is denied when only signer 2 cert is enrolled in db (no matching signer path).
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER2_CERT,
    DB_STATE_EMPTY,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 leaf certificate is explicitly revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER1_LEAF_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 intermediate certificate is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 root certificate is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER1_ROOT_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when intermediate-cert auth is paired with leaf revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_LEAF_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when intermediate-cert auth is paired with intermediate revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when intermediate-cert auth is paired with root revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_ROOT_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when root-cert auth is paired with leaf revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_SIGNER1_LEAF_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when root-cert auth is paired with intermediate revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when root-cert auth is paired with root revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_SIGNER1_ROOT_CERT,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 leaf cert is revoked by TBS hash in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 intermediate-cert auth is paired with signer 1 leaf TBS hash revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 root-cert auth is paired with signer 1 leaf TBS hash revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image stays approved when signer 1 is trusted in db and unrelated signer 2 cert is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER2_CERT,
    EFI_SUCCESS
    ),
  // Signed image stays approved by digest even when signer 1 leaf cert is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_SIGNER1_LEAF_CERT,
    EFI_SUCCESS
    ),
  // Signed image stays approved by digest even when signer 1 leaf TBS hash is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_SUCCESS
    ),
  // Signed image stays approved when digest and leaf cert are in db and leaf is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST | DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER1_LEAF_CERT,
    EFI_SUCCESS
    ),
  // Signed image stays approved by digest even when signer 1 intermediate is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    EFI_SUCCESS
    ),
  // Signed image stays approved when digest and intermediate are in db and intermediate is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST | DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    EFI_SUCCESS
    ),
  // Signed image stays approved by digest even when signer 1 root certificate is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_SIGNER1_ROOT_CERT,
    EFI_SUCCESS
    ),
  // Signed image stays approved when digest and root cert are in db and root cert is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST | DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_SIGNER1_ROOT_CERT,
    EFI_SUCCESS
    ),
  // Signed image is denied when cert-authorized in db but its digest is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when intermediate-cert auth in db is paired with digest revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when root-cert auth in db is paired with digest revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when digest is both authorized in db and revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 intermediate cert is revoked by TBS hash in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 root cert is revoked by TBS hash in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 leaf TBS hash authorizes in db but same hash is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 intermediate TBS hash authorizes in db but same hash is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 root TBS hash authorizes in db but same hash is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 leaf TBS hash authorizes but its chain intermediate TBS hash is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when signer 1 leaf TBS hash authorizes but its chain root TBS hash is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when leaf-cert auth is paired with signer 1 intermediate TBS hash revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image is denied when leaf-cert auth is paired with signer 1 root TBS hash revocation.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Signed image stays approved when signer 1 leaf TBS hash authorizes and unrelated signer 2 TBS hash is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_SIGNER2_TBS_HASH,
    EFI_SUCCESS
    ),
  // Signed image stays approved by digest even when signer 1 intermediate TBS hash is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    EFI_SUCCESS
    ),
  // Signed image stays approved by digest even when signer 1 root TBS hash is in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    EFI_SUCCESS
    ),
};

//
// Dual-signed image scenarios. The dual-signed image carries two signatures: the leaf-chain
// signature (root CA -> intermediate CA -> leaf) and signer 2. Authorization by either
// signature's certs in db is sufficient unless that signature is revoked by dbx.
//
STATIC CONST SECURE_BOOT_IMAGE_TEST_SCENARIO  mDualSignedScenarios[] = {
  // Dual-signed image is denied when no allowlist or denylist entries are present.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_EMPTY,
    DB_STATE_EMPTY,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is approved when signer 1 leaf certificate is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when signer 1 intermediate cert is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when signer 1 root cert is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when signer 2 certificate is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER2_CERT,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when signer 1 leaf TBS hash is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when signer 1 intermediate TBS hash is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when signer 1 root TBS hash is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when signer 2 TBS hash is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when both signer 1 and signer 2 certs are enrolled.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER2_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 is revoked but signer 2 remains trusted.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_LEAF_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 2 is revoked but signer 1 remains trusted.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER2_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when only signer 2 revocation is present in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_EMPTY,
    DB_STATE_SIGNER2_CERT,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when only signer 1 revocation is present in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_EMPTY,
    DB_STATE_SIGNER1_LEAF_CERT,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when both signer revocations are present in dbx only.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_EMPTY,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is approved when its image digest is enrolled in db.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when its digest appears in both db and dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image stays approved by digest even when signer certs are in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when signer 1 cert authorizes but digest is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 intermediate cert authorizes but digest is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 root cert authorizes but digest is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 2 cert authorizes but digest is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER2_CERT,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when both cert paths authorize but digest is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image stays approved when signer 1 leaf cert plus signer 2 are in the db and signer 2 is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER2_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 intermediate plus signer 2 are in db and signer 2 is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER2_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 root plus signer 2 are in db and signer 2 is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER2_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 intermediate plus signer 2 are in db and signer 1 intermediate is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 root plus signer 2 are in db and signer 1 root is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_ROOT_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when signer 1 intermediate plus signer 2 in db are both revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT | DB_STATE_SIGNER2_CERT,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 root plus signer 2 in db are both revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_ROOT_CERT | DB_STATE_SIGNER2_CERT,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image stays approved when digest plus signer 2 are in db and signer 2 is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_IMAGE_DIGEST | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER2_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when digest plus signer 1 intermediate are in db and signer 1 intermediate is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_IMAGE_DIGEST | DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when digest plus signer 1 root are in db and signer 1 root is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_IMAGE_DIGEST | DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_SIGNER1_ROOT_CERT,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when signer 2 cert is revoked by signer 2 TBS hash in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER2_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 leaf cert is revoked by signer 1 leaf TBS hash in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 intermediate cert is revoked by signer 1 intermediate TBS hash in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 root cert is revoked by signer 1 root TBS hash in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 2 TBS hash authorizes in db but same hash is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_SIGNER2_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image stays approved when signer 2 TBS hash is revoked but signer 1 path remains trusted.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER2_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 leaf TBS hash is revoked but signer 2 path remains trusted.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 2 is trusted in db and signer 1 leaf TBS hash is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 is trusted in db and signer 2 TBS hash is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT,
    DB_STATE_SIGNER2_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when only signer 1 intermediate is trusted and signer 1 leaf TBS hash is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image stays approved when signer 1 intermediate TBS hash is revoked but signer 2 path remains trusted.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 root TBS hash is revoked but signer 2 path remains trusted.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when both signer TBS hashes are revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_LEAF_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 intermediate and signer 2 TBS hashes are both revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 root and signer 2 TBS hashes are both revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_CERT | DB_STATE_SIGNER2_CERT,
    DB_STATE_SIGNER1_ROOT_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image stays approved by digest even when both signer TBS hashes are revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_IMAGE_DIGEST,
    DB_STATE_SIGNER1_LEAF_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image is approved when both signers are authorized purely by TBS hash.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_EMPTY,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when signer 2 TBS hash authorizes but digest is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 leaf TBS hash authorizes but digest is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_IMAGE_DIGEST,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image stays approved when signer 2 TBS hash authorizes and signer 1 leaf TBS hash is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved when signer 1 leaf TBS hash authorizes and signer 2 TBS hash is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    DB_STATE_SIGNER2_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved by signer 1 leaf TBS hash when both TBS hashes authorize and signer 2 TBS hash is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_SIGNER2_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image stays approved by signer 2 TBS hash when both TBS hashes authorize and signer 1 leaf TBS hash is revoked.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_SIGNER1_LEAF_TBS_HASH,
    EFI_SUCCESS
    ),
  // Dual-signed image is denied when both TBS-hash authorizations are revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_LEAF_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    DB_STATE_SIGNER1_LEAF_TBS_HASH | DB_STATE_SIGNER2_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 intermediate TBS hash authorizes but same hash is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    DB_STATE_SIGNER1_INTERMEDIATE_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
  // Dual-signed image is denied when signer 1 root TBS hash authorizes but same hash is revoked in dbx.
  TEST_SCENARIO (
    IMAGE_TYPE_DUAL_SIGNED,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    DB_STATE_SIGNER1_ROOT_TBS_HASH,
    EFI_ACCESS_DENIED
    ),
};

//
// One unit test suite per image type.
//
CONST SECURE_BOOT_TEST_SUITE  mTestSuites[] = {
  {
    "Unsigned Image Validation",
    "SecurityPkg.ImageValidation.Unsigned",
    mUnsignedScenarios,
    ARRAY_SIZE (mUnsignedScenarios)
  },
  {
    "Signed Image Validation",
    "SecurityPkg.ImageValidation.Signed",
    mSignedScenarios,
    ARRAY_SIZE (mSignedScenarios)
  },
  {
    "Dual-Signed Image Validation",
    "SecurityPkg.ImageValidation.DualSigned",
    mDualSignedScenarios,
    ARRAY_SIZE (mDualSignedScenarios)
  },
};

CONST UINTN  mTestSuiteCount = ARRAY_SIZE (mTestSuites);
