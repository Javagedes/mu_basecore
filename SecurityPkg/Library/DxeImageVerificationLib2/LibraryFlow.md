# DxeImageVerificationHandler Flow

This document describes the runtime flow of
`DxeImageVerificationHandler` in `SecurityPkg/Library/DxeImageVerificationLib2`.
It focuses on the three high-level phases:

1. **Policy validation** (entry-point gating)
2. **`ValidateUnsignedImage`** (image carries no embedded signature)
3. **`ValidateSignedImage`** (image carries one or more
   `WIN_CERTIFICATE` entries)

The shared `IMAGE_DIGEST_CACHE` constructed in (2) and (3) caches each
Authenticode digest the first time it is computed, so repeated lookups
across `db` / `dbx` and across signature lists do not recompute hashes.

## 1. Top-level flow

```mermaid
flowchart TD
    A[DxeImageVerificationHandler] --> C[GetExecutionPolicy]
    C --> D{{Policy == ALWAYS_EXECUTE?}}
    D -- yes --> D1[return EFI_SUCCESS]
    D -- no  --> E{{IsSecureBootEnabled?}}
    E -- no  --> E1[return EFI_SUCCESS]
    E -- yes --> F[GetImageSecurityDataDirectory]
    F --> G{{SecDataDir.Size == 0?}}
    G -- yes --> H[ValidateUnsignedImage]
    G -- no  --> I[ValidateSignedImage]
    H --> Z[return Status]
    I --> Z

    classDef drill fill:#d9ecff,stroke:#2f6fb2,color:#000;
    class H,I drill;
```

Key observations:

- `GetExecutionPolicy` runs **before** the Secure Boot check because
  it is cheap *and* the FV-dispatched-driver fast path (policy =
  `ALWAYS_EXECUTE`) is by far the most common path - only one or
  two calls per boot miss it - so short-circuiting there avoids
  the Secure Boot variable read and PE/COFF parse for the overwhelming
  majority of invocations.
- If Secure Boot is disabled the handler returns `EFI_SUCCESS` without
  inspecting the image. (Audit mode has been removed, so there is no
  longer a code path that inspects the image when Secure Boot is off.)
- A PE/COFF parse failure in `GetImageSecurityDataDirectory` is treated
  as a verification failure (its status is returned).
- The presence of any data in the security data directory (`Size > 0`)
  routes the image to the signed path; otherwise it is treated as
  unsigned.

## 2. `ValidateUnsignedImage`

The image has no embedded signature, so authorization is decided
entirely on the image hash. The hash is computed lazily for each
algorithm enrolled in `db` / `dbx` and cached in `IMAGE_DIGEST_CACHE`.

```mermaid
flowchart TD
    A[ValidateUnsignedImage] --> B[LoadSignatureDatabases db, dbx]
    B --> C[Init IMAGE_DIGEST_CACHE bound to FileBuffer/FileSize]
    C --> D[IsImageDigestInDatabase dbx]
    D --> D1{{IsFound?}}
    D1 -- yes --> X[return EFI_ACCESS_DENIED]
    D1 -- no  --> E[IsImageDigestInDatabase db]
    E --> E1{{IsFound?}}
    E1 -- no  --> X
    E1 -- yes --> Y[return EFI_SUCCESS]
```

Verdict table:

| `dbx` lookup  | `db` lookup | Result               |
| ------------- | ----------- | -------------------- |
| error or hit  | -           | `EFI_ACCESS_DENIED`  |
| miss          | error / miss| `EFI_ACCESS_DENIED`  |
| miss          | hit         | `EFI_SUCCESS`        |

Rules of thumb:

- `dbx` is consulted **before** `db`. A revoked hash is denied even if
  the same hash also appears in `db`.
- `IsImageDigestInDatabase` walks every signature list in the
  supplied database. For each list whose `SignatureType` is a known
  image-hash GUID it computes the image's
  digest under that algorithm (via the cache), then byte-compares
  against every entry.
- A failure to load either database is fail-closed
  (`EFI_ACCESS_DENIED`), not propagated upward.
  ## 3. `ValidateSignedImage`

The image has one or more `WIN_CERTIFICATE` entries in its security
data directory. The function delegates to two pure helpers that share
the same `IMAGE_DIGEST_CACHE`:

- `IsSignedImageAuthorized` - does `db` accept the image?
- `IsSignedImageRevoked` - does `dbx` reject the image?

`Action` (the platform's `EFI_IMAGE_EXECUTION_ACTION` output) starts as
`AUTH_SIG_FAILED`, is updated by the helpers on definitive outcomes,
and is set to `AUTH_SIG_PASSED` only on full success.

```mermaid
flowchart TD
    A[ValidateSignedImage] --> A0[Action = AUTH_SIG_FAILED]
    A0 --> B[LoadSignatureDatabases db, dbx]
    B --> C[Init IMAGE_DIGEST_CACHE bound to FileBuffer/FileSize]
    C --> D[IsSignedImageAuthorized]
    D --> D1{{Authorized?}}
    D1 -- no  --> X[return EFI_ACCESS_DENIED]
    D1 -- yes --> E[IsSignedImageRevoked]
    E --> E1{{Revoked?}}
    E1 -- yes --> X
    E1 -- no  --> Y[Action = AUTH_SIG_PASSED] --> Z[return EFI_SUCCESS]

    classDef drill fill:#d9ecff,stroke:#2f6fb2,color:#000;
    class D,E drill;
```

### 3a. `IsSignedImageAuthorized`

Two-stage authorization. The cheap image-hash fast path runs first; the
expensive PKCS#7 signature walk runs only on a miss.

```mermaid
flowchart TD
    A[IsSignedImageAuthorized] --> C[IsImageDigestInDatabase db]
    C --> C1{{IsFound?}}
    C1 -- yes --> C2[Action = AUTH_SIG_PASSED, return TRUE]
    C1 -- no  --> D[WinCertIterInit over SecDataDir]
    D --> D0{{Init OK?}}
    D0 -- no  --> E[Action = AUTH_SIG_NOT_FOUND, return FALSE]
    D0 -- yes --> D1[WinCertIterNext: next WIN_CERTIFICATE]
    D1 --> D2{{Entry?}}
    D2 -- no  --> E
    D2 -- yes --> D3[GetWinCertificatePkcs7AuthData]
    D3 --> D4[IsPkcs7AuthDataAuthorizedByDb]
    D4 --> D5{{Authorized?}}
    D5 -- yes --> G[Action = AUTH_SIG_PASSED, return TRUE]
    D5 -- no  --> D1

    classDef drill fill:#d9ecff,stroke:#2f6fb2,color:#000;
    class D4 drill;
```

Per embedded `WIN_CERTIFICATE` entry, `IsPkcs7AuthDataAuthorizedByDb`:

```mermaid
flowchart TD
    A[IsPkcs7AuthDataAuthorizedByDb] --> B[GetAuthenticodeHashAlgorithm AuthData]
    B --> B1{{OK?}}
    B1 -- no  --> R[return FALSE]
    B1 -- yes --> D[DatabaseIterInit db]
    D --> D1{{OK?}}
    D1 -- no  --> R
    D1 -- yes --> E[DatabaseIterNext: next EFI_SIGNATURE_LIST]
    E --> E1{{List?}}
    E1 -- no  --> R
    E1 -- yes --> G

    subgraph SUB[IsPkcs7AuthDataAuthorizedBySignatureList List]
        direction TB
        G[SigListIterInit / Next: next entry]
        G --> G1{{Entry?}}
        G1 -- yes --> H[AuthenticodeVerify AuthData]
        H --> H1{{Verifies?}}
        H1 -- no  --> G
      H1 -- yes --> I[X509GetTBSCert AuthData]
      I --> J{{IsTBSCertHashInDbx?}}
      J -- yes --> G
    end

    G1 -- no  --> E
    J -- no  --> T[return TRUE]

    classDef crypto fill:#ffe6a7,stroke:#d9822b,color:#000;
    class B,H,I crypto;
```

Nodes shaded orange (`GetAuthenticodeHashAlgorithm`, `AuthenticodeVerify`)
are calls into `BaseCryptLib`.

For each verifying trust anchor, `X509GetTBSCert` extracts the TBS bytes,
then `IsTBSCertHashInDbx` performs the revocation check.

### 3b. `IsSignedImageRevoked`

> Currently a stub that always returns FALSE.
