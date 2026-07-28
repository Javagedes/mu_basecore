---
name: EDK2 DXE Image Verification Architect
description: "Important information when continuuing to develop or maintain the EDKII DXE Image Verification library or related components."
applyTo: 'SecurityPkg/Library/DxeImageVerificationLib2/**/*'
---

## EDK2 DXE Image Verification Architecture

## Prerequisites

**CRITICAL**: Before proceeding with this skill, you MUST first load and read these prerequisite skills:
1. Load the [EDK2 Project General Instructions](../edk2-project-general/SKILL.md) skill for foundational knowledge on EDK2-style C code, file formats, build system, coding standards, and best practices.
2. Load the [EDK2 C Code Security Guidelines](../edk2-c-code-security/SKILL.md) skill for comprehensive security guidelines specific to EDK2 firmware C code, including secure coding practices and secure code review principles.

**CRITICAL**: When developing or maintaining the EDKII DXE Image Verification Library or related components, it is critical to update this file with any relevant information about the architecture, design decisions, security considerations, or implementation details that future developers should be aware of. This ensures that knowledge is preserved and shared effectively, enabling future maintainers to understand the context and rationale behind the code, and to continue development in a consistent and informed manner. Failure to do so may lead to confusion, security issues, or inefficient development in the future.

**CRITICAL**: Additionally, a README.md file exists at SecurityPkg/Library/DxeImageVerificationLib2/README.md which provides a more human readable, high level overview of the library, its purpose, and how it fits into the larger EDKII architecture. It is important to keep both this SKILL.md file and the README.md file updated with relevant information to ensure comprehensive documentation for future developers working on this component.

## General Information

The DXE Image verification library is a NULL library implementation. This means that it does not implement a specific library class interface. Instead, when it is linked into a module, its constructor (DxeImageVerificationLibConstructor) will be called. Overall, this constructor does
two things: (1) Registers an event handler for the End of DXE event, and (2) installs an image
verification handler function (`DxeImageVerificationHandler`).

## Requirements

1. Functions should remain small and focused on a single respsonsibility.
2. Functions should be well documented, with clear explanations of their purpose, parameters, return values, and any side effects.
3. All supporting functions (i.e. any function that is not the constructor or the event handler) should be written in a way that allows them to be easily unit tested. When a function is created, unit tests should also be created to validate the functionality of that function.
4. No global variables should be used within any supporting functions and effort should be made to avoid global variables where possible. The only use of global variables allowed should be within the top level `OnReadyToBoot` event handler function and the `DxeImageVerificationHandler`
function. In those cases, the global variable should be returned as a pointer from a getter function that can be mocked during testing.
5. All files should have `\r\n` Line endings.

## Building the library

The below command can be used to build the library, and only the library. This is useful for development and testing purposes, as it allows for faster build times when only working on the library code.

This command will build the DxeImageVerificationLib.inf module, using the CLANGPDB toolchain, for both DEBUG and RELEASE configurations and for IA32, X64, AARCH64 architectures. You can view the build log at `Build/CI_BUILDLOG.txt` and you can also review the actual build artifacts, which will be located in the `Build/SecurityPkg/` directory. There are subfolders that are dependent on the configuration and toolchain, so ensure you are looking in the correct location for the generated files.

```bash
stuart_ci_build -c .pytool/CISettings.py -d CompilerPlugin=run -p SecurityPkg TOOL_CHAIN_TAG=CLANGPDB BUILDMODULE=SecurityPkg/Library/DxeImageVerificationLib2/DxeImageVerificationLib.inf
```

## Unit Testing

Developing unit tests is done via the `GoogleTest` framework. Documentation related to how to write unit tests using this framework can be found in at [UnitTestFrameworkPkg's README](../../../UnitTestFrameworkPkg/ReadMe.md). All unit tests are currently placed in a single unit test INF located at `SecurityPkg/Library/DxeImageVerificationLib2/GoogleTest/*`. Tests should be grouped into separate files based on functionality being tested, but all tests are consolidated to this single INF to make it easier to build and run.

To build and run the unit tests, you can use the below command, which will compile and run ONLY the test executable I specified below. This will both build and run unit tests and you can review the test results in the terminal, in the build output at `Build/SecurityPkg/`, and specifically the test results at `Build/TestSuites.xml`.

```bash
stuart_ci_build -c .pytool/CISettings.py -d  HostUnitTestCompilerPlugin=run -p SecurityPkg TOOL_CHAIN_TAG=GCC5 BUILDMODULE=SecurityPkg/Library/DxeImageVerificationLib2/GoogleTest/DxeImageVerificationLibGoogleTest.inf
```

### Code Coverage

Building and running unit tests to validate pass/fail criteria is only the first step for full validation. Eventually we need to be concerned with ensuring the written unit tests are providing sufficient code coverage. To do this, we can utilize the following command to not only compile and run the test, but also generate code coverage results that can be reviewed. The following command generates a coverage xml file at `Build/SecurityPkg/HostTest/<config>/SecurityPkg_coverage.xml` that can be reviewed to determine which lines of code are being covered by the unit tests and which are not. This coverage file will contain a large amount of coverage results, most of which we do not care about. The main focus should be on the coverage results for the actual library code (i.e. code in `SecurityPkg/Library/DxeImageVerificationLib2`). You should use this information to write more / better unit tests to ensure that all paths are covered. If possible, you should have 100% coverage.

```bash
stuart_ci_build -c .pytool/CISettings.py -d  HostUnitTestCompilerPlugin=run -p SecurityPkg TOOL_CHAIN_TAG=GCC5 BUILDMODULE=SecurityPkg/Library/DxeImageVerificationLib2/GoogleTest/DxeImageVerificationLibGoogleTest.inf CODE_COVERAGE=TRUE CC_REORGANIZE=TRUE CC_FULL=TRUE CC_FLATTEN=TRUE
```

## Code Formatting

Code formatting must be done for every commit. Formatting can be performed automatically using the following command. Do not waste time running it in the middle of active changes. Just run it once you believe the feature is finished.

```bash
stuart_ci_build -c .pytool/CISettings.py -d -p SecurityPkg UncrustifyCheck=run UNCRUSTIFY_IN_PLACE=TRUE
```

## Policy Resolution (`Policy.c` / `Policy.h`)

The first thing the verification handler must do for any image is decide
*how strict* it should be. That decision is driven by where the image
came from, encoded as one of the `IMAGE_*` image source constants, and
mapped to one of the `*_EXECUTE` / `*_ON_SECURITY_VIOLATION` policy
values defined in `Policy.h`.

The current policy surface is intentionally **minimal and fail-closed**:
images loaded from a Firmware Volume are trusted by construction and
always allowed; every other origin is denied if image verification
fails. There are only two `IMAGE_*` constants (`IMAGE_UNKNOWN`,
`IMAGE_FROM_FV`) and two policy constants (`ALWAYS_EXECUTE`,
`DENY_EXECUTE_ON_SECURITY_VIOLATION`). Platform configuration to
set policy for specific image sources has been removed in favor of
the simple hardcoded policy values described above. In particular,
`QUERY_USER_ON_SECURITY_VIOLATION` and `ALLOW_EXECUTE_ON_SECURITY_VIOLATION`
have been removed, along with the ability to associate them with specific
image sources (option-ROMs, removable media, fixed media) via PCDs. This is
a deliberate simplification as no binary should be executed unless it can be
verified.

### Design notes for future maintainers

- If new image-source categories are added, add a new probe helper
  alongside `IsFromFv` and extend `GetImageType` to consult it. Each
  probe should be a single-responsibility function returning
  `EFI_SUCCESS`/`EFI_NOT_FOUND`/`EFI_INVALID_PARAMETER` so it can be
  mocked and unit-tested in isolation.
- Never broaden the `default` arm of `GetPolicyForImageType` to
  something more permissive than `DENY_EXECUTE_ON_SECURITY_VIOLATION`.
  The verification handler relies on this fail-closed behavior for
  unrecognized image sources.
- `IsFromFv` uses `EFI_OPEN_PROTOCOL_TEST_PROTOCOL` so it never has to
  call `CloseProtocol`. Do not switch to `BY_HANDLE_PROTOCOL` etc.
  without re-auditing the open/close balance.

## PE/COFF Header Parsing (`Support.c` / `Support.h`)

`GetImageSecurityDataDirectory (FileBuffer, FileSize, SecDataDir)`
extracts the `EFI_IMAGE_DIRECTORY_ENTRY_SECURITY` data directory from
an in-memory PE/COFF image. PE/COFF image parsing is delegated to `PeCoffLib`.
A DataDirectoryRead hook is used to capture the security directory entry if it
exists, and a bounded image reader is used to ensure that every read PeCoffLib
performs is within the bounds of the file size.

### Bounded image reader

`PeCoffLib`'s stock `PeCoffLoaderImageReadFromMemory` does **no** bounds
checking — it `CopyMem`s from `FileHandle + FileOffset` for the
caller-requested size. This is acceptable for FV-resident images, which are
inherently trusted as they live in an FV. However, this codepath is also used
parse images from untrusted sources (e.g. Option ROMs, removable media, etc.),
so every read must be validated against the declared file size to prevent
malformed headers from causing buffer overflows or other memory safety
violations.

- The image handle passed to PeCoffLib is a pointer to an internal
  `PE_COFF_IMAGE_HANDLE { CONST UINT8 *Base; UINTN Size; }` struct that
  describes the image buffer and its size. This allows the bounded reader to
  validate every read against file size.
- `BoundedImageRead` follows the `PE_COFF_LOADER_READ_FILE` contract
  from `MdePkg/Include/Library/PeCoffLib.h`: an offset at or past EOF
  returns `RETURN_SUCCESS` with `*ReadSize = 0`; a request that
  straddles EOF is clamped so `*ReadSize` reflects only the bytes
  actually available. PeCoffLib's own header parsers reject the
  truncated reads, so malformed images still fail with `EFI_LOAD_ERROR`
  rather than silently corrupting downstream parses.
- The optional `PE_COFF_LOADER_READ_DATA_DIRECTORY` hook
  (`ImageContext.DataDirectoryRead` /
  `ImageContext.DataDirectoryReadContext`) is used to capture the
  security directory entry; the callback only records the entry whose
  `Index == EFI_IMAGE_DIRECTORY_ENTRY_SECURITY` and ignores everything
  else.

### Design notes for future maintainers

- **Do not** call `PeCoffLoaderImageReadFromMemory` directly — it is
  unsafe on untrusted input. Always install `BoundedImageRead` (or an
  equivalently bounds-checked reader) when invoking PeCoffLib on a
  buffer whose size is known up front.
- `BoundedImageRead` must remain spec-compliant (clamp, do not fail
  with `INVALID_PARAMETER`, on partial reads). Returning an error code
  in that case would cause PeCoffLib to abort even for benign reads
  near the end of a well-formed image.
- The `PE_COFF_IMAGE_HANDLE` name is deliberately namespaced to PE/COFF
  to avoid colliding with UEFI's `EFI_HANDLE` / `ImageHandle`
  (LoadImage) concepts.

## Structure Iterators (`Iterator.c` / `Iterator.h`)

Three forward-only iterators centralize the structural validation of the
attacker-controlled containers this library walks:

- `SIG_DATABASE_ITER` - each `EFI_SIGNATURE_LIST` in a `db` / `dbx` / `dbt`
  buffer.
- `SIG_LIST_ITER` - each `EFI_SIGNATURE_DATA` entry inside one
  `EFI_SIGNATURE_LIST`.
- `WIN_CERT_ITER` - each `WIN_CERTIFICATE` in a PE/COFF security data
  directory.

All three share an `Init` / `Next` contract. `<Structure>Init(..)` validates
the container and establishes the iteration range; `<Structure>Next(..)`
returns the next item (or `NULL` once the range is exhausted) and is
infallible after `Init` has run.

### Truncation contract (return `BOOLEAN`, never log)

`Init` is **not fallible**. Rather than rejecting a container that is
malformed partway through, it clamps the iteration range to the valid prefix:
it stops at the first entry that fails to parse and iterates only the entries
that precede it. `Init` returns a `BOOLEAN`:

- `TRUE`  - the whole container parsed cleanly; the iterator covers every
  entry.
- `FALSE` - the range was truncated (one or more trailing entries were
  dropped, or the inputs were unusable, e.g. a NULL pointer). The exposed
  iterator is still safe to use and covers the valid prefix (possibly empty).

`Init` **never logs**. Callers decide what to log based on the returned
boolean, so the parsing primitive stays free of policy and each call site can
describe the container it is walking.

### Design notes for future maintainers

- Truncation-to-empty is the safe default for unusable inputs (NULL `Iter`,
  NULL buffer with a non-zero size, or size fields that leave the entry
  stride undeterminable): the iterator yields nothing and `Next` returns
  `NULL` immediately.
- `Next` must remain infallible. All bounds and consistency checks belong in
  `Init` so the hot iteration path is a simple advance. Do not add validation
  to `Next`.
- Call sites currently treat a `FALSE` return (truncation) the same way they
  treated the old `EFI_ERROR` return (fail-closed for `dbx` revocation paths,
  skip-the-list for the `db` authorization walks) - that is, they check
  `if (!<Structure>Init (...))`. The intent is to later revisit call sites so
  they consume the valid prefix instead of aborting.
- Because `Init` no longer emits diagnostics, any log about a malformed
  container must live at the call site. Prefer `DEBUG_WARN` and name the
  container (db / dbx / certificate table) being walked.

## Signature Database Helpers (`Database.c` / `Database.h`)

`Database.c` contains parsers for Secure Boot's `db`, `dbx`, and `dbt`
UEFI variables, plus a helper to load them from variable storage.
Every walker treats its buffer as untrusted input.

- `LoadSignatureDatabase (DatabseName, OutBuffer, OutSize)` is a wrapper around
  `GetVariable2` that normalizes `EFI_NOT_FOUND` to `EFI_SUCCESS`, but allows
  `*OutBuffer` to be `NULL` and `*OutSize` to be 0 in that case.
- `LoadSignatureDatabases (Db, DbSize, Dbx, DbxSize, HashAlgorithms)` is the
  one-shot setup helper used by every image-validation path. It loads db
  and dbx from variable storage and populates `HashAlgorithms` with the
  set of image-hash signature types currently enrolled. On failure it
  frees any partial allocations so the caller never has to. Callers are
  responsible for `FreePool`-ing `*Db` and `*Dbx` on success.
- `WalkSignatureDatabase (Buffer, BufferSize, Callback, Context)` is the single
  source of structural validation for the signature database buffers. This
  function validates the 0..N list of `EFI_SIGNATURE_LIST`s, and will execute
  the provided callback for earch `EFI_SIGNATURE_LIST` in the buffer.

### Design notes for future maintainers

- All EFI_SIGNATURE_LIST traversal must go through
  `WalkSignatureDatabase`. Do not open-code another walker — the
  centralized validation is what keeps the rest of the helpers safe
  on attacker-controlled buffers.
- `SignatureHeaderSize` is required reading: the first entry begins
  at `(UINT8 *)List + sizeof(EFI_SIGNATURE_LIST) + SignatureHeaderSize`,
  not at the end of the fixed header. Forgetting this offset causes
  silent mis-comparison rather than a crash.
- Keep `IsKnownImageHashGuid` and `mKnownImageHashGuids[]` synchronized
  when adding a new image-hash algorithm; `HASH_ALGORITHM_SET::Guids`
  is sized from that array.
- Any methods that need to parse the signature database should consume the
  database as a `CONST UINT8 *Buffer` and `UINTN BufferSize`. Specifically,
  it should not get the database from the variable itself. This is for
  performance purposes, as the intent is to only get each database a single
  time for each individual image verification.
- Treat `Database == NULL` with `DatabaseSize == 0` as an empty database,
  not an input error. `LoadSignatureDatabase()` normalizes missing variables
  (`EFI_NOT_FOUND`) to that shape, and unsigned-image validation relies on
  this to handle absent `db`/`dbx` variables correctly. Only reject
  `Database == NULL` when `DatabaseSize != 0`.

### Signed-image certificate authorization (chain-relative revocation)

`EvaluateImageCertificate` evaluates one `WIN_CERTIFICATE` and reports a
*verdict* (`IMAGE_CERT_EVALUATION`), performing the `db`/`dbx` decision
with revocation evaluated **relative to the authorizing certificate
chain** rather than globally. The model, and its rationale, for future
maintainers:

- After a prelude (parse PKCS#7 `AuthData`, resolve the Authenticode hash
  algorithm, compute the image digest), it walks every `db` trust anchor. An
  `EFI_CERT_X509_GUID` entry is a
  certificate used directly; an X.509-cert-hash entry (matched via
  `IsX509CertHashGuid`, e.g. `EFI_CERT_X509_SHA256_GUID`) is resolved to
  the certificate carried in the image's own `AuthData` via
  `GetX509FromTbsCertHash` (a thin, unit-tested wrapper over the
  `BaseCryptLib` `GetTrustAnchorX509FromAuthData` primitive). This "cert
  relativeness" lets `db` enroll only a certificate's TBS hash.
- A candidate anchor authorizes the image only when `AuthenticodeVerifyEx`
  confirms it signs the image AND `IsChainRevoked` finds no certificate
  in the returned signer->anchor chain enrolled in `dbx`.
  `AuthenticodeVerifyEx` returns the exact `EFI_CERT_STACK` built and used by
  the verifier, ordered signer..anchor, so revocation does not depend on a
  separate chain reconstruction that could select a different path.
- `IsChainRevoked` checks each chain certificate with `IsInDbx`, the
  single revocation primitive: an `EFI_CERT_X509_GUID` `dbx` entry
  matches by exact DER bytes; an X.509-cert-hash `dbx` entry matches by
  the certificate's TBSCertificate digest under that list's algorithm.
- Return contract: the `EFI_STATUS` says only whether evaluation ran; the
  security outcome is `Evaluation->Verdict`. `EFI_SUCCESS` means "read the
  verdict"; `EFI_INVALID_PARAMETER` means a NULL argument; any other error
  is a genuine image-hash computation failure (propagated from `GetHash`)
  with no verdict produced. The verdict is one of `ImageCertApproved`
  (authorized; `Evaluation->Authority` identifies the `db` entry for PCR 7
  measurement), `ImageCertRevokedByDbx` (an anchor verified but its chain
  is revoked and nothing else authorizes), `ImageCertNotInDb` (no anchor
  verifies), or `ImageCertUnusable` (the certificate could not be
  evaluated: unparseable `WIN_CERTIFICATE` or unknown hash algorithm).
  `ValidateImage` treats only `EFI_SUCCESS` +
  `ImageCertApproved` as "this certificate authorized" and otherwise moves
  on.
- **Fail closed everywhere**: any inability to parse `dbx`, obtain or parse a
  verified chain, resolve a hash, or compute a digest is treated as revoked
  (`IsInDbx` / `IsChainRevoked` return TRUE); a `db` parse problem
  yields an `ImageCertNotInDb` verdict. This deliberately replaced the
  earlier global revocation pass (a now-removed `IsCertRevoked`, which used
  `Pkcs7GetSigners` + a `dbx` `AuthenticodeVerify` pre-check) so a `dbx`
  entry only blocks an image when the revoked certificate actually
  participates in the chain that would authorize it (FR-4).
- BaseCryptLib buffers are caller-owned: free chains returned by
  `AuthenticodeVerifyEx` and resolved anchors via `FreePool`, and the
  trust-anchor cache via `FreeTrustAnchorX509Cache`.
