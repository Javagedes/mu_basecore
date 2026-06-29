# ImageValidationTestApp

## Overview

`ImageValidationTestApp` is a UEFI shell test application that validates image authentication
behavior before loading an image. Its purpose is to ensure the platform image validation handler
(invoked by `LoadImage`) meets UEFI specification Secure Boot requirements based on the provided
inputs:

- Image type (unisgned, signed, dual-signed)
- `db` (allowed signatures/hashes)
- `dbx` (revoked signatures/hashes)

## Test Framework

A simple framework was created so that each test scenario specifies the image type, `db`/`dbx`
contents, and the expected output. The framework itself follows the same flow for each test
scenario:

1. Build synthetic `db` and `dbx` databases from scenario bit flags.
2. Hook `GetVariable` so reads the following variables return scenario controlled values:
    - `db`
    - `dbx`
    - `SecureBoot`
3. Call `LoadImage` on the scenario-selected built-in image buffer.
4. Compare the returned `EFI_STATUS` to the scenario's expected result.

The `GetVariable` hook exists only for the duration of test execution and is
restored afterward.

## Supported Image Types

The test supports three image classes:

1. `IMAGE_TYPE_UNSIGNED`
    - Unsigned PE/COFF image.

2. `IMAGE_TYPE_SIGNED`
    - Single PKCS#7 Authenticode signature (`WIN_CERTIFICATE`).
    - Signature chain includes signer 1 certificates:
    - `SIGNER1_ROOT`
    - `SIGNER1_INTERMEDIATE`
    - `SIGNER1_LEAF`

3. `IMAGE_TYPE_DUAL_SIGNED`
    - Two PKCS#7 Authenticode signatures.
    - Signature 1 is the same signer 1 chain as `IMAGE_TYPE_SIGNED`.
    - Signature 2 is a signer chain only containing `SIGNER2`.

## DB / DBX Scenario Flags

Scenario inputs use `DB_STATE_*` bit flags. These flags describe what is added
to the generated `db` or `dbx` EFI signature database for that scenario.

`db` and `dbx` use the same flags. The meaning of a flag is identical in both;
only whether it allows (`db`) or revokes (`dbx`) changes behavior.

### Flag Definitions

Flags can be OR-combined to place multiple signature lists into one database.

1. `DB_STATE_EMPTY`
    - `GetVariable` returns `EFI_NOT_FOUND`

2. `DB_STATE_IMAGE_DIGEST`
    - Add the image's Authenticode SHA-256 digest as an `EFI_CERT_SHA256_GUID` entry.

3. `DB_STATE_SIGNER1_LEAF_CERT`
    - Add signer 1 leaf X.509 certificate (`EFI_CERT_X509_GUID`).

4. `DB_STATE_SIGNER1_INTERMEDIATE_CERT`
    - Add signer 1 intermediate X.509 certificate.

5. `DB_STATE_SIGNER1_ROOT_CERT`
    - Add signer 1 root X.509 certificate.

6. `DB_STATE_SIGNER2_CERT`
    - Add signer 2 X.509 certificate (used by dual-signed image scenarios).

## GenTestData.py

`GenTestData.py` generates architecture-specific test data from input EFI
images. It signs images, computes Authenticode digests, and emits C source data
used by this test app.

### Inputs

- `--x64-image <path>`: unsigned X64 EFI image
- `--aarch64-image <path>`: unsigned AARCH64 EFI image

Provide one or both.

### Outputs

Generated files are written to:

- `X64/TestData.c`
- `Aarch64/TestData.c`

These files include:

- Unsigned, signed, and dual-signed image bytes
- Authenticode SHA-256 digests for each image form
- DER certificates for signer 1 chain and signer 2

### Tool Requirements

`GenTestData.py` requires:

- `openssl`
- `sbsign` (from `sbsigntool` / `sbsigntools` package)
- Python 3

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3 openssl sbsigntool
```

Verify tools:

```bash
which python3
which openssl
which sbsign
```

### Typical Linux Usage

Run from this directory:

```bash
python3 GenTestData.py \
	--x64-image X64/HelloWorld.efi \
	--aarch64-image Aarch64/HelloWorld.efi
```

Generate only one architecture:

```bash
python3 GenTestData.py --x64-image X64/HelloWorld.efi
python3 GenTestData.py --aarch64-image Aarch64/HelloWorld.efi
```

### Windows With WSL

Because signing tools are Linux-native in this workflow, run the script inside
WSL.

Example from PowerShell:

```powershell
wsl bash -lc "python3 GenTestData.py --x64-image X64/HelloWorld.efi --aarch64-image Aarch64/HelloWorld.efi"
```

## Notes

- Scenario definitions live in `Scenarios.c`.
- Scenario data structures and `DB_STATE_*` definitions are in
	`ImageValidationTestApp.h`.
- Runtime test behavior and database synthesis are in `ImageValidationTestApp.c`.
