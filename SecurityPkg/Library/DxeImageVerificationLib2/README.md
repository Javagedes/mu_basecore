# DxeImageVerificationLib2

`DxeImageVerificationLib2` is a from-scratch rewrite of
[`DxeImageVerificationLib`](../DxeImageVerificationLib/). The rewrite is
in progress; this document only tracks the behavioral differences that
have already landed.

## Differences from `DxeImageVerificationLib`

### No image execution information table / no Ready-To-Boot handler

The legacy library tracks every image that fails verification (or is
deferred) by appending an entry to the
`EFI_IMAGE_EXECUTION_INFO_TABLE` published in the system configuration
table. To make sure the table exists even on platforms that never failed
a verification, the legacy constructor registers an
`EfiCreateEventReadyToBootEx` callback (`OnReadyToBoot`) that allocates
and installs an empty table at Ready-To-Boot if no other code did first.
This table is part of the UEFI Secure Boot Audit Mode contract: the OS
loader inspects it after the boot to learn which images the firmware
would have rejected.

Because `DxeImageVerificationLib2` does not implement Audit Mode,
there is nothing to publish:

- `OnReadyToBoot` and the Ready-To-Boot event creation in the
  constructor have been removed.
- `DxeImageVerificationLibConstructor` now does only one thing:
  `RegisterSecurity2Handler` for
  `EFI_AUTH_OPERATION_VERIFY_IMAGE | EFI_AUTH_OPERATION_IMAGE_REQUIRED`.
- `DxeImageVerificationHandler` will store the execution information.
