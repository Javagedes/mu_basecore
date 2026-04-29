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

### Policy module

The image-source classification and policy lookup have been deliberately
simplified.

#### Image classification (`GetImageType`)

The legacy library distinguishes five image sources, derived from a mix
of `LocateDevicePath`, `BlockIo->Media->RemovableMedia`,
`SimpleFileSystem`, and a walk of the device path looking for
`MEDIA_RELATIVE_OFFSET_RANGE_DP` and `MSG_MAC_ADDR_DP` nodes:

- `IMAGE_FROM_FV`
- `IMAGE_FROM_OPTION_ROM`
- `IMAGE_FROM_REMOVABLE_MEDIA`
- `IMAGE_FROM_FIXED_MEDIA`
- `IMAGE_UNKNOWN`

`DxeImageVerificationLib2` collapses this to two values:

- `IMAGE_FROM_FV`: the device path resolves to a Firmware Volume.
- `IMAGE_UNKNOWN`: everything else.

`GetImageType` consequently only probes for `gEfiFirmwareVolume2ProtocolGuid`
and falls back to `IMAGE_UNKNOWN`. The Block I/O, Simple File System, and
device-path-node-walk helpers have been removed along with their
dependencies on `DevicePathLib` and the corresponding protocol GUIDs.

#### Policy lookup (`GetPolicyForImageType`)

The legacy library reads three platform PCDs to map the per-source
classification to one of six policy values
(`ALWAYS_EXECUTE`, `NEVER_EXECUTE`, `ALLOW_EXECUTE_ON_SECURITY_VIOLATION`,
`DEFER_EXECUTE_ON_SECURITY_VIOLATION`, `DENY_EXECUTE_ON_SECURITY_VIOLATION`,
`QUERY_USER_ON_SECURITY_VIOLATION`):

- `PcdOptionRomImageVerificationPolicy`
- `PcdRemovableMediaImageVerificationPolicy`
- `PcdFixedMediaImageVerificationPolicy`

`DxeImageVerificationLib2` removes those PCDs and the `PcdLib`
dependency. The mapping is reduced to two values:

| `ImageType`     | Policy                                |
| --------------- | ------------------------------------- |
| `IMAGE_FROM_FV` | `ALWAYS_EXECUTE`                      |
| anything else   | `DENY_EXECUTE_ON_SECURITY_VIOLATION`  |

`ALWAYS_EXECUTE` (`0x0`) and `DENY_EXECUTE_ON_SECURITY_VIOLATION` (`0x1`)
are the only policy values exposed by `Policy.h`.

### Secure Boot enablement check

The legacy handler decides whether Secure Boot is active by reading the
`SecureBoot` UEFI variable directly with `gRT->GetVariable` and then
inspecting the variable's *attributes* alongside its value. The check
treats the platform as "Secure Boot disabled" only when the variable is
present, equals `SECURE_BOOT_MODE_DISABLE`, and has attributes
`BS|RT`. The intent is to keep verification running in Audit Mode, where
the firmware re-publishes `SecureBoot` with a `BS`-only attribute set
even though the value is `0`.

`DxeImageVerificationLib2` removes that attribute-based Audit Mode
inference and instead delegates to
[`SecureBootVariableLib::IsSecureBootEnabled`](../../Include/Library/SecureBootVariableLib.h).
Concretely:

- The handler stops touching `gRT->GetVariable` for `SecureBoot` and
  takes a `SecureBootVariableLib` dependency.
- "Is Secure Boot on?" is now a single boolean answer shared with every
  other consumer of `SecureBootVariableLib` in the tree, instead of an
  ad-hoc check that only this library understood.
- The handler is explicitly framed as a Secure-Boot-only enforcer: when
  `IsSecureBootEnabled()` returns `FALSE`, the handler returns
  `EFI_SUCCESS` because there is nothing for it to enforce. The Audit
  Mode special case is intentionally not re-implemented here; if a
  future change needs Audit-Mode-aware behavior, it should be added to
  `SecureBootVariableLib` so every consumer gets it.

The Secure Boot variable read only happens after policy resolution
returns something other than `ALWAYS_EXECUTE`, so the common case
(FV-dispatched drivers) does not pay for the variable access.
