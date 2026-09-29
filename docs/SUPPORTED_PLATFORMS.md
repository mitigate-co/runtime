# Platform verification

There is no supported public release yet. The table records the native build/test
matrix; it is not a promise about untested customer OS versions.

| Artifact target | Native candidate runner | Planned install path |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | Ubuntu 22.04 x86-64 | Verified new-directory installation |
| `x86_64-pc-windows-msvc` | Windows Server 2022 x86-64 | Verified new-directory installation |
| `aarch64-apple-darwin` | macOS 14 Apple Silicon | Verified directory or reviewed Homebrew cask |
| `x86_64-apple-darwin` | macOS 15 Intel | Verified directory or reviewed Homebrew cask |

Actual CLI, native credential and security tests also run in the `Verify` matrix.
macOS release artifacts require Developer ID, owned team identity and notarization.
The platform's native secret store must be available for operations that need
secrets. Scanner-only use does not require enrollment or a Platform account.

The ELF/libc baseline, Windows client versions and minimum supported macOS
versions must be confirmed through actual release installation/use tests before
being advertised. A binary's Mach-O minimum load version is extracted for package
requirements, but does not establish tested product support. Homebrew's own
support tiers are independent of Mitigate's candidate runner coverage.

Not currently packaged: Linux arm64/musl, native Windows arm64, universal macOS,
MSI/Intune/Jamf installers, services and containers. WSL is a Linux environment;
its passing tests do not replace native Windows acceptance. No endpoint sandbox
guarantee follows from a passing build or from this platform list.

Before marking a platform supported, retain the exact source/tag and artifact
digests, publisher and platform verification, ordinary-user fresh installation,
representative scan/gateway behavior, privacy/egress checks, uninstall/data
preservation and [upgrade/rollback decision](UPGRADE_AND_ROLLBACK.md).
