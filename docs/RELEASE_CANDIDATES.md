# Release candidates

`Package candidates` builds the native CLI for Linux x64 (Ubuntu 22.04), Windows
x64 (Server 2022), macOS arm64 (14) and macOS x64 (15). These are test candidates,
not supported public releases. Each job builds from its clean checked-out commit,
uses the pinned Rust toolchain and locked dependencies, and exercises the packaged
binary in fresh synthetic state. No Runtime account, enrollment, customer files,
Platform access or signing credential is used.

## Build and verify locally

Use Python 3.11 or newer, the pinned Rust toolchain, and the native C toolchain
specified in the README. Run from a clean, committed checkout on the target OS.
The output directory must not already exist. For example, on Linux x64:

```sh
python scripts/release/test_release.py
python scripts/release/package.py --target x86_64-unknown-linux-gnu --output dist/candidate
python scripts/release/smoke.py dist/candidate --target x86_64-unknown-linux-gnu --commit "$(git rev-parse HEAD)"
```

Other native targets are `x86_64-pc-windows-msvc`, `aarch64-apple-darwin` and
`x86_64-apple-darwin`. Cross-compiling without native execution does not satisfy
this gate. Custom compiler flags and wrappers are refused. The packager checks
source cleanliness and revision both before and after the build. A trusted build
host, toolchain and Cargo configuration remain prerequisites; this is not a
hermetic build sandbox.

## Artifact contents

The ZIP includes the CLI, Runtime license and notice, dependency license texts,
Rust standard-library copyright/exception notices, SPDX 2.3 build-input inventory,
build information and test-only instructions. The companion manifest binds the
archive and each member to SHA-256, size and executable mode. `SHA256SUMS` covers
the ZIP, manifest and companion SPDX document.

The SPDX graph starts at the CLI and follows resolved normal/build dependencies
for the native target. Dev-only and unrelated workspace packages are excluded.
Registry packages have their exact Cargo.lock archive hashes. Local/vendored
packages use source identities tied to the repository commit, never workstation
paths. The patched SQLite C version is recorded separately from its Rust binding.
License notices include nested upstream notices; absent notices fail packaging.
The Rust standard library has a separate aggregate entry and the toolchain's
complete library notice file. Compiler executables and host system libraries are
not represented as bundled application packages. The graph is conservative build
input evidence, not a claim that each dependency's code is reachable at runtime.

Archive paths, member order, modes and timestamps are fixed. Identical input
bytes produce identical ZIP bytes on the same Python/zlib implementation. This
does not establish bit-for-bit Rust builds across hosts. Build metadata records
the source commit, target, compiler, Cargo.lock digest and toolchain-file digest.

The smoke harness rejects unknown/duplicate fields, unsupported targets, wrong
commits, tampered bytes, oversize archives, duplicate/traversal paths and symlink
entries before executing anything. It uses a new temporary directory and runs
version, configuration validation, an empty scan, privacy self-test and egress
inspection. A malformed configuration must return the documented error without
its synthetic content. Native credential and full gateway tests remain in Verify;
this smoke does not replace them.

## Distribution boundary

Checksums detect changed bytes; they do not authenticate a publisher. The smoke
harness is only for a trusted locally built/CI candidate and is not an installer.
Candidate CI has read-only repository permission, no signing or OIDC authority,
no release upload and seven-day test artifact retention. Pull-request artifacts
must never be promoted directly into customer releases.

Before public distribution, the release standard still requires a protected,
clean, CI-green source revision and tag, authenticated artifacts/manifests with
provenance, macOS signing/notarization, release notes and rollback guidance, and
fresh-machine install/use acceptance. An installer must verify publisher identity
and the intended version/revision before extraction or execution; unsigned
`latest` downloads are forbidden. No automatic update, Homebrew publication,
container release, supported-platform claim or signing/notarization success is
implied by candidate packaging.

The two new CI tools are build-only GitHub actions, pinned to reviewed release
commits: `actions/setup-python` v7.0.0 and `actions/upload-artifact` v7.0.1 (both
MIT). They download a fixed Python version/upload test artifacts through GitHub;
neither enters the Runtime binary or sensitive request path. This slice adds no
Cargo dependency or Runtime network capability. Their documented interfaces and
runner labels are from the [GitHub action](https://github.com/actions/upload-artifact)
and [runner image](https://github.com/actions/runner-images) repositories. The SBOM
uses the [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/).
