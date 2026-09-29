# Verified local installation

`scripts/release/install.py` consumes separately selected local release files,
verifies publisher identity and installs into a **new** directory. It never
downloads or executes a binary, changes PATH, activates a service, changes Runtime
state, overwrites an existing install or selects `latest`. It refuses the unsigned
test candidates produced by the current packaging workflow.

There is no supported signed release yet. This implements the install boundary;
the actual signing workflow, Apple credentials, positive signature/notarization
evidence and fresh-user acceptance remain required. Do not present mock tests or
an unsigned candidate smoke test as proof that a distributed release works.

## Inputs and trust

Run from a separately trusted Runtime checkout with Python 3.11+ and the trusted
GitHub CLI described in [release authentication](RELEASE_AUTHENTICATION.md).
The following is a command template; uppercase values and paths are placeholders:

```sh
python scripts/release/install.py \
  --manifest /path/to/release.manifest.json \
  --manifest-bundle /path/to/manifest.attestation.jsonl \
  --archive /path/to/release.zip \
  --archive-bundle /path/to/archive.attestation.jsonl \
  --commit FULL_40_CHARACTER_COMMIT_SHA --tag v0.1.0 \
  --install-dir /existing/private/parent/mitigate-0.1.0
```

Obtain the expected tag and full revision through a trusted release decision,
not from the downloaded files. On macOS, also supply `--apple-team TEAM_ID`, the
independently trusted ten-character Apple Developer team identifier. No team is
invented or taken from package contents. Other platforms refuse that argument.
The install-directory leaf uses 1–128 ASCII letters/digits/dots/underscores/hyphens,
starting with a letter/digit and excluding portable device names and trailing dots.
Its parent must already exist and be trusted. Administrator privileges are not
required for a directory owned by the current user.

Both manifest and archive independently pass the fixed certificate policy for
`mitigate-co/runtime`, its direct `release.yml` workflow, the selected source/tag,
GitHub Actions issuer and hosted runners. All subsequent reads use those private
authenticated snapshots; changes to the original paths cannot substitute bytes.
No alternate key, custom root, signature bypass or checksum fallback is supported.
GitHub trust refresh and Apple notarization checks may need network access.
This network activity belongs to installation verification, not Runtime telemetry.

The target is selected from the current OS/architecture: Windows x64, Linux x64,
macOS arm64 or macOS x64. There is no cross-target install override. This detection
does not prove minimum OS/glibc support; native fresh-machine acceptance and the
release's supported-system policy must establish that separately.

## Signed release schema 1

The manifest must contain exactly:

- `schema_version: 1`, `kind: "signed_release"`, `version` equal to the selected
  tag without `v`, exact `source_commit` and native `target`;
- `rustc`, a nonempty compiler string of at most 4,096 characters;
- lowercase SHA-256 `cargo_lock_sha256`, `toolchain_file_sha256`, `archive_sha256`;
- `archive`, exactly `mitigate-VERSION-TARGET.zip`, and integer `archive_size`;
- `files`, exactly the eight entries below, each containing only `sha256`, integer
  `size` and boolean `executable`.

The eight entries are `mitigate` (`mitigate.exe` for Windows), `LICENSE`, `NOTICE`,
`THIRD_PARTY_NOTICES.txt`, `RUST_NOTICES.html`, `sbom.spdx.json`, `build-info.json`,
and `INSTALL.txt`. Only the binary is executable. Build-info repeats exactly the
first eight manifest fields (through `toolchain_file_sha256`); its JSON values
must agree. Unknown/duplicate fields, non-UTF-8 JSON and unsupported kind/version
are refused. The signed source and pipeline remain responsible for the license,
SBOM and release instructions' meaning; digest checking is not semantic review.

Manifest/build-info are bounded at 16 KiB; archive at 128 MiB, each expanded file
at 256 MiB and all expanded files at 384 MiB. The ZIP directory is bounded before
entry allocation: exactly eight entries, no split disks, ZIP64, comments or
trailing data, and at most 4 KiB of directory metadata. Entry paths must be the
exact package prefix plus one allowlisted filename. Links, devices, directories,
special/world-writable modes, encryption, unknown compression and extra fields
are rejected. Each member is read with a byte bound, CRC checked and SHA-256
matched; only validated in-memory bytes can reach installation. No `extractall`
or archive-controlled pathname is used. Expanded bytes can require up to the
documented memory budget.

macOS adds `/usr/bin/codesign` strict/all-architecture verification of the binary
in private temporary storage. Its requirement combines Apple's generic anchor,
Developer ID certificate OIDs, the separately selected team's certificate OU,
and `notarized`. A missing tool, timeout or failed requirement prevents creation
of the install directory. Raw command-line binaries cannot carry stapled tickets;
online notarization lookup may be necessary. These checks follow Apple's
[requirement language](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
and [notarization verification guidance](https://developer.apple.com/videos/play/wwdc2019/703/).
They do not replace the release pipeline's hardened-runtime/signing review.

## Completion and recovery

After verification, exclusive directory creation refuses any existing directory,
file or link, including a target created during verification. Static filenames
are created exclusively, flushed and synchronized. Unix uses 0700 for the
directory/binary and 0600 for other files; Windows inherits the trusted parent's
ACL. The saved release manifest and `install-receipt.json` record the selected
public identity and digests. No Runtime credentials, configuration or database
are read. The trusted host/parent and absence of a malicious same-user process
are assumptions; these files are not an immutable authority store.

Exit 0 returns one JSON receipt with `installed: true`, `activated: false`, version,
commit, target, archive/manifest SHA-256 and `apple_verified` (false when not a
macOS target). No candidate code is run. Exit 2 returns only schema version,
`installed: false` and a fixed error code; provider messages and paths are omitted.

A write, chmod, synchronization or temporary cleanup failure may leave a partial
**new** installation, even complete-looking receipt bytes. The command's failure
must not be overridden by a file's presence. Keep the previous installation and
choose a new destination after investigating disk/permissions. No automatic
recursive cleanup or rollback touches the selected install directory. A successful
install also does not itself authorize switching an existing deployment.

To activate a future accepted release, explicitly select its installed executable
in the client configuration or PATH after the release's supported-platform smoke
test. Rollback is a separate operator decision based on release notes and local
schema compatibility; never restore an old authority store or reuse consumed
approvals to obtain a passing result. A Homebrew/distribution wrapper must preserve
the same verification policy. No such wrapper is distributed yet.

## Tests and remaining acceptance

Synthetic tests cover both signature failures, every supported layout, wrong
source/version/target, ambiguous manifests, size limits, path traversal, duplicate
entries, ZIP metadata bombs, modes/symlinks, source replacement, target races,
partial writes and final-sync uncertainty. Apple command policy and failures are
tested; native macOS CI additionally uses the real verifier on unsigned fixture
bytes. Successful unit cases mock publisher/Apple verification. They do not prove
an authentic positive release. The real GitHub CLI's negative test must refuse
an unsigned candidate with a malformed bundle without creating the destination.

Source gates, current security failures, release signing/notarization and clean
machine install/use evidence remain separate acceptance requirements.
