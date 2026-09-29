# Homebrew distribution

No signed release or public tap is available yet. `scripts/release/homebrew.py`
prepares a **reviewable cask draft** from already downloaded release files. It
does not create a tap, publish, install, start a gateway or enable optional sync.
Linux and Windows use the [verified directory installer](VERIFIED_INSTALL.md);
this Homebrew draft is macOS-only.

## Prepare the draft

Use a separately trusted Runtime checkout on macOS with Python 3.11+, GitHub CLI,
native Apple verification tools and access to both final Mac artifact directories.
Each directory contains the archive, manifest, SPDX SBOM, checksums and publisher
bundle from the same selected release. Obtain the full source revision and Apple
team independently through the release review, not from the downloaded files.

Command template; replace the three uppercase placeholders with reviewed values:

```sh
python scripts/release/homebrew.py \
  --arm-directory release-arm \
  --intel-directory release-intel \
  --commit REVIEWED_FULL_COMMIT_SHA \
  --tag REVIEWED_STABLE_TAG \
  --apple-team REVIEWED_APPLE_TEAM \
  --output mitigate.rb
```

The output parent must exist and `mitigate.rb` must not exist. Exit 0 means a draft
was written after verification, **not** that release/publication was approved.
Exit 2 means unavailable or rejected. Existing files are never replaced.

For each architecture, the generator verifies all four publisher signatures and
their exact repository/workflow/source/tag identity, checks the closed archive
and sidecars, and verifies Apple Developer ID, the independently selected team
and notarization on a private binary copy. It does not run the binary. Both
architectures must pass before output is created. Network trust/notarization
availability is required; there is no unsigned or offline fallback.

The cask uses fixed GitHub release URLs, the reviewed stable version and archive
digests taken from authenticated snapshots. Its only install artifact is a
binary link. Homebrew retains the extracted archive with its license/notices and
metadata. No installer script, service, `sudo`, keychain mutation, automatic
updater, remote configuration or customer-data cleanup hook is generated.

The expected minimum OS comes from the authenticated thin 64-bit Mach-O load
commands, not a guessed marketing support range. Wrong CPU, malformed/bounded
command tables, duplicate minimum declarations and non-macOS platform records
fail. Older minima use Homebrew's existing macOS requirement. A newer minor/patch
minimum requires review rather than silently rounding down. This narrow reader
does not replace native signature verification or prove OS compatibility.

## Validate and publish only after release approval

The generated cask is trusted code and must be reviewed before Homebrew loads it.
For a draft made from accepted artifacts, create an explicitly owned local test
tap and copy the reviewed `mitigate.rb` into its `Casks` directory. Use `brew
tap-new` and `brew --repository` to select that directory. Do not disable
Homebrew's path or trust protection to load arbitrary Ruby files. On versions
with explicit package trust, review the cask and use `brew trust --cask` for that
single fully qualified cask.

On both Mac architectures, substitute the actual test tap's fully qualified
cask name for `OWNED_TEST_TAP/mitigate`:

```sh
brew info --cask --json=v2 OWNED_TEST_TAP/mitigate
brew style --cask OWNED_TEST_TAP/mitigate
brew audit --new --cask OWNED_TEST_TAP/mitigate
brew install --cask OWNED_TEST_TAP/mitigate
mitigate version --json
mitigate mcp scan --root . --json
brew uninstall --cask OWNED_TEST_TAP/mitigate
```

Remove only the owned test cask's trust entry and empty test tap after validation.
Run scan against a deliberate synthetic test project, not an unrelated working
directory. Confirm ordinary-user install, useful scan output, binary identity,
package removal and preservation of existing Runtime data. Online audit and
release URL checks cannot pass until the owner-approved release actually exists.
Do not disable quarantine/Gatekeeper or replace signatures to pass installation.

Only after the [release gates](RELEASE_PIPELINE.md) and actual installation checks
pass should a maintainer review the draft into an owned protected Homebrew tap.
No tap repository name or successful installation is invented here. The future
user-facing command should select that reviewed tap explicitly.

Homebrew verifies the fixed archive digest in the trusted tap definition; it does
not repeat our GitHub attestation command during install. That trust transition
is deliberate: the draft generator authenticates the bytes, and the reviewed tap
pins their digest. Homebrew, the protected tap and native macOS trust are part of
the installation boundary. No arbitrary URLs or checksum overrides are accepted.

Synthetic tests authenticate fixture archives with mocked publisher/Apple
boundaries. Native CI also loads the generated definition through an explicitly owned temporary
Homebrew tap, removing only its own trust entry/tap afterward. It never downloads
or installs fixture bytes, and the mutation test is skipped outside native CI. These do not establish
successful installation of an authentic signed release.

Provider references: [Homebrew cask cookbook](https://docs.brew.sh/Cask-Cookbook)
and [Apple Mach-O declarations](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h).
Homebrew is BSD-2-Clause licensed; no Homebrew implementation code is vendored.
