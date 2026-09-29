# Ephemeral Apple signing credentials

`scripts/release/ci_stage.py` is the entrypoint for the future direct release
workflow's protected `sign` job. It composes the
[signing prerequisites](RELEASE_SIGNING_GATES.md), a temporary native Keychain and
[release staging](RELEASE_STAGING.md). No workflow or credential is enabled here.

The job must run on a fresh GitHub-hosted runner after all unprivileged native
build/smoke jobs succeed and a maintainer approves the signing environment. Never
compile dependencies or execute the candidate in this job. Actual installation
and execution belong on a separate acceptance runner without signing authority.

The entrypoint removes all Apple inputs from the process environment before
Git/GitHub subprocesses run. It holds them in process memory while rechecking
current source, failure policy and environment evidence. Blocked prerequisites
prevent decoding or importing keys. Linux/Windows staging rejects accidental
Apple credential configuration and never creates a Keychain.

## Protected environment inputs

Configure these only in the future `release-signing` environment. Never put keys
or passwords in source, workflow YAML, logs, chat or command arguments supplied by
an operator. No real values are provided or invented by this implementation.

| Input | Purpose |
| --- | --- |
| `APPLE_CERTIFICATE_P12_BASE64` | Base64-encoded encrypted Developer ID Application certificate/private key export; at most 1 MiB decoded. |
| `APPLE_CERTIFICATE_PASSWORD` | Nonempty PKCS#12 import password, at most 4 KiB UTF-8. |
| `APPLE_NOTARY_KEY_P8_BASE64` | Base64-encoded App Store Connect team API private key, at most 64 KiB decoded. |
| `APPLE_NOTARY_KEY_ID` | The matching 10-character key identifier. |
| `APPLE_NOTARY_ISSUER_ID` | The matching team API issuer UUID. |
| `APPLE_SIGNING_IDENTITY` | Independently reviewed 40-character certificate fingerprint. |
| `APPLE_TEAM_ID` | Independently reviewed 10-character Apple developer team. |

Use environment secrets for key material/passwords and metadata that the owner
considers private. The public certificate fingerprint and team may be reviewed
environment variables, and the team must also be supplied independently to the
installer. Notary setup validates credentials with Apple; it does not submit a
binary until the later explicit signing/notarization operation.

## Lifetime and failures

The helper creates a random private temporary directory (0700 on macOS), writes
exclusive import files (0600), and creates a separate Keychain with a generated
password. It imports only the explicitly supplied certificate and grants the
native code-signing tool access to that Keychain's signing key. It stores the
notary credential under the fixed `mitigate-release` profile in the same Keychain.
Import files are removed before the caller can sign anything. Only public
identity/team/profile references and the temporary Keychain path reach staging.

Every normal success/failure path attempts native deletion of the owned Keychain,
including partially failed setup. A cleanup failure prevents success even if
release archive bytes already exist; those files must not be attested or reused.
Temporary-directory cleanup follows. The helper never selects an existing user
Keychain, changes the default Keychain or explicitly rewrites the user's search list.

Native `security` operations require passwords briefly in their subprocess argv;
they are passed as argument arrays, never shell text, and command output is
discarded. This is permitted only on the isolated ephemeral signing runner. It
does not protect against a malicious same-user process inspecting argv/memory,
and Python cannot promise memory zeroization. A hard kill or host failure may
prevent cleanup; disposal of the hosted runner is required. This tooling is not
for a developer/customer machine or a persistent self-hosted runner.

Missing/malformed/oversized inputs, wrong host/job, import/ACL failures, notary
authentication failure and cleanup failure all stop the operation with a fixed
category. No automatic credential retry or provider-output dump is performed.

## Verification status

Synthetic tests cover input consumption, closed sizes/identifiers, absence from
child environments, restricted native command selection, private import files,
setup/signing/cleanup failures and separation from non-Apple jobs. Native calls
are mocked; no test imports or uses real keys. Authentic Developer ID import,
notary authentication, signing and fresh-machine verification remain required
with the project's owned account before release. See Apple's
[notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
