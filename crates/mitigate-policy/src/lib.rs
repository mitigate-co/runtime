//! Local, deterministic policy decisions. No network, raw tool payloads or
//! credentials enter the interpreter. Policy source never enters diagnostics.
pub mod approvals;
mod bundle;
mod files;
pub mod grants;
mod input;
mod profile;
mod storage;
#[cfg(test)]
mod tests;

pub use bundle::{ActivePolicy, Authority, Receipt, SignedBundle, public_key};
pub use files::{read_document, write_new};
pub use input::{Decision, GrantState, PolicyInput};
pub use profile::Policy;
pub use storage::PolicyStore;

/// Versioned, deliberately restricted Rego v1 contract.
pub const PROFILE: &str = "mitigate-mcp-rego-v1";
/// Maximum UTF-8 policy source bytes before parsing.
pub const MAX_SOURCE: usize = 16_384;

/// Content-free failures. None of these errors authorize execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The closed input contract was violated.
    Input,
    /// Source is malformed or outside the supported profile/resource bounds.
    Profile,
    /// Evaluation failed, timed out or produced conflicting/undefined output.
    Evaluation,
    /// Bundle format, signature or pinned authority does not match.
    Signature,
    /// A replacement reuses or rolls back an activated version.
    Rollback,
    /// No verified policy is available.
    NoPolicy,
    /// The local file is unsafe, unavailable or already exists on creation.
    Path,
    /// Local storage is unavailable or failed; keep the loaded policy.
    Storage,
    /// Native signing credential is missing, locked, invalid or unavailable.
    Key,
}
impl Error {
    /// Stable diagnostic code, never derived from untrusted content.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Input => "policy_input_invalid",
            Self::Profile => "policy_profile_invalid",
            Self::Evaluation => "policy_evaluation_failed",
            Self::Signature => "policy_bundle_unverified",
            Self::Rollback => "policy_version_rejected",
            Self::NoPolicy => "policy_unavailable",
            Self::Path => "policy_path_unavailable",
            Self::Storage => "policy_store_unavailable",
            Self::Key => "policy_signing_key_unavailable",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Input => "Invalid policy input. Use the documented versioned metadata schema.",
            Self::Profile => "Policy rejected. Check the Mitigate Rego Profile syntax and limits.",
            Self::Evaluation => "Policy evaluation failed closed. Review the rules for conflicts and retry.",
            Self::Signature => "Bundle verification failed. Check its signature, policy reference and pinned public key.",
            Self::Rollback => "Policy version rejected. Sign a newer version; the active policy is unchanged.",
            Self::NoPolicy => "No verified policy is available. Activate a signed bundle before evaluation.",
            Self::Path => "Cannot use the policy file. Check its type, permissions and whether the destination already exists.",
            Self::Storage => "Policy storage failed. Check access, disk space and database integrity. The loaded policy is unchanged.",
            Self::Key => "Cannot use the native signing key. Check its reference and unlock the OS credential store.",
        })
    }
}
impl std::error::Error for Error {}
