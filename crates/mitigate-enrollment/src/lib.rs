//! Optional Platform enrollment authentication, separate from telemetry admission.
//!
//! Core protocol types perform no I/O. The `storage` module owns native persistence
//! and exclusive recovery. The optional `https` feature provides one explicit
//! authenticated bootstrap request or confirmed signed event exchange. Neither
//! starts background sync nor grants tenant authority. Platform must validate the
//! enrollment grant and ongoing access. The caller owns local consent and durable
//! credential/queue lifecycle. Local MCP operation is independent.

mod claim;
mod code;
pub mod event;
#[cfg(feature = "https")]
pub mod event_https;
#[cfg(feature = "https")]
pub mod https;
pub mod storage;
#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "https"))]
mod tls_fixture;
#[cfg(feature = "https")]
mod transport;

pub use claim::{EnrollmentClaim, EnrollmentKey, EnrollmentReceipt};
pub use code::EnrollmentCode;
use mitigate_egress::SyncRef;
use std::fmt;
use url::Url;

/// Maximum claim and receipt document size before any JSON parsing.
pub const MAX_ENROLLMENT_BYTES: usize = 1024;

/// Closed, content-free failure categories; no source or provider diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Malformed or noncanonical one-use bootstrap code.
    Code,
    /// Platform is not one explicitly configured canonical HTTPS origin.
    Origin,
    /// Persisted private seed is missing or malformed.
    Key,
    /// Two references are identical or otherwise cannot bind an enrollment.
    Identity,
    /// OS randomness is unavailable.
    Randomness,
    /// Receipt is ambiguous, oversized, unsupported or bound to another claim.
    Receipt,
    /// Fixed claim serialization failed.
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Code => "Use a complete enrollment code from your organization.",
            Self::Origin => "Configure one canonical HTTPS Platform origin without a path.",
            Self::Key => "The enrollment key is unavailable or invalid. Check native storage.",
            Self::Identity => "The enrollment references are invalid. Start a new enrollment.",
            Self::Randomness => "Secure enrollment key generation is unavailable.",
            Self::Receipt => "Enrollment was not confirmed. Retain the same request for recovery.",
            Self::Encoding => "The enrollment request could not be encoded.",
        })
    }
}
impl std::error::Error for Error {}

/// Canonical HTTPS origin, independent of untrusted MCP configuration/content.
/// No userinfo, path, query, fragment, implicit normalization or redirects.
#[derive(Clone, PartialEq, Eq)]
pub struct PlatformOrigin(String);
impl PlatformOrigin {
    /// Validate an explicit operator-selected origin before reading a credential.
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() > 256 || !value.is_ascii() {
            return Err(Error::Origin);
        }
        let url = Url::parse(value).map_err(|_| Error::Origin)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.host_str().is_some_and(|host| host.contains('*'))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.origin().ascii_serialization() != value
        {
            return Err(Error::Origin);
        }
        Ok(Self(value.to_owned()))
    }
    /// Destination and signature audience. A transport must not redirect it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Independent, enrollment-scoped opaque references; never workload fingerprints.
#[derive(Clone)]
pub struct EnrollmentIdentity {
    runtime: SyncRef,
    enrollment: SyncRef,
}
impl EnrollmentIdentity {
    /// Generate both references from independent OS randomness.
    pub fn fresh() -> Result<Self, Error> {
        Self::from_references(
            SyncRef::fresh().map_err(|_| Error::Randomness)?,
            SyncRef::fresh().map_err(|_| Error::Randomness)?,
        )
    }
    /// Restore the exact identity for retry; never silently regenerate one field.
    pub fn from_references(runtime: SyncRef, enrollment: SyncRef) -> Result<Self, Error> {
        if runtime == enrollment {
            return Err(Error::Identity);
        }
        Ok(Self {
            runtime,
            enrollment,
        })
    }
    /// Public opaque Runtime correlation reference.
    pub fn runtime_ref(&self) -> &SyncRef {
        &self.runtime
    }
    /// Public opaque enrollment credential reference; not the private signing key.
    pub fn enrollment_ref(&self) -> &SyncRef {
        &self.enrollment
    }
}
