//! Customer-local audit metadata. No payload storage, network or generic SQL API.
//!
//! The hash chain detects unrecomputed modifications, not malicious rewrites or
//! rollback by someone controlling the entire database. This is not a sync schema.

mod call;
mod event;
mod storage;

pub use call::{ApprovalActor, ApprovalChoice, CallContext, CallPhase, OperatorSource};
pub use event::{Attribution, Decision, Event, EventDetails, Operation, ResultClass};
pub use storage::{AuditStore, Page, Record, Retention, Verification};

/// Safe errors deliberately exclude SQLite diagnostics, paths and source values.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// The explicit file cannot be accessed safely or already exists on creation.
    Path,
    /// Database content, schema or hash-chain validation failed. Preserve the file.
    Integrity,
    /// A disk, lock, resource limit or database operation prevented completion.
    Unavailable,
    /// A typed event, retention policy or pagination bound is invalid.
    InvalidInput,
}
impl Error {
    /// Stable machine-readable diagnostic.
    pub fn code(self) -> &'static str {
        match self {
            Self::Path => "audit_path_invalid",
            Self::Integrity => "audit_integrity_failed",
            Self::Unavailable => "audit_unavailable",
            Self::InvalidInput => "audit_input_invalid",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Path => "Cannot open the audit file safely. Use a regular file in a private local directory; init requires a new path.",
            Self::Integrity => "Audit verification failed. Preserve the database for investigation; do not reset or overwrite it.",
            Self::Unavailable => "Audit storage is unavailable. Check disk space, permissions and competing writers, then verify the database before retrying.",
            Self::InvalidInput => "Invalid audit input. Check event fields, retention limits and pagination bounds.",
        })
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}

#[cfg(test)]
mod tests;
