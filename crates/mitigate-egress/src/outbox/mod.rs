//! Optional customer-local queue and egress admission journal. Never owns a
//! network handle, workload invocation or an enrollment credential.
#[cfg(test)]
mod consent_tests;
pub(crate) mod db;
mod state;
mod storage;
#[cfg(test)]
mod tests;

use crate::{CheckedEvent, Rejection, SyncRef};
use serde::{Deserialize, Serialize};
use std::fmt;
pub use storage::Outbox;

const MAX_TIME: u64 = 9_007_199_254_740_991;
const LEASE_MS: u64 = 30_000;
const MAX_BACKOFF_MS: u64 = 3_600_000;
const JOURNAL_LIMIT: usize = 128;

/// Capacity and retention apply to pending events and completed-ID receipts.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Pending events, 1–1000. Full queues reject new events without eviction.
    pub max_events: u32,
    /// Admission age in milliseconds, 1000 through seven days.
    pub max_age_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_events: 1000,
            max_age_ms: 7 * 86_400_000,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if !(1..=1000).contains(&self.max_events)
            || !(1000..=7 * 86_400_000).contains(&self.max_age_ms)
        {
            return Err(Error::Input);
        }
        Ok(())
    }
}

/// Immutable queue scope. Provision only after explicit local sync consent.
/// An enrollment reference identifies trusted local configuration; it is not
/// proof of authentication. Enrollment/signing must be checked by a sender.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Partition {
    /// Exact runtime whose validated events may enter this outbox.
    pub runtime_ref: SyncRef,
    /// Separately provisioned destination/organization enrollment mapping.
    pub enrollment_ref: SyncRef,
}

/// Admission results, returned only after their local journal commit succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// New validated event and journal entry committed together.
    Queued,
    /// Identical ID/body already pending or retained as a completed receipt.
    Duplicate,
    /// Privacy rejection; no payload, ID or digest of rejected input is retained.
    Rejected(Rejection),
    /// Event runtime does not match this enrollment's partition.
    WrongRuntime,
    /// Same ID was reused with different accepted facts.
    IdConflict,
    /// Pending capacity exhausted; local tool authorization is unaffected.
    Full,
    /// Explicitly paused outbox; no event was queued.
    Paused,
    /// The capture predates a consent change or belongs to another queue.
    ConsentChanged,
}

/// Opaque consent snapshot for bounded, customer-local producer buffers.
/// Obtain before capture and present unchanged at admission. Cloning does not
/// renew consent. This is not an enrollment credential or a wire identifier.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturePermit(state::CaptureConsent);

/// A delivery result classification supplied by the trusted sender. Never pass
/// a response body/error message. Only transient failures are retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// Authenticated receiver durably accepted this idempotent event ID.
    Accepted,
    /// Transport/temporary service failure; retry the same bytes/ID after backoff.
    Transient,
    /// Permanent schema/privacy refusal; delete this event, never retry unchanged.
    Rejected,
    /// Enrollment no longer authorizes delivery; pause the whole outbox.
    Unauthorized,
}

/// Owned delivery lease. No Clone/Serialize/Debug; a completion consumes it.
/// Its event remains checked, but the sender must verify enrollment, sign and
/// use the configured destination. It must not substitute another body or ID.
pub struct Lease {
    event: CheckedEvent,
    token: SyncRef,
    partition: Partition,
}
impl Lease {
    /// Exact canonical event for this delivery attempt.
    pub fn event(&self) -> &CheckedEvent {
        &self.event
    }
    /// Enrollment scope to compare with the independently verified sender config.
    pub fn partition(&self) -> &Partition {
        &self.partition
    }
}

/// Closed local journal actions. These reports are not Platform telemetry.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
pub enum Action {
    /// Valid event committed.
    Queued,
    /// Existing ID/body observed again.
    Duplicate,
    /// Content/schema validation refused input.
    PrivacyRejected,
    /// Runtime partition mismatch.
    PartitionRejected,
    /// ID collision with a different body.
    IdConflict,
    /// Pending capacity exhausted.
    CapacityRejected,
    /// Explicit/authorization-induced pause, paused admission or stale capture.
    Paused,
    /// Deliberate operator resume.
    Resumed,
    /// Exclusive bounded delivery lease committed.
    Claimed,
    /// Receiver confirmed durable acceptance.
    Delivered,
    /// Bounded transport retry scheduled.
    TransportRetry,
    /// Permanent receiver rejection; payload removed.
    DeliveryRejected,
    /// Admission age exceeded retention.
    Expired,
    /// Operator removed retained queue data.
    Purged,
    /// Unfinished delivery lease expired, so a delayed retry was scheduled.
    LeaseExpired,
}
const ACTIONS: [Action; 15] = [
    Action::Queued,
    Action::Duplicate,
    Action::PrivacyRejected,
    Action::PartitionRejected,
    Action::IdConflict,
    Action::CapacityRejected,
    Action::Paused,
    Action::Resumed,
    Action::Claimed,
    Action::Delivered,
    Action::TransportRetry,
    Action::DeliveryRejected,
    Action::Expired,
    Action::Purged,
    Action::LeaseExpired,
];

/// One bounded local egress decision. Contains no event contents/identifiers.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    /// Monotonic local journal sequence; retained entries form a suffix.
    pub sequence: u64,
    /// Trusted UTC time observed under the transaction lock.
    pub time_ms: u64,
    /// Fixed admission/delivery action.
    pub action: Action,
    /// Number of events represented by this entry, at most 1000.
    pub events: u32,
    /// Byte count capped at 4,097 per event for rejected untrusted input.
    pub bytes: u32,
    /// Fixed privacy rejection category, present only for PrivacyRejected.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rejection: Option<Rejection>,
}

/// Lifetime diagnostic totals. Saturate at the interoperable integer bound.
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Totals {
    /// Number of events represented by the action.
    pub events: u64,
    /// Bounded observed/canonical byte totals.
    pub bytes: u64,
}

/// Named totals; never arbitrary string-keyed diagnostic metadata.
#[derive(Serialize)]
pub struct Counter {
    /// Fixed action name.
    pub action: Action,
    /// Saturating totals for this action.
    pub totals: Totals,
}

/// Local inspector result, with no queued payloads or rejected source material.
#[derive(Serialize)]
pub struct Report {
    /// Local report version.
    pub schema_version: u8,
    /// Configured local enrollment scope; a sender resolves its destination.
    pub partition: Partition,
    /// Whether new admission and delivery are paused.
    pub paused: bool,
    /// Persistent queue bounds.
    pub limits: Limits,
    /// Retained pending events, including leased events.
    pub pending: usize,
    /// Currently leased records (expiry is applied on claim/admit/complete).
    pub leased: usize,
    /// Retained canonical event bytes.
    pub payload_bytes: usize,
    /// Completed ID/digest receipts retained for local duplicate prevention.
    pub receipts: usize,
    /// Fixed action counters.
    pub counters: Vec<Counter>,
    /// Most recent 128 local decisions, bounded further by retention.
    pub recent: Vec<JournalEntry>,
}

/// Fixed storage failures; no paths, SQL, backend messages or candidate bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid limits or trusted operation parameters.
    Input,
    /// Missing/unsafe/nonprivate/oversized local file.
    Path,
    /// Another connection holds the required lock past the bounded wait.
    Busy,
    /// Other SQLite failure, full storage or uncertain commit.
    Storage,
    /// SQLite stopped an operation, including progress-handler budget withdrawal.
    Interrupted,
    /// Unexpected schema, corrupt records or inconsistent state.
    Integrity,
    /// Wrong independently supplied enrollment scope.
    Partition,
    /// Unavailable, out-of-range or backward OS time.
    Clock,
    /// Lease expired, replaced, purged or belongs to another queue.
    StaleLease,
    /// Bounded operation exceeded its work/time budget.
    Budget,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Input => "invalid outbox settings; review the configured bounds",
            Self::Path => "outbox file unavailable; inspect its location and permissions",
            Self::Busy => "outbox is busy; retry from the delivery worker after backoff",
            Self::Storage => "outbox storage unavailable; inspect capacity and access",
            Self::Interrupted => {
                "outbox operation interrupted; inspect local storage health and retry"
            }
            Self::Integrity => "outbox integrity check failed; preserve and inspect the store",
            Self::Partition => "outbox enrollment does not match the selected configuration",
            Self::Clock => "outbox clock check failed; correct the local OS clock",
            Self::StaleLease => "delivery lease is no longer current; do not acknowledge it",
            Self::Budget => "outbox work limit exceeded; inspect local storage health",
        })
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy
            }
            Some(rusqlite::ErrorCode::OperationInterrupted) => Self::Interrupted,
            _ => Self::Storage,
        }
    }
}
