//! Explicit optional sync controls. The immutable local profile binds one queue
//! and reference catalog to one native enrollment; it contains references and
//! paths, never credentials.
//! Pause/purge need no native-store access and drain the enrollment operation lock
//! before confirming completion. These blocking operations do not own MCP calls.
mod capture;
mod profile;
pub use capture::CaptureSession;

use super::{EnrollmentStore, Session, Status, Vault, anchor::Anchor};
use crate::PlatformOrigin;
use mitigate_egress::{
    outbox::{self, Limits, Outbox, Partition, Report},
    references::{self, ReferenceMap},
};
use profile::Record;
use std::{
    fmt,
    path::Path,
    thread,
    time::{Duration, Instant},
};

/// Closed control failures. No local paths, credential values or provider text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid, missing, unsafe or oversized local profile/settings.
    Profile,
    /// Creation never replaces an existing profile, queue or enrollment.
    Exists,
    /// A private profile write could not be confirmed; inspect before retrying.
    Storage,
    /// Native binding/confirmation is unavailable; local MCP remains independent.
    Enrollment(super::Error),
    /// Queue mutation could not be confirmed.
    Outbox(outbox::Error),
    /// Local reference mappings could not be verified; preserve the original file.
    References(references::Error),
    /// Queue is paused, but an outstanding operation has not drained yet.
    Draining,
}
impl Error {
    /// Stable local category, independent of content and provider diagnostics.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Profile => "sync_profile",
            Self::Exists => "sync_exists",
            Self::Storage => "sync_storage",
            Self::Enrollment(error) => error.code(),
            Self::Outbox(_) => "sync_outbox",
            Self::References(_) => "sync_references",
            Self::Draining => "sync_draining",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile => f.write_str("Check the private sync profile, paths and queue limits."),
            Self::Exists => f.write_str("Sync state already exists. Inspect or resume it instead of replacing it."),
            Self::Storage => f.write_str("Sync setup could not be confirmed. Inspect its local files before retrying."),
            Self::Enrollment(error) => error.fmt(f),
            Self::Outbox(error) => error.fmt(f),
            Self::References(error) => error.fmt(f),
            Self::Draining => f.write_str("New delivery is paused. An operation is still finishing; retry pause before removing state."),
        }
    }
}
impl std::error::Error for Error {}

/// Immutable local binding. Not network authority: every resume/send independently
/// restores and verifies the confirmed native record. No Clone/Debug/Serialize.
pub struct SyncProfile {
    record: Record,
    origin: PlatformOrigin,
}
impl SyncProfile {
    /// Explicit consent entry point: create a version-two profile, queue and local
    /// reference catalog using a confirmed native enrollment. The catalog is a
    /// new sibling named `<outbox filename>.references.sqlite`. Never enroll,
    /// replace files, adopt an existing catalog or start a sender.
    /// Parent directories must already exist and be trusted/private. A failed
    /// creation can leave partial files; do not silently delete or repair them.
    pub fn create(
        path: &Path,
        enrollment_file: &Path,
        origin: &PlatformOrigin,
        outbox_file: &Path,
        limits: Limits,
    ) -> Result<Self, Error> {
        let store = EnrollmentStore::open(enrollment_file, origin).map_err(Error::Enrollment)?;
        initialize(path, enrollment_file, outbox_file, &store.0, limits)
    }
    /// Read a bounded private profile. Does not unlock credentials, repair state,
    /// change consent, create a queue or access the network.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let record = profile::read(path)?;
        let origin = record.validate()?;
        Ok(Self { record, origin })
    }
    /// Inspect the existing queue without credential/network access or maintenance.
    /// `paused` stops future admission/claims; it does not certify in-flight drain.
    pub fn inspect(&self) -> Result<Report, Error> {
        Outbox::inspect_file(&self.record.outbox_file, self.record.partition.clone())
            .map_err(Error::Outbox)
    }
    /// Explicitly resume only after restoring the exact confirmed native identity.
    /// Does not send or start a worker. Credential failure never enables delivery.
    pub fn resume(&self) -> Result<Report, Error> {
        let _store = self.enrollment()?;
        self.verify_references()?;
        let mut queue = self.queue()?;
        queue.set_paused(false).map_err(Error::Outbox)?;
        queue.inspect().map_err(Error::Outbox)
    }
    /// Stop admission/new attempts, wait up to 25 seconds for an outstanding
    /// native-owner operation, then reconfirm pause under that lock. No native
    /// credential read occurs. Success cannot retract earlier transmitted bytes.
    pub fn pause(&self) -> Result<Report, Error> {
        self.stop(false, Duration::from_secs(25))
    }
    /// Pause/drain, then remove pending bodies and duplicate receipts. Retains
    /// the bounded content-free journal, profile, local reference catalog and
    /// immutable enrollment anchor. Retained mappings prevent identity rotation
    /// when this enrollment is resumed.
    /// Never deletes credentials or claims to remove previously hosted records.
    pub fn purge(&self) -> Result<Report, Error> {
        self.stop(true, Duration::from_secs(25))
    }
    /// One explicit attempt. No native prompt occurs after a lease is claimed.
    /// The enrollment lock serializes sends, resume, stop and credential deletion.
    #[cfg(feature = "https")]
    pub fn deliver_next(&self) -> Result<crate::event_https::Delivery, DeliveryError> {
        if self.inspect().map_err(DeliveryError::Control)?.paused {
            return Ok(crate::event_https::Delivery::Idle);
        }
        let store = self.enrollment().map_err(DeliveryError::Control)?;
        let mut queue = self.queue().map_err(DeliveryError::Control)?;
        crate::event_https::deliver_next(&store, &mut queue).map_err(DeliveryError::Delivery)
    }
    fn enrollment(&self) -> Result<EnrollmentStore, Error> {
        let store = EnrollmentStore::open(&self.record.enrollment_file, &self.origin)
            .map_err(Error::Enrollment)?;
        self.check_anchor(&store.0.anchor)?;
        if !matches!(store.status(), Status::Confirmed { .. }) {
            return Err(Error::Enrollment(super::Error::Pending));
        }
        if &self.record.partition.runtime_ref != store.identity().runtime_ref()
            || &self.record.partition.enrollment_ref != store.identity().enrollment_ref()
        {
            return Err(Error::Enrollment(super::Error::Scope));
        }
        Ok(store)
    }
    fn queue(&self) -> Result<Outbox, Error> {
        Outbox::open(&self.record.outbox_file, self.record.partition.clone()).map_err(Error::Outbox)
    }
    fn verify_references(&self) -> Result<(), Error> {
        if let Some(path) = &self.record.reference_file {
            ReferenceMap::open(path, self.record.partition.clone()).map_err(Error::References)?;
        }
        Ok(())
    }
    fn check_anchor(&self, anchor: &Anchor) -> Result<(), Error> {
        if anchor.reference.as_str() != self.record.native_reference {
            return Err(Error::Enrollment(super::Error::Scope));
        }
        Ok(())
    }
    fn stop(&self, purge: bool, wait: Duration) -> Result<Report, Error> {
        let mut queue = self.queue()?;
        // First persist withdrawal without needing the native broker or its lock.
        // A sender still waiting on an unlock prompt must observe this pause.
        queue.set_paused(true).map_err(Error::Outbox)?;
        let deadline = Instant::now() + wait;
        let anchor = loop {
            match Anchor::open(&self.record.enrollment_file, &self.origin) {
                Ok(anchor) => break anchor,
                Err(super::Error::Busy) if Instant::now() < deadline => {
                    thread::sleep(
                        Duration::from_millis(25)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(super::Error::Busy) => return Err(Error::Draining),
                Err(error) => return Err(Error::Enrollment(error)),
            }
        };
        self.check_anchor(&anchor)?;
        // An explicit resume could have won the lock between the first pause
        // and this acquisition. Reassert withdrawal before reporting shutdown.
        if purge {
            queue.purge().map_err(Error::Outbox)?;
        } else {
            queue.set_paused(true).map_err(Error::Outbox)?;
        }
        queue.inspect().map_err(Error::Outbox)
    }
    #[cfg(test)]
    pub(super) fn stop_now(&self, purge: bool) -> Result<Report, Error> {
        self.stop(purge, Duration::ZERO)
    }
}

/// One-attempt failures preserve the distinction between local control and HTTPS.
#[cfg(feature = "https")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryError {
    /// Profile, credential or queue setup failed before starting an attempt.
    Control(Error),
    /// Delivery or local completion failed; retain/reconcile the queue.
    Delivery(crate::event_https::Error),
}
#[cfg(feature = "https")]
impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(error) => error.fmt(f),
            Self::Delivery(error) => error.fmt(f),
        }
    }
}
#[cfg(feature = "https")]
impl std::error::Error for DeliveryError {}

pub(super) fn initialize<V: Vault>(
    path: &Path,
    enrollment_file: &Path,
    outbox_file: &Path,
    session: &Session<V>,
    limits: Limits,
) -> Result<SyncProfile, Error> {
    if !matches!(session.status(), Status::Confirmed { .. }) {
        return Err(Error::Enrollment(super::Error::Pending));
    }
    if !(1..=1000).contains(&limits.max_events)
        || !(25_001..=7 * 86_400_000).contains(&limits.max_age_ms)
    {
        return Err(Error::Profile);
    }
    let enrollment_file = enrollment_file.canonicalize().map_err(|_| Error::Profile)?;
    let path = profile::new_path(path)?;
    let outbox_file = profile::new_path(outbox_file)?;
    let reference_file = profile::reference_path(&outbox_file)?;
    if path == enrollment_file
        || path == outbox_file
        || outbox_file == enrollment_file
        || reference_file == path
        || reference_file == enrollment_file
    {
        return Err(Error::Profile);
    }
    let record = Record {
        schema_version: 2,
        platform: session.anchor.origin.as_str().to_owned(),
        enrollment_file,
        outbox_file,
        reference_file: Some(reference_file.clone()),
        native_reference: session.anchor.reference.as_str().to_owned(),
        partition: Partition {
            runtime_ref: session.record.identity.runtime_ref().clone(),
            enrollment_ref: session.record.identity.enrollment_ref().clone(),
        },
    };
    let origin = record.validate()?;
    let bytes = profile::encode(&record)?;
    // Reserve an empty profile first; partial setup never looks usable. Keep the
    // native owner locked until queue, catalog and immutable profile are durable.
    let file = profile::reserve(&path)?;
    drop(
        Outbox::create(&record.outbox_file, record.partition.clone(), limits)
            .map_err(Error::Outbox)?,
    );
    drop(
        ReferenceMap::create(&reference_file, record.partition.clone())
            .map_err(Error::References)?,
    );
    profile::finish(file, &path, &bytes)?;
    Ok(SyncProfile { record, origin })
}
