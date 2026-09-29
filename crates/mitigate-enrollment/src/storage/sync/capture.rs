//! Short-lived local producer ownership; no native secret or network access.
use super::{Anchor, Error, Outbox, ReferenceMap, SyncProfile};
use mitigate_egress::{
    CheckedEvent, SyncRef,
    outbox::{Admission, CapturePermit},
    references::LocalKey,
};

/// Own the original enrollment anchor only while mapping/admitting one bounded
/// producer batch. Drop before waiting on a channel, timer or network. A stalled
/// owner prevents pause from falsely reporting that local operations drained.
/// This is not proof that the native credential still exists or authorizes delivery.
pub struct CaptureSession {
    _anchor: Anchor,
    queue: Outbox,
    references: ReferenceMap,
    runtime_ref: SyncRef,
}
impl SyncProfile {
    /// Open only the pinned queue/catalog under the original local owner lock.
    /// Never creates state, unlocks native credentials, changes consent or sends.
    /// Legacy profiles have no catalog and cannot start a metadata producer.
    pub fn capture_session(&self) -> Result<CaptureSession, Error> {
        let path = self.record.reference_file.as_ref().ok_or(Error::Profile)?;
        let anchor =
            Anchor::open(&self.record.enrollment_file, &self.origin).map_err(Error::Enrollment)?;
        self.check_anchor(&anchor)?;
        Ok(CaptureSession {
            _anchor: anchor,
            queue: self.queue()?,
            references: ReferenceMap::open(path, self.record.partition.clone())
                .map_err(Error::References)?,
            runtime_ref: self.record.partition.runtime_ref.clone(),
        })
    }
}
impl CaptureSession {
    /// Exact runtime configured by the immutable profile, not caller input.
    pub fn runtime_ref(&self) -> &SyncRef {
        &self.runtime_ref
    }
    /// Read current capture consent; callers obtain this before copying metadata.
    pub fn permit(&mut self) -> Result<Option<CapturePermit>, Error> {
        self.queue.capture_permit().map_err(Error::Outbox)
    }
    /// Resolve only a still-current capture's local governance keys. A None
    /// result requires discarding the capture, not renewing its permit. Pause
    /// may race after this check; admit performs the authoritative atomic check.
    pub fn resolve(
        &mut self,
        permit: &CapturePermit,
        keys: &[LocalKey],
    ) -> Result<Option<Vec<SyncRef>>, Error> {
        if self.permit()?.as_ref() != Some(permit) {
            return Ok(None);
        }
        self.references
            .resolve(keys)
            .map(Some)
            .map_err(Error::References)
    }
    /// Revalidate typed bytes and original consent together at durable admission.
    /// Failure never authorizes replaying a local tool call.
    pub fn admit(
        &mut self,
        permit: &CapturePermit,
        event: &CheckedEvent,
    ) -> Result<Admission, Error> {
        self.queue
            .admit_captured(event, permit)
            .map_err(Error::Outbox)
    }
}
