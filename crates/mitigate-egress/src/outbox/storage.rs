use super::{db, state::*, *};
use crate::MAX_EVENT_BYTES;
use rusqlite::{Connection, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// Bounded SQLite outbox with atomic privacy journal/admission and delivery leases.
/// Synchronous: own on a dedicated worker, never the tool authorization path.
/// A failure returns no delivery lease; uncertain commits are inspected on reopen.
pub struct Outbox {
    conn: Connection,
    partition: Partition,
    #[cfg(test)]
    pub(super) test_time: Option<u64>,
}
impl Outbox {
    /// Inspect an existing store through a read-only SQLite connection. Performs
    /// no maintenance, file creation, schema change or write-journal recovery.
    pub fn inspect_file(path: &Path, partition: Partition) -> Result<Report, Error> {
        let mut store = Self {
            conn: db::readonly(path)?,
            partition,
            #[cfg(test)]
            test_time: None,
        };
        store.inspect()
    }
    #[cfg(test)]
    pub(super) fn connection(&self) -> &Connection {
        &self.conn
    }
    /// Create a new private store, never overwrite or auto-repair one. The caller
    /// must obtain explicit local sync consent and pin enrollment separately.
    pub fn create(path: &Path, partition: Partition, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        db::create_file(path)?;
        let mut conn = db::connect(path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        db::initialize(&tx, &State::new(partition.clone(), limits)?)?;
        tx.commit()?;
        Ok(Self {
            conn,
            partition,
            #[cfg(test)]
            test_time: None,
        })
    }
    /// Open only a valid existing store for exactly this independently configured
    /// runtime/enrollment pair. Verify all retained candidates before use.
    pub fn open(path: &Path, partition: Partition) -> Result<Self, Error> {
        let mut result = Self {
            conn: db::connect(path)?,
            partition,
            #[cfg(test)]
            test_time: None,
        };
        result.inspect()?;
        Ok(result)
    }
    /// Validate candidate input before persistence. Accepted events and the local
    /// journal commit together. Rejections retain only bounded counts/reasons.
    /// They are not queued for retry, and rejected bytes/IDs/digests are discarded.
    pub fn admit(&mut self, bytes: &[u8]) -> Result<Admission, Error> {
        self.admit_with_permit(bytes, None)
    }
    /// Admit a typed local capture only if its original consent is still current.
    /// The comparison and admission share the same SQLite write transaction.
    /// A rejected capture must be discarded, never retried with a fresh permit.
    pub fn admit_captured(
        &mut self,
        event: &CheckedEvent,
        permit: &CapturePermit,
    ) -> Result<Admission, Error> {
        self.admit_with_permit(event.as_bytes(), Some(permit))
    }
    fn admit_with_permit(
        &mut self,
        bytes: &[u8],
        permit: Option<&CapturePermit>,
    ) -> Result<Admission, Error> {
        let candidate = CheckedEvent::from_bytes(bytes);
        let observed = bytes.len().min(MAX_EVENT_BYTES + 1);
        self.update(|state, rows, receipts| {
            if permit.is_some_and(|p| state.capture.as_ref() != Some(&p.0)) {
                state.record(Action::Paused, 1, 0, None)?;
                return Ok(Admission::ConsentChanged);
            }
            let event = match candidate {
                Ok(event) => event,
                Err(reason) => {
                    state.record(Action::PrivacyRejected, 1, observed, Some(reason))?;
                    return Ok(Admission::Rejected(reason));
                }
            };
            let bytes = event.as_bytes().len();
            let (action, admission) = if event.runtime_ref() != &state.partition.runtime_ref {
                (Action::PartitionRejected, Admission::WrongRuntime)
            } else if state.paused {
                (Action::Paused, Admission::Paused)
            } else if let Some(existing) = rows.get(event.event_id().as_str()) {
                if existing.event.as_bytes() == event.as_bytes() {
                    (Action::Duplicate, Admission::Duplicate)
                } else {
                    (Action::IdConflict, Admission::IdConflict)
                }
            } else if let Some(existing) = receipts.get(event.event_id().as_str()) {
                if existing.digest == digest(event.as_bytes()) {
                    (Action::Duplicate, Admission::Duplicate)
                } else {
                    (Action::IdConflict, Admission::IdConflict)
                }
            } else if rows.len() >= state.limits.max_events as usize {
                (Action::CapacityRejected, Admission::Full)
            } else {
                rows.insert(
                    event.event_id().as_str().to_owned(),
                    Record {
                        event: String::from_utf8(event.as_bytes().to_vec())
                            .map_err(|_| Error::Integrity)?,
                        admitted_ms: state.last_time,
                        attempts: 0,
                        next_ms: state.last_time,
                        lease: None,
                    },
                );
                (Action::Queued, Admission::Queued)
            };
            state.record(action, 1, bytes, None)?;
            Ok(admission)
        })
    }
    /// Claim one ready event for thirty seconds. Dropping a lease never marks it
    /// delivered. Expiry schedules a delayed retry with the same event ID/body.
    pub fn claim(&mut self) -> Result<Option<Lease>, Error> {
        self.update(|state, rows, _| {
            if state.paused {
                return Ok(None);
            }
            let id = rows
                .iter()
                .filter(|(_, r)| r.lease.is_none() && r.next_ms <= state.last_time)
                .min_by_key(|(id, r)| (r.admitted_ms, *id))
                .map(|(id, _)| id.clone());
            let Some(id) = id else {
                return Ok(None);
            };
            let record = rows.get_mut(&id).ok_or(Error::Integrity)?;
            let event = record.checked(&id, state)?;
            let token = SyncRef::fresh().map_err(|_| Error::Storage)?;
            record.attempts = record.attempts.saturating_add(1).min(16);
            record.lease = Some(DeliveryLease {
                token: token.clone(),
                until_ms: state.last_time + LEASE_MS,
            });
            state.record(Action::Claimed, 1, event.as_bytes().len(), None)?;
            Ok(Some(Lease {
                event,
                token,
                partition: state.partition.clone(),
            }))
        })
    }
    /// Recheck consent, exact ownership and remaining time immediately before a
    /// sender starts I/O. The budget must cover its entire bounded exchange and
    /// completion. A false result forbids sending; this never extends a lease.
    /// Pause/purge can still race after return, so the sender must coordinate
    /// shutdown separately and never claim an in-flight request was retracted.
    pub fn delivery_ready(&mut self, lease: &Lease, budget_ms: u64) -> Result<bool, Error> {
        if !(1..=LEASE_MS).contains(&budget_ms) {
            return Err(Error::Input);
        }
        self.update(|state, rows, _| {
            let id = lease.event.event_id().as_str();
            let record = rows.get(id).ok_or(Error::StaleLease)?;
            let current = record.lease.as_ref().ok_or(Error::StaleLease)?;
            if state.partition != lease.partition || current.token != lease.token {
                return Err(Error::StaleLease);
            }
            if record.event.as_bytes() != lease.event.as_bytes() {
                return Err(Error::Integrity);
            }
            Ok(!state.paused
                && current.until_ms.saturating_sub(state.last_time) > budget_ms
                && (record.admitted_ms + state.limits.max_age_ms).saturating_sub(state.last_time)
                    > budget_ms)
        })
    }
    /// Record a classified response only for the still-current lease. Completion
    /// consumes the handle; stale acknowledgements cannot remove a newer attempt.
    /// Transient delivery is at-least-once: the receiver must deduplicate event IDs.
    pub fn complete(&mut self, lease: Lease, outcome: DeliveryOutcome) -> Result<(), Error> {
        self.update(|state, rows, receipts| {
            let id = lease.event.event_id().as_str();
            let current = rows.get(id).and_then(|r| r.lease.as_ref());
            if state.partition != lease.partition
                || current.is_none_or(|l| l.token != lease.token || l.until_ms <= state.last_time)
            {
                return Err(Error::StaleLease);
            }
            let record = rows.get_mut(id).ok_or(Error::StaleLease)?;
            if record.event.as_bytes() != lease.event.as_bytes() {
                return Err(Error::Integrity);
            }
            let bytes = record.event.len();
            let action = match outcome {
                DeliveryOutcome::Accepted | DeliveryOutcome::Rejected => {
                    let record = rows.remove(id).ok_or(Error::StaleLease)?;
                    receipts.insert(
                        id.to_owned(),
                        Receipt {
                            digest: digest(record.event.as_bytes()),
                            finished_ms: state.last_time,
                        },
                    );
                    if outcome == DeliveryOutcome::Accepted {
                        Action::Delivered
                    } else {
                        Action::DeliveryRejected
                    }
                }
                DeliveryOutcome::Transient => {
                    record.retry(state.last_time)?;
                    Action::TransportRetry
                }
                DeliveryOutcome::Unauthorized => {
                    record.retry(state.last_time)?;
                    state.invalidate_capture()?;
                    state.paused = true;
                    Action::Paused
                }
            };
            trim_receipts(state, receipts);
            state.record(action, 1, bytes, None)
        })
    }
    /// Explicitly pause/resume admission and future claims. This cannot retract
    /// a request already sent by a lease owner. Enrollment remains independently checked.
    /// Explicit resume upgrades legacy queue storage to schema two atomically;
    /// earlier binaries cannot open the upgraded queue. No other operation upgrades it.
    pub fn set_paused(&mut self, paused: bool) -> Result<(), Error> {
        self.update(|state, _, _| {
            let upgrade = !paused && state.capture.is_none();
            if upgrade {
                state.capture = Some(CaptureConsent::new()?);
            }
            if state.paused != paused || upgrade {
                state.invalidate_capture()?;
                state.paused = paused;
                state.record(
                    if paused {
                        Action::Paused
                    } else {
                        Action::Resumed
                    },
                    0,
                    0,
                    None,
                )?;
            }
            Ok(())
        })
    }
    /// Explicitly pause and purge pending payloads and completed-ID receipts.
    /// Keep only the bounded content-free decision journal and diagnostic counts.
    pub fn purge(&mut self) -> Result<(), Error> {
        self.update(|state, rows, receipts| {
            let count = rows.len() as u32;
            let bytes = rows.values().map(|r| r.event.len()).sum();
            rows.clear();
            receipts.clear();
            state.invalidate_capture()?;
            state.paused = true;
            state.record(Action::Purged, count, bytes, None)
        })
    }
    /// Read a verified bounded local report. Does not claim, prune or expose any
    /// event bodies, rejected content, per-event IDs or sender credentials.
    pub fn inspect(&mut self) -> Result<Report, Error> {
        let deadline = db::budget(&self.conn)?;
        let tx = self.conn.transaction()?;
        let (state, rows, receipts) = db::load(&tx, deadline)?;
        if state.partition != self.partition {
            return Err(Error::Partition);
        }
        tx.commit()?;
        Ok(state.report(&rows, receipts.len()))
    }
    /// Read consent before capturing any optional producer metadata. Returns
    /// None while paused or for legacy stores awaiting an explicit resume.
    /// Does not renew consent, migrate, prune, unlock credentials or contact Platform.
    pub fn capture_permit(&mut self) -> Result<Option<CapturePermit>, Error> {
        let deadline = db::budget(&self.conn)?;
        let tx = self.conn.transaction()?;
        let (state, _, _) = db::load(&tx, deadline)?;
        if state.partition != self.partition {
            return Err(Error::Partition);
        }
        tx.commit()?;
        Ok(if state.paused {
            None
        } else {
            state.capture.map(CapturePermit)
        })
    }
    fn update<T>(
        &mut self,
        operation: impl FnOnce(&mut State, &mut Rows, &mut Receipts) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let deadline = db::budget(&self.conn)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut state, mut rows, mut receipts) = db::load(&tx, deadline)?;
        if state.partition != self.partition {
            return Err(Error::Partition);
        }
        // Observe real time only after acquiring the lock and reading verified
        // state. Pre-lock samples can falsely look like concurrent clock rollback.
        #[cfg(test)]
        let override_time = self.test_time;
        #[cfg(not(test))]
        let override_time: Option<u64> = None;
        let now = match override_time {
            Some(value) => value,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Clock)?
                .as_millis()
                .try_into()
                .map_err(|_| Error::Clock)?,
        };
        if now < state.last_time
            || now > MAX_TIME - MAX_BACKOFF_MS - LEASE_MS - state.limits.max_age_ms
        {
            return Err(Error::Clock);
        }
        state.last_time = now;
        let old_events = rows.keys().cloned().collect::<Vec<_>>();
        let old_receipts = receipts.keys().cloned().collect::<Vec<_>>();
        prune(&mut state, &mut rows, &mut receipts)?;
        let result = operation(&mut state, &mut rows, &mut receipts);
        // Persist observed expiry/clock even when a stale completion is refused.
        // Other errors roll back all state; no admission or lease is returned.
        if result
            .as_ref()
            .err()
            .is_some_and(|e| *e != Error::StaleLease)
        {
            return result;
        }
        db::save(
            &tx,
            &state,
            &rows,
            &receipts,
            &old_events,
            &old_receipts,
            deadline,
        )?;
        tx.commit()?;
        result
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn trim_receipts(state: &State, receipts: &mut Receipts) {
    while receipts.len() > state.limits.max_events as usize {
        let oldest = receipts
            .iter()
            .min_by_key(|(id, r)| (r.finished_ms, *id))
            .map(|(id, _)| id.clone())
            .unwrap();
        receipts.remove(&oldest);
    }
}
fn prune(state: &mut State, rows: &mut Rows, receipts: &mut Receipts) -> Result<(), Error> {
    let now = state.last_time;
    let age = state.limits.max_age_ms;
    state
        .journal
        .retain(|entry| now.saturating_sub(entry.time_ms) < age);
    receipts.retain(|_, receipt| now.saturating_sub(receipt.finished_ms) < age);
    let expired: Vec<_> = rows
        .iter()
        .filter(|(_, r)| now - r.admitted_ms >= age)
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        let record = rows.remove(&id).ok_or(Error::Integrity)?;
        receipts.insert(
            id,
            Receipt {
                digest: digest(record.event.as_bytes()),
                finished_ms: now,
            },
        );
        state.record(Action::Expired, 1, record.event.len(), None)?;
    }
    for record in rows
        .values_mut()
        .filter(|r| r.lease.as_ref().is_some_and(|l| l.until_ms <= now))
    {
        record.retry(now)?;
        state.record(Action::LeaseExpired, 1, record.event.len(), None)?;
    }
    trim_receipts(state, receipts);
    Ok(())
}
