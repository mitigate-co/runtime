use super::*;
use crate::MAX_EVENT_BYTES;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub partition: Partition,
    pub limits: Limits,
    pub paused: bool,
    pub last_time: u64,
    pub sequence: u64,
    pub totals: [Totals; 15],
    pub journal: Vec<JournalEntry>,
}
impl State {
    pub fn new(partition: Partition, limits: Limits) -> Self {
        Self {
            partition,
            limits,
            paused: false,
            last_time: 0,
            sequence: 0,
            totals: [Totals::default(); 15],
            journal: Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate().map_err(|_| Error::Integrity)?;
        if self.last_time > MAX_TIME
            || self.sequence > MAX_TIME
            || self.journal.len() > JOURNAL_LIMIT
            || self
                .totals
                .iter()
                .any(|t| t.events > MAX_TIME || t.bytes > MAX_TIME)
        {
            return Err(Error::Integrity);
        }
        let mut prior = None;
        for entry in &self.journal {
            if entry.sequence == 0
                || entry.sequence > self.sequence
                || entry.time_ms > self.last_time
                || entry.events > 1000
                || entry.bytes > 1000 * (MAX_EVENT_BYTES as u32 + 1)
                || (entry.action == Action::PrivacyRejected) != entry.rejection.is_some()
                || prior
                    .is_some_and(|(seq, time)| entry.sequence != seq + 1 || entry.time_ms < time)
            {
                return Err(Error::Integrity);
            }
            prior = Some((entry.sequence, entry.time_ms));
        }
        if self
            .journal
            .last()
            .is_some_and(|e| e.sequence != self.sequence)
        {
            return Err(Error::Integrity);
        }
        Ok(())
    }
    pub fn record(
        &mut self,
        action: Action,
        events: u32,
        bytes: usize,
        rejection: Option<Rejection>,
    ) -> Result<(), Error> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .filter(|v| *v <= MAX_TIME)
            .ok_or(Error::Budget)?;
        let bytes = u32::try_from(bytes).map_err(|_| Error::Budget)?;
        let total = &mut self.totals[action as usize];
        total.events = total.events.saturating_add(u64::from(events)).min(MAX_TIME);
        total.bytes = total.bytes.saturating_add(u64::from(bytes)).min(MAX_TIME);
        if self.journal.len() == JOURNAL_LIMIT {
            self.journal.remove(0);
        }
        self.journal.push(JournalEntry {
            sequence: self.sequence,
            time_ms: self.last_time,
            action,
            events,
            bytes,
            rejection,
        });
        Ok(())
    }
    pub fn report(self, rows: &Rows, receipts: usize) -> Report {
        Report {
            schema_version: 1,
            partition: self.partition,
            paused: self.paused,
            limits: self.limits,
            pending: rows.len(),
            leased: rows.values().filter(|r| r.lease.is_some()).count(),
            payload_bytes: rows.values().map(|r| r.event.len()).sum(),
            receipts,
            counters: ACTIONS
                .into_iter()
                .zip(self.totals)
                .map(|(action, totals)| Counter { action, totals })
                .collect(),
            recent: self.journal,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub event: String,
    pub admitted_ms: u64,
    pub attempts: u16,
    pub next_ms: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub lease: Option<DeliveryLease>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeliveryLease {
    pub token: SyncRef,
    pub until_ms: u64,
}
pub(super) type Rows = BTreeMap<String, Record>;

impl Record {
    pub fn checked(&self, id: &str, state: &State) -> Result<CheckedEvent, Error> {
        let event =
            CheckedEvent::from_bytes(self.event.as_bytes()).map_err(|_| Error::Integrity)?;
        if event.as_bytes() != self.event.as_bytes()
            || event.event_id().as_str() != id
            || event.runtime_ref() != &state.partition.runtime_ref
            || self.admitted_ms > state.last_time
            || self.next_ms > MAX_TIME
            || self.next_ms < self.admitted_ms
            || self.next_ms > state.last_time.saturating_add(MAX_BACKOFF_MS)
            || self.attempts > 16
            || (self.attempts == 0 && self.next_ms != self.admitted_ms)
            || self.lease.as_ref().is_some_and(|l| {
                self.attempts == 0
                    || l.until_ms > MAX_TIME
                    || l.until_ms < self.admitted_ms.saturating_add(LEASE_MS)
                    || l.until_ms > state.last_time.saturating_add(LEASE_MS)
                    || self.next_ms > state.last_time
            })
        {
            return Err(Error::Integrity);
        }
        Ok(event)
    }
    pub fn retry(&mut self, now: u64) -> Result<(), Error> {
        self.lease = None;
        let backoff = (1000u64 << self.attempts.saturating_sub(1)).min(MAX_BACKOFF_MS);
        self.next_ms = now
            .checked_add(backoff)
            .filter(|t| *t <= MAX_TIME)
            .ok_or(Error::Clock)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub digest: String,
    pub finished_ms: u64,
}
pub(super) type Receipts = BTreeMap<String, Receipt>;
