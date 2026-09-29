//! Optional metadata capture. Local authorization never waits for this worker.
mod capture;
mod inventory;
#[cfg(test)]
pub(super) mod tests;
use capture::Capture;
pub(super) use capture::InvocationRefs;
use inventory::InventoryCapture;
use mitigate_audit::{CallPhase, EventDetails};
use mitigate_egress::{
    outbox::{Admission, CapturePermit},
    self_test,
};
use mitigate_enrollment::storage::sync::{CaptureSession, SyncProfile};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::Duration,
};

const CAPACITY: usize = 128;
pub(super) struct Envelope {
    permit: CapturePermit,
    capture: Capture,
}
pub(super) enum Message {
    Decision(Box<Envelope>),
    Inventory(Box<InventoryCapture>),
}
struct Shared {
    permit: Mutex<Option<CapturePermit>>,
    stopped: AtomicBool,
    dropped: AtomicBool,
    inventory_busy: AtomicBool,
}
#[derive(Clone)]
pub(super) struct Producer {
    sender: SyncSender<Message>,
    shared: Arc<Shared>,
}
pub(super) struct InventoryPermit {
    permit: CapturePermit,
    shared: Arc<Shared>,
}
impl Drop for InventoryPermit {
    fn drop(&mut self) {
        self.shared.inventory_busy.store(false, Ordering::Release);
    }
}
pub(super) struct Worker {
    shared: Arc<Shared>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Do not delay local gateway shutdown on optional storage/probe work.
        // An already-started bounded metadata transaction may finish; explicit
        // sync pause/purge independently drains its original enrollment owner.
        self.shared.stopped.store(true, Ordering::Release);
    }
}
impl Producer {
    /// Snapshot consent at the record boundary, before the required audit write.
    /// A later resume must not retroactively opt that record into capture.
    pub fn permit(&self) -> Option<CapturePermit> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return None;
        }
        match self.shared.permit.try_lock() {
            Ok(permit) => permit.clone(),
            Err(_) => {
                self.shared.dropped.store(true, Ordering::Release);
                None
            }
        }
    }
    pub fn publish(
        &self,
        permit: CapturePermit,
        detail: &EventDetails,
        phase: CallPhase,
        time_ms: u64,
        refs: &mut Option<InvocationRefs>,
    ) {
        if self.shared.stopped.load(Ordering::Acquire) {
            return;
        }
        if refs.is_none() {
            *refs = InvocationRefs::new();
        }
        let candidate = refs
            .as_mut()
            .and_then(|refs| Capture::from_call(detail, phase, time_ms, refs));
        if candidate.is_none_or(|capture| {
            self.sender
                .try_send(Message::Decision(Box::new(Envelope { permit, capture })))
                .is_err()
        }) {
            self.shared.dropped.store(true, Ordering::Release);
        }
    }
    /// Reserve at most one whole observation before its fresh listing begins.
    /// Queue pressure or a busy optional worker cannot delay local execution.
    pub fn inventory_permit(&self) -> Option<InventoryPermit> {
        let permit = self.permit()?;
        if self
            .shared
            .inventory_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.shared.dropped.store(true, Ordering::Release);
            return None;
        }
        Some(InventoryPermit {
            permit,
            shared: self.shared.clone(),
        })
    }
    pub fn publish_inventory<'a>(
        &self,
        ticket: InventoryPermit,
        server: &mitigate_fingerprint::Fingerprint,
        tools: impl ExactSizeIterator<Item = &'a super::facts::ToolFacts>,
        supported: bool,
        time_ms: u64,
    ) {
        if self.shared.stopped.load(Ordering::Acquire) {
            return;
        }
        let capture = InventoryCapture::new(ticket, server, tools, supported, time_ms);
        if capture.is_none_or(|capture| {
            self.sender
                .try_send(Message::Inventory(Box::new(capture)))
                .is_err()
        }) {
            self.shared.dropped.store(true, Ordering::Release);
        }
    }
}
fn channel() -> (Producer, Receiver<Message>, Arc<Shared>) {
    let (sender, receiver) = mpsc::sync_channel(CAPACITY);
    let shared = Arc::new(Shared {
        permit: Mutex::new(None),
        stopped: AtomicBool::new(false),
        dropped: AtomicBool::new(false),
        inventory_busy: AtomicBool::new(false),
    });
    (
        Producer {
            sender,
            shared: shared.clone(),
        },
        receiver,
        shared,
    )
}
pub(super) fn start(path: PathBuf) -> std::io::Result<(Producer, Worker)> {
    let (producer, receiver, shared) = channel();
    let state = shared.clone();
    thread::Builder::new()
        .name("mitigate-sync-capture".into())
        .spawn(move || {
            run(path, receiver, &state);
            state.stopped.store(true, Ordering::Release);
        })?;
    Ok((producer, Worker { shared }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Ready,
    Paused,
    Unavailable,
    Dropped,
}
fn announce(previous: &mut Option<Status>, current: Status) {
    if *previous != Some(current) {
        eprintln!(
            "Mitigate: {}",
            match current {
                Status::Ready => "sync capture ready.",
                Status::Paused => "sync capture is paused or needs explicit resume.",
                Status::Unavailable =>
                    "sync capture unavailable; inspect the original profile, queue and catalog.",
                Status::Dropped =>
                    "optional sync metadata was dropped; inspect queue capacity and local storage.",
            }
        );
        *previous = Some(current);
    }
}
fn run(path: PathBuf, receiver: Receiver<Message>, shared: &Shared) {
    let mut status = None;
    let profile = match SyncProfile::open(&path) {
        Ok(profile) => profile,
        Err(_) => {
            announce(&mut status, Status::Unavailable);
            return;
        }
    };
    // No capture is enabled unless the actual synthetic egress probe completes.
    // Unavailable is not a pass; do not retry or weaken the probe automatically.
    let failure = match self_test::run(&std::env::temp_dir()) {
        Ok(report) if report.passed => None,
        Ok(_) => Some("assertion"),
        Err(self_test::Error::Workspace) => Some("workspace"),
        Err(self_test::Error::Setup) => Some("setup"),
        Err(self_test::Error::Cleanup) => Some("cleanup"),
        Err(self_test::Error::Storage(mitigate_egress::outbox::Error::Clock)) => {
            Some("storage_clock")
        }
        Err(self_test::Error::Storage(mitigate_egress::outbox::Error::Budget)) => {
            Some("storage_budget")
        }
        Err(self_test::Error::Storage(_)) => Some("storage"),
    };
    if let Some(category) = failure {
        eprintln!("Mitigate: sync privacy check category: {category}.");
        eprintln!(
            "Mitigate: sync capture disabled because the privacy self-test did not pass. Run mitigate privacy self-test before restarting sync capture."
        );
        return;
    }
    let mut pending: Option<Message> = None;
    let mut inventory: Option<InventoryCapture> = None;
    while !shared.stopped.load(Ordering::Acquire) {
        let (consent, result) = match profile.capture_session() {
            Ok(mut session) => match session.permit() {
                Ok(permit) => {
                    let mut result = if permit.is_some() {
                        Status::Ready
                    } else {
                        Status::Paused
                    };
                    match pending.take() {
                        Some(Message::Decision(envelope)) => {
                            result = admit(&mut session, *envelope, &shared.stopped)
                        }
                        Some(Message::Inventory(capture)) if inventory.is_none() => {
                            inventory = Some(*capture)
                        }
                        Some(Message::Inventory(_)) => result = Status::Dropped,
                        None => (),
                    }
                    // Both kinds make progress under load. Each loop handles at
                    // most one decision and one bounded inventory step, then
                    // releases ownership before looking for another message.
                    if let Some(capture) = inventory.take() {
                        let (status, next) = capture.advance(&mut session, &shared.stopped);
                        inventory = next;
                        if result != Status::Dropped {
                            result = status;
                        }
                    }
                    (permit, result)
                }
                Err(_) => (None, Status::Unavailable),
            },
            Err(_) => (None, Status::Unavailable),
        };
        // No storage/owner lock is held while publishing consent or waiting.
        // Never reuse a buffered record after an uncertain admission failure.
        if pending.take().is_some() {
            shared.dropped.store(true, Ordering::Release);
        }
        if result == Status::Unavailable {
            inventory = None;
        }
        match shared.permit.lock() {
            Ok(mut current) => *current = consent,
            Err(_) => return,
        }
        announce(
            &mut status,
            if shared.dropped.swap(false, Ordering::AcqRel) {
                Status::Dropped
            } else {
                result
            },
        );
        if inventory.is_some() {
            pending = receiver.try_recv().ok();
            continue;
        }
        pending = match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(envelope) => Some(envelope),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
    }
}

fn admit(session: &mut CaptureSession, envelope: Envelope, stopped: &AtomicBool) -> Status {
    let keys: Vec<_> = envelope.capture.keys.iter().flatten().cloned().collect();
    let mapped = match session.resolve(&envelope.permit, &keys) {
        Ok(Some(mapped)) => mapped,
        Ok(None) => return Status::Paused,
        Err(_) => return Status::Dropped,
    };
    let event = match envelope.capture.bind(session.runtime_ref().clone(), mapped) {
        Ok(event) if !stopped.load(Ordering::Acquire) => event,
        _ => return Status::Dropped,
    };
    match session.admit(&envelope.permit, &event) {
        Ok(Admission::Queued | Admission::Duplicate) => Status::Ready,
        Ok(Admission::Paused | Admission::ConsentChanged) => Status::Paused,
        _ => Status::Dropped,
    }
}
