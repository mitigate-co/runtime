//! Optional metadata capture. Local authorization never waits for this worker.
mod capture;
#[cfg(test)]
pub(super) mod tests;
use capture::Capture;
pub(super) use capture::InvocationRefs;
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
struct Shared {
    permit: Mutex<Option<CapturePermit>>,
    stopped: AtomicBool,
    dropped: AtomicBool,
}
pub(super) struct Producer {
    sender: SyncSender<Envelope>,
    shared: Arc<Shared>,
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
        if candidate
            .is_none_or(|capture| self.sender.try_send(Envelope { permit, capture }).is_err())
        {
            self.shared.dropped.store(true, Ordering::Release);
        }
    }
}
fn channel() -> (Producer, Receiver<Envelope>, Arc<Shared>) {
    let (sender, receiver) = mpsc::sync_channel(CAPACITY);
    let shared = Arc::new(Shared {
        permit: Mutex::new(None),
        stopped: AtomicBool::new(false),
        dropped: AtomicBool::new(false),
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
fn run(path: PathBuf, receiver: Receiver<Envelope>, shared: &Shared) {
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
    match self_test::run(&std::env::temp_dir()) {
        Ok(report) if report.passed => (),
        _ => {
            eprintln!(
                "Mitigate: sync capture disabled because the privacy self-test did not pass. Run mitigate privacy self-test before restarting sync capture."
            );
            return;
        }
    }
    let mut pending: Option<Envelope> = None;
    while !shared.stopped.load(Ordering::Acquire) {
        let (consent, result) = match profile.capture_session() {
            Ok(mut session) => match session.permit() {
                Ok(permit) => {
                    let result = match pending.take() {
                        Some(envelope) => admit(&mut session, envelope, &shared.stopped),
                        None => {
                            if permit.is_some() {
                                Status::Ready
                            } else {
                                Status::Paused
                            }
                        }
                    };
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
