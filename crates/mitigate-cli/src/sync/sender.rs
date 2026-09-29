//! Explicit foreground sender. Local calls never depend on this process.
//! Only the existing SyncProfile owns credential access and signed HTTPS.
use super::{Failure, privacy_check};
use crate::output;
use mitigate_egress::outbox::{self, Readiness};
use mitigate_enrollment::{
    event_https::{Delivery, Error as EventError},
    storage::{
        self,
        sync::{DeliveryError, Error, SyncProfile},
    },
};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    time::Duration,
};

#[cfg(test)]
mod tests;

const IDLE_WAIT: Duration = Duration::from_secs(1);
const DELIVERY_WAIT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Waiting,
    Sending,
    Retrying(&'static str),
    Rejected,
    Stopping,
    Stopped(&'static str),
}
fn emit(status: Status, machine: bool) -> Result<(), Failure> {
    #[derive(Serialize)]
    struct StatusReport {
        schema_version: u8,
        status: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<&'static str>,
    }
    let (name, reason, message) = match status {
        Status::Waiting => ("waiting", None, "Waiting for queued events."),
        Status::Sending => ("sending", None, "Sending queued events."),
        Status::Retrying(reason) => (
            "retrying",
            Some(reason),
            "Delivery delayed. Waiting to retry.",
        ),
        Status::Rejected => (
            "rejected",
            Some("sync_rejected"),
            "One event was rejected. Continuing with other events.",
        ),
        Status::Stopping => (
            "stopping",
            None,
            "Stopping this sender. Waiting for its current operation to finish.",
        ),
        Status::Stopped(reason) => ("stopped", Some(reason), "This sender stopped."),
    };
    let mut stdout = io::stdout().lock();
    let result = if machine {
        output::json(
            &StatusReport {
                schema_version: 1,
                status: name,
                reason,
            },
            &mut stdout,
        )
    } else {
        writeln!(stdout, "{message}")
    };
    result.and_then(|()| stdout.flush()).map_err(|_| Failure {
        code: "sync_output",
        message: "Sender output is unavailable. No further delivery will start.".to_owned(),
    })
}

/// A private seam for deterministic scheduling tests; production has one
/// implementation and no configurable transport or alternate credential source.
trait Source {
    fn readiness(&self) -> Result<Readiness, Error>;
    fn deliver(&self) -> Result<Delivery, DeliveryError>;
}
impl Source for SyncProfile {
    fn readiness(&self) -> Result<Readiness, Error> {
        self.delivery_readiness()
    }
    fn deliver(&self) -> Result<Delivery, DeliveryError> {
        self.deliver_next()
    }
}

struct Stop {
    receiver: Receiver<()>,
    requested: bool,
}
impl Stop {
    fn requested(&mut self) -> bool {
        if !matches!(self.receiver.try_recv(), Err(TryRecvError::Empty)) {
            self.requested = true;
        }
        self.requested
    }
    fn wait(&mut self, delay: Duration) {
        if !self.requested
            && !matches!(
                self.receiver.recv_timeout(delay),
                Err(RecvTimeoutError::Timeout)
            )
        {
            self.requested = true;
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
enum Finished {
    Interrupted,
    Paused,
    Authority(EventError),
}
fn contention(error: &DeliveryError) -> bool {
    matches!(
        error,
        DeliveryError::Control(
            Error::Enrollment(storage::Error::Busy) | Error::Outbox(outbox::Error::Busy)
        ) | DeliveryError::Delivery(EventError::Outbox(outbox::Error::Busy))
    )
}
fn drive(
    source: &impl Source,
    stop: &mut Stop,
    mut announce: impl FnMut(Status) -> Result<(), Failure>,
) -> Result<Finished, Failure> {
    let mut previous = None;
    let mut report = |status| {
        if previous != Some(status) {
            announce(status)?;
            previous = Some(status);
        }
        Ok::<_, Failure>(())
    };
    loop {
        if stop.requested() {
            return Ok(Finished::Interrupted);
        }
        let ready = match source.readiness() {
            Ok(state) => state,
            Err(Error::Outbox(outbox::Error::Busy)) => {
                report(Status::Retrying("sync_busy"))?;
                stop.wait(IDLE_WAIT);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if stop.requested() {
            return Ok(Finished::Interrupted);
        }
        match ready {
            Readiness::Paused => return Ok(Finished::Paused),
            Readiness::Waiting => {
                report(Status::Waiting)?;
                stop.wait(IDLE_WAIT);
            }
            Readiness::Ready => {
                report(Status::Sending)?;
                // Reporting can block on an attached pipe. Recheck cancellation
                // before native access; once started, the operation must drain.
                if stop.requested() {
                    return Ok(Finished::Interrupted);
                }
                match source.deliver() {
                    Ok(Delivery::Accepted) => stop.wait(DELIVERY_WAIT),
                    Ok(Delivery::Rejected) => {
                        report(Status::Rejected)?;
                        stop.wait(DELIVERY_WAIT);
                    }
                    Ok(Delivery::Idle) => {
                        report(Status::Waiting)?;
                        stop.wait(IDLE_WAIT);
                    }
                    Ok(Delivery::Retry(error)) => {
                        report(Status::Retrying(error.code()))?;
                        stop.wait(IDLE_WAIT);
                    }
                    Ok(Delivery::Paused(error)) => return Ok(Finished::Authority(error)),
                    Err(error) if contention(&error) => {
                        report(Status::Retrying("sync_busy"))?;
                        stop.wait(IDLE_WAIT);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
}

fn worker(path: PathBuf, mut stop: Stop, machine: bool) -> Result<Finished, Failure> {
    if stop.requested() {
        return Ok(Finished::Interrupted);
    }
    let profile = SyncProfile::open(&path)?;
    if profile.inspect()?.paused {
        return Ok(Finished::Paused);
    }
    privacy_check()?;
    drive(&profile, &mut stop, |status| emit(status, machine))
}

fn control_failure() -> Failure {
    Failure { code: "sync_worker", message: "Sender stopped because its worker or shutdown control is unavailable. Inspect local sync state before restarting.".to_owned() }
}
pub(super) fn run(path: PathBuf, machine: bool) -> io::Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(async {
            #[cfg(unix)]
            let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| control_failure())?;
            let interrupt = async {
                #[cfg(unix)]
                { tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) } }
                #[cfg(not(unix))]
                { tokio::signal::ctrl_c().await }
            };
            tokio::pin!(interrupt);
            // Poll the signal future once before any worker can access credentials.
            tokio::select! {
                biased;
                result = &mut interrupt => { result.map_err(|_| control_failure())?; return Ok(Finished::Interrupted); }
                () = std::future::ready(()) => ()
            }
            let (sender, receiver) = mpsc::sync_channel(1);
            let mut handle = tokio::task::spawn_blocking(move || worker(path, Stop { receiver, requested: false }, machine));
            tokio::select! {
                result = &mut handle => result.map_err(|_| control_failure())?,
                signal = &mut interrupt => {
                    let _ = sender.try_send(());
                    // Never claim stopped while native unlock or HTTPS is in flight.
                    // Capture output failure too, but always await this worker.
                    let reported = emit(Status::Stopping, machine);
                    let finished = handle.await.map_err(|_| control_failure())?;
                    signal.map_err(|_| control_failure())?;
                    reported?;
                    finished
                }
            }
        }),
        Err(_) => Err(control_failure()),
    };
    match result {
        Ok(finished) => {
            let (reason, failed) = match finished {
                Finished::Interrupted => ("sync_interrupted", false),
                Finished::Paused => ("sync_paused", false),
                Finished::Authority(error) => (error.code(), true),
            };
            emit(Status::Stopped(reason), machine).map_err(|_| io::Error::other("sync_output"))?;
            Ok(if failed {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            })
        }
        Err(error) => {
            output::error(error.code, &error.message, machine)?;
            Ok(ExitCode::from(2))
        }
    }
}
