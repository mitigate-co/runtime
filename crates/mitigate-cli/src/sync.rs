//! Explicit local consent and optional delivery. No payload import or implicit daemon.
mod sender;
use crate::{args::SyncCommand, output};
use mitigate_egress::outbox::{Limits, Report as QueueReport};
use mitigate_enrollment::{
    PlatformOrigin,
    event_https::Delivery,
    storage::sync::{DeliveryError, Error, SyncProfile},
};
use serde::Serialize;
use std::{
    io::{self, Write},
    process::ExitCode,
};

#[derive(Serialize)]
struct Report {
    schema_version: u8,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_drained: Option<bool>,
    queue: QueueReport,
    #[serde(skip)]
    message: String,
    #[serde(skip)]
    failed: bool,
}
#[derive(Debug)]
struct Failure {
    code: &'static str,
    message: String,
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}
impl From<DeliveryError> for Failure {
    fn from(error: DeliveryError) -> Self {
        let code = match error {
            DeliveryError::Control(e) => e.code(),
            DeliveryError::Delivery(e) => e.code(),
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}
fn execute(command: SyncCommand) -> Result<Report, Failure> {
    let mut drained = None;
    let mut reason = None;
    let mut failed = false;
    let (queue, status, message) = match command {
        SyncCommand::Enable {
            profile,
            enrollment,
            platform,
            outbox,
        } => {
            let origin = PlatformOrigin::parse(&platform).map_err(|_| Failure {
                code: "enrollment_origin",
                message: "Use the original canonical HTTPS Platform address.".to_owned(),
            })?;
            let profile =
                SyncProfile::create(&profile, &enrollment, &origin, &outbox, Limits::default())?;
            (
                profile.inspect()?,
                "enabled",
                "Sync enabled. No background sender is running.".to_owned(),
            )
        }
        SyncCommand::Status { profile } => {
            let queue = SyncProfile::open(&profile)?.inspect()?;
            let (status, message) = if queue.paused {
                (
                    "paused",
                    "Sync paused. Active delivery has not been checked.",
                )
            } else {
                (
                    "enabled",
                    "Sync enabled. Use run for continuous delivery or send for one event.",
                )
            };
            (queue, status, message.to_owned())
        }
        SyncCommand::Pause { profile } => {
            let queue = SyncProfile::open(&profile)?.pause()?;
            drained = Some(true);
            (
                queue,
                "paused",
                "Sync paused. Active delivery has finished.".to_owned(),
            )
        }
        SyncCommand::Resume { profile } => (
            SyncProfile::open(&profile)?.resume()?,
            "enabled",
            "Sync resumed. No event was sent.".to_owned(),
        ),
        SyncCommand::Purge {
            profile,
            confirm: _,
        } => {
            let queue = SyncProfile::open(&profile)?.purge()?;
            drained = Some(true);
            (
                queue,
                "purged",
                "Sync paused. Local queued events removed.".to_owned(),
            )
        }
        SyncCommand::Send { profile } => {
            let profile = SyncProfile::open(&profile)?;
            let result = match profile.delivery_readiness()? {
                mitigate_egress::outbox::Readiness::Ready => {
                    privacy_check()?;
                    profile.deliver_next()?
                }
                // Do not re-enter delivery after an ungated idle observation:
                // a producer could have queued an event between the two reads.
                _ => Delivery::Idle,
            };
            let (status, message) = match result {
                Delivery::Idle => ("waiting", "No event is ready to send.".to_owned()),
                Delivery::Accepted => ("accepted", "One event accepted.".to_owned()),
                Delivery::Rejected => {
                    failed = true;
                    reason = Some("sync_rejected");
                    (
                        "rejected",
                        "One event rejected. It will not be retried.".to_owned(),
                    )
                }
                Delivery::Retry(error) => {
                    failed = true;
                    reason = Some(error.code());
                    ("retry_pending", error.to_string())
                }
                Delivery::Paused(error) => {
                    failed = true;
                    reason = Some(error.code());
                    ("paused", error.to_string())
                }
            };
            (profile.inspect()?, status, message)
        }
        SyncCommand::Run { .. } => unreachable!("continuous sync is dispatched separately"),
    };
    Ok(Report {
        schema_version: 1,
        status,
        reason,
        delivery_drained: drained,
        queue,
        message,
        failed,
    })
}
pub(crate) fn run(command: SyncCommand, machine: bool) -> io::Result<ExitCode> {
    if let SyncCommand::Run { profile } = command {
        return sender::run(profile, machine);
    }
    match execute(command) {
        Ok(report) => {
            if machine {
                output::json(&report, io::stdout().lock())?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "{}\nQueued: {}",
                    report.message,
                    report.queue.pending
                )?;
            }
            Ok(if report.failed {
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

/// The real admission/storage probe must pass before this process sends events.
/// Never retry an unavailable probe or report it as a successful privacy check.
fn privacy_check() -> Result<(), Failure> {
    match mitigate_egress::self_test::run(&std::env::temp_dir()) {
        Ok(report) if report.passed => Ok(()),
        _ => Err(Failure {
            code: "sync_privacy",
            message: "Delivery stopped: privacy check did not pass. Run mitigate privacy self-test before restarting the sender.".to_owned(),
        }),
    }
}
