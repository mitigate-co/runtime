use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
};

enum Step {
    Read(Result<Readiness, Error>),
    Send(Result<Delivery, DeliveryError>),
}
struct Script {
    steps: RefCell<VecDeque<Step>>,
    deliveries: Cell<usize>,
    interrupt_after_read: Option<mpsc::SyncSender<()>>,
}
impl Script {
    fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: RefCell::new(steps.into_iter().collect()),
            deliveries: Cell::new(0),
            interrupt_after_read: None,
        }
    }
}
impl Source for Script {
    fn readiness(&self) -> Result<Readiness, Error> {
        let Some(Step::Read(result)) = self.steps.borrow_mut().pop_front() else {
            panic!("unexpected readiness check")
        };
        if let Some(sender) = &self.interrupt_after_read {
            sender.try_send(()).unwrap();
        }
        result
    }
    fn deliver(&self) -> Result<Delivery, DeliveryError> {
        self.deliveries.set(self.deliveries.get() + 1);
        let Some(Step::Send(result)) = self.steps.borrow_mut().pop_front() else {
            panic!("unexpected credential/transport access")
        };
        result
    }
}
fn control() -> (mpsc::SyncSender<()>, Stop) {
    let (sender, receiver) = mpsc::sync_channel(1);
    (
        sender,
        Stop {
            receiver,
            requested: false,
        },
    )
}

#[test]
fn empty_wait_is_interruptible_without_credentials_and_disconnect_stops() {
    let source = Script::new([Step::Read(Ok(Readiness::Waiting))]);
    let (sender, mut stop) = control();
    let result = drive(&source, &mut stop, |status| {
        assert_eq!(status, Status::Waiting);
        sender.try_send(()).unwrap();
        Ok(())
    })
    .unwrap();
    assert_eq!(result, Finished::Interrupted);
    assert_eq!(source.deliveries.get(), 0);
    let (sender, mut stop) = control();
    drop(sender);
    assert_eq!(
        drive(&Script::new([]), &mut stop, |_| panic!(
            "disconnected worker reported progress"
        ))
        .unwrap(),
        Finished::Interrupted
    );
}

#[test]
fn cancellation_after_readiness_or_blocked_output_prevents_native_access() {
    let (sender, mut stop) = control();
    let mut source = Script::new([Step::Read(Ok(Readiness::Ready))]);
    source.interrupt_after_read = Some(sender.clone());
    assert_eq!(
        drive(&source, &mut stop, |_| panic!(
            "cancelled worker reported progress"
        ))
        .unwrap(),
        Finished::Interrupted
    );
    assert_eq!(source.deliveries.get(), 0);

    let (sender, mut stop) = control();
    let source = Script::new([Step::Read(Ok(Readiness::Ready))]);
    assert_eq!(
        drive(&source, &mut stop, |_| {
            sender.try_send(()).unwrap();
            Ok(())
        })
        .unwrap(),
        Finished::Interrupted
    );
    assert_eq!(source.deliveries.get(), 0);

    let (_sender, mut stop) = control();
    let source = Script::new([Step::Read(Ok(Readiness::Ready))]);
    let failed = drive(&source, &mut stop, |_| {
        Err(Failure {
            code: "sync_output",
            message: "closed".to_owned(),
        })
    })
    .unwrap_err();
    assert_eq!(failed.code, "sync_output");
    assert_eq!(source.deliveries.get(), 0);
}

#[test]
fn cancellation_during_delivery_waits_for_the_attempt_and_starts_no_second_one() {
    struct InFlight(mpsc::SyncSender<()>, Cell<bool>);
    impl Source for InFlight {
        fn readiness(&self) -> Result<Readiness, Error> {
            Ok(Readiness::Ready)
        }
        fn deliver(&self) -> Result<Delivery, DeliveryError> {
            assert!(!self.1.replace(true), "second attempt after shutdown");
            self.0.try_send(()).unwrap();
            // The driver must wait for this result, not interpret the stop signal
            // as a completed or retracted network operation.
            Ok(Delivery::Accepted)
        }
    }
    let (sender, mut stop) = control();
    let source = InFlight(sender, Cell::new(false));
    assert_eq!(
        drive(&source, &mut stop, |_| Ok(())).unwrap(),
        Finished::Interrupted
    );
    assert!(source.1.get());
}

#[test]
fn retry_waits_for_queue_readiness_and_pause_never_resumes_it() {
    let (_sender, mut stop) = control();
    let source = Script::new([
        Step::Read(Ok(Readiness::Ready)),
        Step::Send(Ok(Delivery::Retry(EventError::RateLimited))),
        Step::Read(Ok(Readiness::Waiting)),
        Step::Read(Ok(Readiness::Paused)),
    ]);
    let mut reports = Vec::new();
    assert_eq!(
        drive(&source, &mut stop, |status| {
            reports.push(status);
            Ok(())
        })
        .unwrap(),
        Finished::Paused
    );
    assert_eq!(source.deliveries.get(), 1);
    assert!(source.steps.borrow().is_empty());
    assert!(reports.contains(&Status::Retrying("sync_rate_limited")));
    assert_eq!(reports.last(), Some(&Status::Waiting));
}

#[test]
fn only_documented_contention_is_retried_and_clock_or_storage_failure_stops() {
    for error in [
        Error::Outbox(outbox::Error::Clock),
        Error::Outbox(outbox::Error::Integrity),
        Error::Profile,
    ] {
        let (_sender, mut stop) = control();
        let source = Script::new([Step::Read(Err(error))]);
        assert_eq!(
            drive(&source, &mut stop, |_| Ok(())).unwrap_err().code,
            error.code()
        );
        assert_eq!(source.deliveries.get(), 0);
    }
    let (_sender, mut stop) = control();
    let source = Script::new([
        Step::Read(Err(Error::Outbox(outbox::Error::Busy))),
        Step::Read(Ok(Readiness::Ready)),
        Step::Send(Err(DeliveryError::Control(Error::Enrollment(
            storage::Error::Busy,
        )))),
        Step::Read(Ok(Readiness::Paused)),
    ]);
    assert_eq!(
        drive(&source, &mut stop, |_| Ok(())).unwrap(),
        Finished::Paused
    );
    assert_eq!(source.deliveries.get(), 1);
}

#[test]
fn authority_refusal_stops_immediately_and_local_completion_failure_is_fatal() {
    let (_sender, mut stop) = control();
    let source = Script::new([
        Step::Read(Ok(Readiness::Ready)),
        Step::Send(Ok(Delivery::Paused(EventError::Unauthorized))),
        Step::Read(Ok(Readiness::Ready)),
    ]);
    assert_eq!(
        drive(&source, &mut stop, |_| Ok(())).unwrap(),
        Finished::Authority(EventError::Unauthorized)
    );
    assert_eq!(source.steps.borrow().len(), 1);
    let (_sender, mut stop) = control();
    let source = Script::new([
        Step::Read(Ok(Readiness::Ready)),
        Step::Send(Err(DeliveryError::Delivery(EventError::Outbox(
            outbox::Error::Storage,
        )))),
    ]);
    assert_eq!(
        drive(&source, &mut stop, |_| Ok(())).unwrap_err().code,
        "sync_outbox"
    );
    assert_eq!(source.deliveries.get(), 1);
}

#[test]
fn permanent_refusal_continues_other_events_but_native_failure_never_retries() {
    let (_sender, mut stop) = control();
    let source = Script::new([
        Step::Read(Ok(Readiness::Ready)),
        Step::Send(Ok(Delivery::Rejected)),
        Step::Read(Ok(Readiness::Ready)),
        Step::Send(Ok(Delivery::Accepted)),
        Step::Read(Ok(Readiness::Paused)),
    ]);
    let mut reports = Vec::new();
    assert_eq!(
        drive(&source, &mut stop, |status| {
            reports.push(status);
            Ok(())
        })
        .unwrap(),
        Finished::Paused
    );
    assert_eq!(source.deliveries.get(), 2);
    assert!(reports.contains(&Status::Rejected));
    let (_sender, mut stop) = control();
    let source = Script::new([
        Step::Read(Ok(Readiness::Ready)),
        Step::Send(Err(DeliveryError::Control(Error::Enrollment(
            storage::Error::Missing,
        )))),
    ]);
    assert_eq!(
        drive(&source, &mut stop, |_| Ok(())).unwrap_err().code,
        storage::Error::Missing.code()
    );
    assert_eq!(source.deliveries.get(), 1);
}
