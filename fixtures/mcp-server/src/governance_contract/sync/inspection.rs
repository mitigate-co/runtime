//! Fixed failure categories for the synthetic queue fixture, never raw errors.
use mitigate_egress::outbox::{Error as OutboxError, Report};
use mitigate_enrollment::storage::sync::{Error, SyncProfile};

#[track_caller]
pub(super) fn inspect(profile: &SyncProfile) -> Report {
    match profile.inspect() {
        Ok(report) => report,
        Err(error) => {
            eprintln!(
                "Synthetic capture inspection category: {}.",
                category(error)
            );
            panic!("synthetic queue inspection failed");
        }
    }
}

fn category(error: Error) -> &'static str {
    match error {
        Error::Outbox(error) => match error {
            OutboxError::Input => "outbox_input",
            OutboxError::Path => "outbox_path",
            OutboxError::Busy => "outbox_busy",
            OutboxError::Storage => "outbox_storage",
            OutboxError::Interrupted => "outbox_interrupted",
            OutboxError::Integrity => "outbox_integrity",
            OutboxError::Partition => "outbox_partition",
            OutboxError::Clock => "outbox_clock",
            OutboxError::StaleLease => "outbox_stale_lease",
            OutboxError::Budget => "outbox_budget",
        },
        // Inspection currently returns only Outbox errors. Do not accidentally
        // expose a future control/provider error through a generic formatter.
        _ => "unexpected_control",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_queue_failure_has_a_distinct_closed_category() {
        for (error, expected) in [
            (OutboxError::Input, "outbox_input"),
            (OutboxError::Path, "outbox_path"),
            (OutboxError::Busy, "outbox_busy"),
            (OutboxError::Storage, "outbox_storage"),
            (OutboxError::Interrupted, "outbox_interrupted"),
            (OutboxError::Integrity, "outbox_integrity"),
            (OutboxError::Partition, "outbox_partition"),
            (OutboxError::Clock, "outbox_clock"),
            (OutboxError::StaleLease, "outbox_stale_lease"),
            (OutboxError::Budget, "outbox_budget"),
        ] {
            assert_eq!(category(Error::Outbox(error)), expected);
        }
        assert_eq!(category(Error::Storage), "unexpected_control");
    }
}
