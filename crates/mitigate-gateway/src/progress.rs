//! Bounded latest-value progress, local to one request. No message text or token
//! enters the service; the listener owns correlation with the downstream token.
use serde::Serialize;
use tokio::sync::watch;

#[derive(Clone, Copy, Serialize)]
pub(crate) struct Counters {
    pub progress: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
}
/// One request's content-free progress sink. Intermediate updates may coalesce;
/// memory stays constant even when the client is slow. Not an authority token.
pub struct ProgressSink(watch::Sender<Option<Counters>>);
impl ProgressSink {
    /// Publish finite nonnegative, strictly increasing counters. Invalid updates
    /// are omitted. No free-form text, server token or arbitrary metadata is accepted.
    pub fn report(&mut self, completed: f64, total: Option<f64>) {
        if !completed.is_finite()
            || completed < 0.0
            || total.is_some_and(|t| !t.is_finite() || t < completed)
            || self.0.borrow().is_some_and(|old| completed <= old.progress)
        {
            return;
        }
        self.0.send_replace(Some(Counters {
            progress: completed,
            total,
        }));
    }
}
pub(crate) fn channel() -> (ProgressSink, watch::Receiver<Option<Counters>>) {
    let (sender, receiver) = watch::channel(None);
    (ProgressSink(sender), receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coalesces_and_discards_invalid_or_regressing_counters() {
        let (mut sender, receiver) = channel();
        for i in 0..10_000 {
            sender.report(f64::from(i), Some(10_000.0));
        }
        for (completed, total) in [
            (f64::NAN, None),
            (f64::INFINITY, None),
            (-1.0, None),
            (1.0, None),
            (10_000.0, Some(1.0)),
            (10_000.0, Some(f64::INFINITY)),
        ] {
            sender.report(completed, total);
        }
        assert_eq!(receiver.borrow().unwrap().progress, 9999.0);
        assert_eq!(receiver.borrow().unwrap().total, Some(10_000.0));
    }
}
