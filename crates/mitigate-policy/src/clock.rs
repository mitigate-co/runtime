//! Trusted time sampled inside store serialization, never from an MCP message.
use std::time::{SystemTime, UNIX_EPOCH};

/// UTC observation used by an approval/control operation after acquiring its
/// database transaction. Implementations must be prompt and use trusted time.
/// A caller-supplied timestamp remains useful for deterministic simulation, but
/// production callers should use `SystemClock` to avoid stale pre-lock samples.
pub trait Clock {
    /// Return UTC Unix milliseconds, or None when a trustworthy value is unavailable.
    fn now_ms(self) -> Option<u64>;
}
/// Read the local OS clock only when the store is ready to apply the operation.
#[derive(Clone, Copy, Default)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis()
            .try_into()
            .ok()
    }
}
impl Clock for u64 {
    fn now_ms(self) -> Option<u64> {
        Some(self)
    }
}

#[cfg(test)]
pub(crate) struct LockedClock<'a>(pub &'a std::path::Path, pub Option<u64>);
#[cfg(test)]
impl Clock for LockedClock<'_> {
    fn now_ms(self) -> Option<u64> {
        let probe = rusqlite::Connection::open(self.0).unwrap();
        probe.busy_timeout(std::time::Duration::ZERO).unwrap();
        let error = probe
            .execute_batch("BEGIN EXCLUSIVE")
            .expect_err("clock must be sampled while the store owns its transaction lock");
        assert!(matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        ));
        self.1
    }
}
