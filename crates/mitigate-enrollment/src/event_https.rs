//! One explicit signed event exchange using a confirmed, locked native enrollment.
//! No consent mutation, background worker, queue completion or automatic retry.
use crate::{
    event::{EVENT_PATH, EventReceipt, MAX_EVENT_RECEIPT_BYTES, SignedEvent},
    storage::{self, EnrollmentStore},
    transport,
};
use mitigate_egress::outbox::Lease;
use std::fmt;
use ureq::{Agent, Body, http::Response};

#[cfg(test)]
mod tests;

/// Fixed failures, without response bodies, headers or provider error chains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Confirmed native state or matching lease was unavailable; nothing was sent.
    Enrollment(storage::Error),
    /// Verified HTTPS could not be established or completed; acceptance is uncertain.
    Connection,
    /// A bounded request phase timed out; preserve the same event for recovery.
    Timeout,
    /// A redirect was refused. Pause and inspect the configured Platform.
    Redirect,
    /// Receiver refused current enrollment authority; pause optional delivery.
    Unauthorized,
    /// Receiver permanently refused this event's schema or identity/body binding.
    Rejected,
    /// Receiver limited requests; retain the same event for later retry.
    RateLimited,
    /// Receiver returned a server error; local MCP operation remains available.
    Unavailable,
    /// Unsupported response or acknowledgment; acceptance remains unconfirmed.
    Response,
}
impl Error {
    /// Closed diagnostic category for local reports, never response-dependent text.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Enrollment(error) => error.code(),
            Self::Connection => "sync_connection",
            Self::Timeout => "sync_timeout",
            Self::Redirect => "sync_redirect",
            Self::Unauthorized => "sync_unauthorized",
            Self::Rejected => "sync_rejected",
            Self::RateLimited => "sync_rate_limited",
            Self::Unavailable => "sync_unavailable",
            Self::Response => "sync_response",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enrollment(error) => error.fmt(f),
            Self::Connection => f.write_str("Could not complete verified HTTPS delivery. Retain this event and check the Platform address, network and clock."),
            Self::Timeout => f.write_str("Event delivery timed out. Retry the same queued event after backoff."),
            Self::Redirect => f.write_str("Platform redirected event delivery. No redirect was followed. Pause sync and check its address."),
            Self::Unauthorized => f.write_str("Platform refused this enrollment. Pause sync and check organization access or revocation."),
            Self::Rejected => f.write_str("Platform rejected this event. Do not automatically retry its unchanged body."),
            Self::RateLimited => f.write_str("Platform limited event delivery. Retain this event and retry after backoff."),
            Self::Unavailable => f.write_str("Platform is unavailable. Retain this event for later delivery; local MCP protection remains available."),
            Self::Response => f.write_str("Event acceptance was not confirmed. Retain this event and inspect the Platform connection."),
        }
    }
}
impl std::error::Error for Error {}

/// HTTPS-authenticated acknowledgment bound to the exact submitted event.
/// No public constructor, raw response accessor or generic serialization.
pub struct HttpsEventReceipt(EventReceipt);
impl HttpsEventReceipt {
    /// Checked receipt facts; the caller must still complete its current lease.
    pub fn receipt(&self) -> &EventReceipt {
        &self.0
    }
}

/// Sign and send one lease with its confirmed native enrollment, keeping the
/// owner's operation lock borrowed for the entire exchange. Pending/wrong-scope
/// state fails before network I/O. The caller must separately obtain current sync
/// consent, validate the lease, coordinate opt-out/cancellation and persist the
/// outcome. Twenty-second HTTP deadline is shorter than the outbox's 30-second
/// lease, but time spent before submission still counts against that lease.
pub fn submit(store: &EnrollmentStore, lease: &Lease) -> Result<HttpsEventReceipt, Error> {
    let signed = store.sign_event(lease).map_err(Error::Enrollment)?;
    exchange(&transport::config().build().into(), &signed)
}

fn exchange(agent: &Agent, event: &SignedEvent) -> Result<HttpsEventReceipt, Error> {
    let response = agent
        .post(format!("{}{EVENT_PATH}", event.origin().as_str()))
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .header("Connection", "close")
        .send(event.as_bytes())
        .map_err(|error| transport_failure(transport::failure(error)))?;
    read_response(response, event)
}

fn read_response(
    response: Response<Body>,
    event: &SignedEvent,
) -> Result<HttpsEventReceipt, Error> {
    // Error bodies and arbitrary Retry-After/Location text are never read or copied.
    match response.status().as_u16() {
        200 => (),
        300..=399 => return Err(Error::Redirect),
        401 | 403 | 404 | 410 => return Err(Error::Unauthorized),
        400 | 409 | 413 | 422 => return Err(Error::Rejected),
        429 => return Err(Error::RateLimited),
        500..=599 => return Err(Error::Unavailable),
        _ => return Err(Error::Response),
    }
    let bytes =
        transport::read_json(response, MAX_EVENT_RECEIPT_BYTES).map_err(transport_failure)?;
    event
        .verify_receipt(&bytes)
        .map(HttpsEventReceipt)
        .map_err(|_| Error::Response)
}

fn transport_failure(error: transport::Error) -> Error {
    match error {
        transport::Error::Connection => Error::Connection,
        transport::Error::Timeout => Error::Timeout,
        transport::Error::Response => Error::Response,
    }
}
