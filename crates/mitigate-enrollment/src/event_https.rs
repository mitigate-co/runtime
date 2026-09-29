//! One explicit signed event exchange using a confirmed, locked native enrollment.
//! Composes one bounded attempt with exact lease checks and durable completion.
//! No consent activation, background worker or automatic retry loop.
use crate::{
    event::{EVENT_PATH, EventReceipt, MAX_EVENT_RECEIPT_BYTES, SignedEvent},
    storage::{self, EnrollmentStore},
    transport,
};
use mitigate_egress::outbox::{self, DeliveryOutcome, Lease, Outbox};
use std::fmt;
use ureq::{Agent, Body, http::Response};

#[cfg(test)]
mod tests;

/// Fixed failures, without response bodies, headers or provider error chains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Confirmed native state or matching lease was unavailable; nothing was sent.
    Enrollment(storage::Error),
    /// Queue state could not authorize or durably finish this attempt.
    Outbox(outbox::Error),
    /// Consent was paused or too little lease/retention time remains. Nothing sent.
    NotReady,
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
            Self::Outbox(_) => "sync_outbox",
            Self::NotReady => "sync_not_ready",
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
            Self::Outbox(error) => error.fmt(f),
            Self::NotReady => f.write_str("Delivery is paused or its time budget expired. No request was sent."),
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
/// state fails before network I/O. Rechecks the committed outbox immediately
/// before transmission, reserving the HTTP deadline plus five seconds for local
/// completion. The caller still coordinates shutdown and persists the outcome.
/// This cannot retract an already dispatched request or extend the lease.
pub fn submit(
    store: &EnrollmentStore,
    outbox: &mut Outbox,
    lease: &Lease,
) -> Result<HttpsEventReceipt, Error> {
    let signed = store.sign_event(lease).map_err(Error::Enrollment)?;
    let agent = transport::config().build().into();
    checked_exchange(outbox, lease, &signed, &agent)
}

fn checked_exchange(
    outbox: &mut Outbox,
    lease: &Lease,
    signed: &SignedEvent,
    agent: &Agent,
) -> Result<HttpsEventReceipt, Error> {
    let budget_ms = transport::EXCHANGE_TIMEOUT.as_millis() as u64 + 5000;
    if !outbox
        .delivery_ready(lease, budget_ms)
        .map_err(Error::Outbox)?
    {
        return Err(Error::NotReady);
    }
    exchange(agent, signed)
}

/// One completed queue operation, never an event/response payload. Retry and
/// pause report only fixed transport categories; local commit failure is Err.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Paused, empty, leased, backing off or without enough retention to send.
    Idle,
    /// Exact authenticated acknowledgment and local completion both committed.
    Accepted,
    /// Permanent refusal recorded; unchanged bytes will not be retried.
    Rejected,
    /// Same event retained with bounded retry backoff.
    Retry(Error),
    /// Enrollment refusal or redirect paused the entire queue.
    Paused(Error),
}

/// Send at most one ready event, with no loop, implicit resume or producer.
/// Open the enrollment before calling: native credential prompts must finish
/// before claiming a short-lived lease. Its exclusive owner stays borrowed until
/// the receipt/outcome commit finishes. Call only on an optional sync worker;
/// queue/network failures must never control local MCP authorization.
pub fn deliver_next(store: &EnrollmentStore, outbox: &mut Outbox) -> Result<Delivery, Error> {
    if !matches!(store.status(), storage::Status::Confirmed { .. }) {
        return Err(Error::Enrollment(storage::Error::Pending));
    }
    let report = outbox.inspect().map_err(Error::Outbox)?;
    if &report.partition.runtime_ref != store.identity().runtime_ref()
        || &report.partition.enrollment_ref != store.identity().enrollment_ref()
    {
        return Err(Error::Enrollment(storage::Error::Scope));
    }
    deliver_with(outbox, |outbox, lease| submit(store, outbox, lease))
}

// Private seam injects failures after real claims without granting callers a
// configurable transport or an acknowledgment constructor.
fn deliver_with(
    outbox: &mut Outbox,
    send: impl FnOnce(&mut Outbox, &Lease) -> Result<HttpsEventReceipt, Error>,
) -> Result<Delivery, Error> {
    let budget_ms = transport::EXCHANGE_TIMEOUT.as_millis() as u64 + 5000;
    let Some(lease) = outbox
        .claim_for_delivery(budget_ms)
        .map_err(Error::Outbox)?
    else {
        return Ok(Delivery::Idle);
    };
    let (outcome, result) = match send(outbox, &lease) {
        Ok(_) => (DeliveryOutcome::Accepted, Delivery::Accepted),
        Err(Error::Rejected) => (DeliveryOutcome::Rejected, Delivery::Rejected),
        Err(reason @ (Error::Unauthorized | Error::Redirect)) => {
            (DeliveryOutcome::Unauthorized, Delivery::Paused(reason))
        }
        Err(
            reason @ (Error::Connection
            | Error::Timeout
            | Error::RateLimited
            | Error::Unavailable
            | Error::Response),
        ) => (DeliveryOutcome::Transient, Delivery::Retry(reason)),
        // Nothing was sent. Retain the claim for normal expiry/recovery without
        // rewriting consent or mistaking a local failure for receiver rejection.
        Err(error @ (Error::Enrollment(_) | Error::Outbox(_) | Error::NotReady)) => {
            return Err(error);
        }
    };
    outbox.complete(lease, outcome).map_err(Error::Outbox)?;
    Ok(result)
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
