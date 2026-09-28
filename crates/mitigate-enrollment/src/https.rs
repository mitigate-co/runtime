//! Explicit bootstrap exchange, separate from Zero-Content event transmission.
//! No redirects, ambient proxy, cookies, compression, retries or credential logs.
use crate::{EnrollmentClaim, EnrollmentReceipt, MAX_ENROLLMENT_BYTES};
use std::{fmt, io::Read, time::Duration};
use ureq::{Agent, Body, config::ConfigBuilder, http::Response, typestate::AgentScope};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

/// Fixed failures. Provider errors, headers and response bodies are never exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Transport or authenticated TLS could not be established/completed.
    Connection,
    /// A bounded request phase exceeded its deadline; acceptance may be uncertain.
    Timeout,
    /// The selected Platform returned a redirect, which was not followed.
    Redirect,
    /// Platform refused the bootstrap credential or enrollment binding.
    Rejected,
    /// Platform asked the caller to wait; no automatic retry is attempted.
    RateLimited,
    /// Platform returned a server error; local MCP operation is unaffected.
    Unavailable,
    /// Unsupported status, framing, media type, size or mismatched receipt.
    Response,
}
impl Error {
    /// Stable machine-readable category, without response-dependent text.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Connection => "enrollment_connection",
            Self::Timeout => "enrollment_timeout",
            Self::Redirect => "enrollment_redirect",
            Self::Rejected => "enrollment_rejected",
            Self::RateLimited => "enrollment_rate_limited",
            Self::Unavailable => "enrollment_unavailable",
            Self::Response => "enrollment_response",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connection => "Could not complete a verified HTTPS connection. Check the Platform address, network and system clock; retain the pending enrollment.",
            Self::Timeout => "Enrollment timed out. Retry the same pending enrollment to recover its result.",
            Self::Redirect => "Platform redirected enrollment. No redirect was followed. Check the configured Platform address.",
            Self::Rejected => "Platform rejected enrollment. Check the code's expiry, revocation and organization access before starting a new enrollment.",
            Self::RateLimited => "Platform limited enrollment attempts. Wait before retrying the same pending enrollment.",
            Self::Unavailable => "Platform is unavailable. Retry the same pending enrollment later; local MCP protection remains available.",
            Self::Response => "Platform returned an invalid enrollment response. Retain the same pending enrollment for recovery.",
        })
    }
}
impl std::error::Error for Error {}

/// An HTTPS-authenticated response validated against the submitted claim.
/// No generic formatting/serialization; rejected response bytes never escape.
pub struct HttpsReceipt {
    bytes: Zeroizing<Vec<u8>>,
    receipt: EnrollmentReceipt,
}
impl HttpsReceipt {
    /// Closed receipt facts. This does not establish durable local confirmation.
    pub fn receipt(&self) -> &EnrollmentReceipt {
        &self.receipt
    }
    /// Borrow for native lifecycle confirmation while its operation lock is held.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Submit exactly one explicit enrollment request to its signed HTTPS audience.
///
/// The caller must persist pending identity/code/key in the native store **before**
/// calling, retain exclusive ownership through response confirmation, and obtain
/// user intent separately. Errors do not establish whether Platform accepted the
/// request. Recovery must use the identical pending proof. No automatic retry,
/// durable write, background task or telemetry activation occurs here.
pub fn submit(claim: &EnrollmentClaim) -> Result<HttpsReceipt, Error> {
    exchange(&config().build().into(), claim)
}

fn config() -> ConfigBuilder<AgentScope> {
    Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent("")
        .accept("application/json")
        .accept_encoding("identity")
        .max_idle_connections(0)
        .max_idle_connections_per_host(0)
        // The parser must be able to observe the header cap plus a byte before
        // the fixed input buffer fills, otherwise an oversize looks like EOF.
        .input_buffer_size(16384)
        .output_buffer_size(2048)
        .max_response_header_size(8192)
        .timeout_global(Some(Duration::from_secs(20)))
        .timeout_resolve(Some(Duration::from_secs(5)))
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_send_request(Some(Duration::from_secs(5)))
        .timeout_send_body(Some(Duration::from_secs(5)))
        .timeout_recv_response(Some(Duration::from_secs(5)))
        .timeout_recv_body(Some(Duration::from_secs(5)))
}

fn exchange(agent: &Agent, claim: &EnrollmentClaim) -> Result<HttpsReceipt, Error> {
    let destination = format!("{}/api/v1/runtime/enroll", claim.origin().as_str());
    let response = agent
        .post(destination)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .header("Connection", "close")
        .send(claim.as_bytes())
        .map_err(transport_error)?;
    read_response(response, claim)
}

fn read_response(
    mut response: Response<Body>,
    claim: &EnrollmentClaim,
) -> Result<HttpsReceipt, Error> {
    // Do not read error/redirect bodies, copy arbitrary Retry-After/Location text,
    // or turn a returned page into a user-visible provider diagnostic.
    match response.status().as_u16() {
        200 => (),
        300..=399 => return Err(Error::Redirect),
        400 | 401 | 403 | 404 | 409 => return Err(Error::Rejected),
        429 => return Err(Error::RateLimited),
        500..=599 => return Err(Error::Unavailable),
        _ => return Err(Error::Response),
    }
    let headers = response.headers();
    let mut types = headers.get_all("content-type").iter();
    let media_type = types.next().ok_or(Error::Response)?;
    if types.next().is_some()
        || !matches!(
            media_type.to_str(),
            Ok("application/json" | "application/json; charset=utf-8")
        )
        || headers.contains_key("content-encoding")
        || headers.contains_key("set-cookie")
    {
        return Err(Error::Response);
    }
    if let Some(length) = headers.get("content-length") {
        let length = length
            .to_str()
            .map_err(|_| Error::Response)?
            .parse::<usize>()
            .map_err(|_| Error::Response)?;
        if length > MAX_ENROLLMENT_BYTES {
            return Err(Error::Response);
        }
    }
    // The read bound also applies to chunked and absent/lying Content-Length.
    // A malicious authenticated endpoint may reflect credentials; the buffer is
    // zeroized on every exit, including partial reads and parse failure.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_ENROLLMENT_BYTES + 1));
    response
        .body_mut()
        .as_reader()
        .take((MAX_ENROLLMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| transport_error(e.into()))?;
    let receipt = claim.verify_receipt(&bytes).map_err(|_| Error::Response)?;
    Ok(HttpsReceipt { bytes, receipt })
}

fn transport_error(error: ureq::Error) -> Error {
    match error {
        ureq::Error::Timeout(_) => Error::Timeout,
        ureq::Error::LargeResponseHeader(_, _)
        | ureq::Error::Protocol(_)
        | ureq::Error::BodyExceedsLimit(_) => Error::Response,
        _ => Error::Connection,
    }
}
