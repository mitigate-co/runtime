//! Shared private HTTPS policy and bounded JSON framing for the two fixed APIs.
//! No public agent, destination override, retry or provider diagnostic escapes.
use std::{io::Read, time::Duration};
use ureq::{Agent, Body, config::ConfigBuilder, http::Response, typestate::AgentScope};
use zeroize::Zeroizing;

pub(super) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Connection,
    Timeout,
    Response,
}

pub(super) fn config() -> ConfigBuilder<AgentScope> {
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
        // Observe the header cap plus a byte before the fixed input buffer fills.
        .input_buffer_size(16384)
        .output_buffer_size(2048)
        .max_response_header_size(8192)
        .timeout_global(Some(EXCHANGE_TIMEOUT))
        .timeout_resolve(Some(Duration::from_secs(5)))
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_send_request(Some(Duration::from_secs(5)))
        .timeout_send_body(Some(Duration::from_secs(5)))
        .timeout_recv_response(Some(Duration::from_secs(5)))
        .timeout_recv_body(Some(Duration::from_secs(5)))
}

pub(super) fn read_json(
    mut response: Response<Body>,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
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
        if length > limit {
            return Err(Error::Response);
        }
    }
    // Also bound chunked and EOF-delimited responses. A malicious endpoint may
    // reflect credentials or workload text: zeroize owned bytes on every exit.
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
    response
        .body_mut()
        .as_reader()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| failure(e.into()))?;
    if bytes.len() > limit {
        return Err(Error::Response);
    }
    Ok(bytes)
}

pub(super) fn failure(error: ureq::Error) -> Error {
    match error {
        ureq::Error::Timeout(_) => Error::Timeout,
        ureq::Error::LargeResponseHeader(_, _)
        | ureq::Error::Protocol(_)
        | ureq::Error::BodyExceedsLimit(_) => Error::Response,
        _ => Error::Connection,
    }
}
