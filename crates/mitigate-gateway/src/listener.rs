//! One content-plane session. A busy backend does not prevent ping/cancellation.
use crate::{
    CallerIdentity, Error, Fault,
    framing::{self, Reader},
    protocol::{self, Action, Session},
};
use serde_json::{Value, json};
use std::{future::Future, time::Duration};
use tokio::{
    io::{AsyncBufRead, AsyncWrite},
    time::{Instant, sleep_until},
};

/// Validated tool request, containing local content that must never be logged.
/// No Debug/Serialize implementation; only an authorized service may forward it.
pub enum ToolRequest {
    /// Enumerate one page of definitions.
    List {
        /// Opaque, bounded upstream cursor; not an authorization token.
        cursor: Option<String>,
    },
    /// Tool invocation awaiting service authorization.
    Call {
        /// Bounded tool identity.
        name: String,
        /// Raw local arguments, never policy or Platform metadata.
        arguments: Value,
        /// Bounded local MCP metadata, never trusted identity or telemetry.
        meta: Option<Value>,
    },
}

/// Security boundary between protocol handling and authorized upstream execution.
///
/// Implementations MUST enforce policy before tool execution, return fixed faults
/// rather than upstream error bodies, and clean up when the request future drops.
/// Session owners must confirm upstream cleanup after `serve` returns. This trait
/// is intentionally local/non-Send; no detached background requests are created.
pub trait ToolService {
    /// Advertise only implemented tool support, fixed for this session.
    fn tools_supported(&self) -> bool;
    /// Handle a validated request with Runtime-supplied identity, never clientInfo.
    fn request(
        &mut self,
        caller: &CallerIdentity,
        request: ToolRequest,
    ) -> impl Future<Output = Result<Value, Fault>>;
}

/// Serve MCP over an already-owned local newline-delimited stream.
///
/// Opens no listener socket and does not authenticate network peers. Intended for
/// inherited stdio pipes. Idle sessions can remain open; initialization is bounded
/// to 10 seconds, requests to 30 seconds and output writes to 5 seconds. One tool
/// request is active at a time; concurrent tool requests receive a busy error.
/// Cancellation ends this connection without a response to the cancelled request.
/// This prevents late upstream results from being confused with later requests.
pub async fn serve(
    input: impl AsyncBufRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    service: &mut impl ToolService,
    caller: CallerIdentity,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let mut reader = Reader::new(input);
    let mut session = Session::new(service.tools_supported());
    let initialize_deadline = Instant::now() + Duration::from_secs(10);
    let session_deadline = Instant::now() + Duration::from_secs(86_400);
    tokio::pin!(shutdown);
    loop {
        let deadline = if session.ready() {
            session_deadline
        } else {
            initialize_deadline
        };
        let bytes = tokio::select! {
            biased;
            _ = &mut shutdown => return Ok(()),
            _ = sleep_until(deadline) => return Err(Error::Timeout),
            bytes = reader.next() => bytes?,
        };
        let Some(bytes) = bytes else {
            return Ok(());
        };
        let action = accept(&mut session, &mut output, &bytes).await?;
        match action {
            Action::Reply(reply) => framing::write(&mut output, reply).await?,
            Action::Ignore | Action::Cancel(_) => (),
            Action::Relay(id, request) => {
                let operation = service.request(&caller, request);
                tokio::pin!(operation);
                let deadline = (Instant::now() + Duration::from_secs(30)).min(session_deadline);
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut shutdown => return Ok(()),
                        _ = sleep_until(deadline) => {
                            framing::write(&mut output, protocol::failure(id.value(), -32002, "Request deadline exceeded")).await?;
                            return Err(Error::Timeout);
                        }
                        bytes = reader.next() => {
                            let Some(bytes) = bytes? else { return Ok(()); };
                            match accept(&mut session, &mut output, &bytes).await? {
                                Action::Cancel(cancelled) if cancelled == id => return Err(Error::Cancelled),
                                Action::Reply(reply) => framing::write(&mut output, reply).await?,
                                Action::Relay(other, _) => framing::write(&mut output, protocol::failure(other.value(), -32005, "Gateway busy; wait for the current request")).await?,
                                _ => (),
                            }
                        }
                        result = &mut operation => {
                            let reply = match result {
                                Ok(value) if value.is_object() => protocol::result(&id, value),
                                Ok(_) => protocol::failure(id.value(), -32603, "Invalid local service response"),
                                Err(fault) => { let (code, message) = fault.parts(); protocol::failure(id.value(), code, message) }
                            };
                            framing::write(&mut output, reply).await?;
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn accept(
    session: &mut Session,
    output: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<Action, Error> {
    let value = match mitigate_json::parse(bytes) {
        Ok(value) => value,
        Err(_) => {
            framing::write(
                output,
                protocol::failure(json!(null), -32700, "Invalid or ambiguous JSON"),
            )
            .await?;
            return Err(Error::Protocol);
        }
    };
    match session.accept(value) {
        Ok(action) => Ok(action),
        Err(error) => {
            framing::write(
                output,
                protocol::failure(json!(null), -32600, "Invalid MCP session"),
            )
            .await?;
            Err(error)
        }
    }
}
