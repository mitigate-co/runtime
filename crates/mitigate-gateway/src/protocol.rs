//! Lifecycle and request routing. Hostile client metadata cannot alter identity.
use crate::{Error, ToolRequest};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_IDS: usize = 32_768;
const MAX_MESSAGES: usize = 65_536;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Id {
    Text(String),
    Signed(i64),
    Unsigned(u64),
}
impl Id {
    pub fn parse(value: &Value) -> Option<Self> {
        match value {
            Value::String(s) if s.len() <= 128 => Some(Self::Text(s.clone())),
            Value::Number(n) => n
                .as_i64()
                .map(Self::Signed)
                .or_else(|| n.as_u64().map(Self::Unsigned)),
            _ => None,
        }
    }
    pub fn value(&self) -> Value {
        match self {
            Self::Text(s) => json!(s),
            Self::Signed(n) => json!(n),
            Self::Unsigned(n) => json!(n),
        }
    }
}

pub(crate) enum Action {
    Reply(Value),
    Relay(Id, ToolRequest),
    Cancel(Id),
    Ignore,
}
#[derive(PartialEq, Eq)]
enum Phase {
    New,
    AwaitingInitialized,
    Ready,
}
pub(crate) struct Session {
    phase: Phase,
    ids: BTreeSet<Id>,
    messages: usize,
    tools_supported: bool,
}
pub(crate) fn failure(id: Value, code: i32, message: &'static str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
pub(crate) fn result(id: &Id, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id.value(),"result":result})
}
fn fields(value: &Value, allowed: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.keys().all(|k| allowed.contains(&k.as_str())))
        && value.get("_meta").is_none_or(Value::is_object)
}
fn label(value: &Value, max: usize) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.len() <= max)
}
impl Session {
    pub fn new(tools_supported: bool) -> Self {
        Self {
            phase: Phase::New,
            ids: BTreeSet::new(),
            messages: 0,
            tools_supported,
        }
    }
    pub fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }
    pub fn accept(&mut self, message: Value) -> Result<Action, Error> {
        self.messages += 1;
        if self.messages > MAX_MESSAGES {
            return Err(Error::Limit);
        }
        if !fields(&message, &["jsonrpc", "id", "method", "params"])
            || message.get("jsonrpc") != Some(&json!("2.0"))
            || !label(&message["method"], 128)
            || message.get("params").is_some_and(|v| !v.is_object())
        {
            return Err(Error::Protocol);
        }
        let method = message["method"].as_str().ok_or(Error::Protocol)?;
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        let Some(id) = message.get("id") else {
            return self.notification(method, &params);
        };
        let id = Id::parse(id).ok_or(Error::Protocol)?;
        if self.ids.len() >= MAX_IDS {
            return Err(Error::Limit);
        }
        if !self.ids.insert(id.clone()) {
            return Err(Error::Protocol);
        }
        let invalid = || Action::Reply(failure(id.value(), -32602, "Invalid method parameters"));
        if method == "ping" {
            return Ok(if fields(&params, &["_meta"]) {
                Action::Reply(result(&id, json!({})))
            } else {
                invalid()
            });
        }
        if method == "initialize" {
            if self.phase != Phase::New {
                return Err(Error::Protocol);
            }
            if !fields(
                &params,
                &["protocolVersion", "capabilities", "clientInfo", "_meta"],
            ) || !label(&params["protocolVersion"], 64)
                || !params["capabilities"].is_object()
                || !label(&params["clientInfo"]["name"], 128)
                || !label(&params["clientInfo"]["version"], 128)
            {
                return Ok(invalid());
            }
            // The MCP protocol requires offering a supported version when the
            // client's proposal is unsupported. It must disconnect if unsuitable.
            let proposed = params["protocolVersion"].as_str().ok_or(Error::Protocol)?;
            let version = if VERSIONS.contains(&proposed) {
                proposed
            } else {
                VERSIONS[0]
            };
            self.phase = Phase::AwaitingInitialized;
            let capabilities = if self.tools_supported {
                json!({"tools":{}})
            } else {
                json!({})
            };
            return Ok(Action::Reply(result(
                &id,
                json!({
                    "protocolVersion": version, "capabilities": capabilities,
                    "serverInfo": {"name":"mitigate", "version":env!("CARGO_PKG_VERSION")}
                }),
            )));
        }
        if self.phase != Phase::Ready {
            return Ok(Action::Reply(failure(
                id.value(),
                -32000,
                "Complete MCP initialization before sending requests",
            )));
        }
        match method {
            "tools/list" if self.tools_supported => {
                if !fields(&params, &["cursor", "_meta"])
                    || params.get("cursor").is_some_and(|v| !label(v, 1024))
                {
                    return Ok(invalid());
                }
                Ok(Action::Relay(
                    id,
                    ToolRequest::List {
                        cursor: params
                            .get("cursor")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    },
                ))
            }
            "tools/call" if self.tools_supported => {
                if !fields(&params, &["name", "arguments", "_meta"])
                    || !label(&params["name"], 128)
                    || !params["name"].as_str().is_some_and(|s| {
                        s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                    })
                    || params.get("arguments").is_some_and(|v| !v.is_object())
                    || params
                        .get("_meta")
                        .and_then(|m| m.get("progressToken"))
                        .is_some_and(|token| Id::parse(token).is_none())
                {
                    return Ok(invalid());
                }
                Ok(Action::Relay(
                    id,
                    ToolRequest::Call {
                        name: params["name"].as_str().ok_or(Error::Protocol)?.to_owned(),
                        arguments: params
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                        meta: params.get("_meta").cloned(),
                    },
                ))
            }
            _ => Ok(Action::Reply(failure(
                id.value(),
                -32601,
                "Method not supported",
            ))),
        }
    }
    fn notification(&mut self, method: &str, params: &Value) -> Result<Action, Error> {
        match method {
            "notifications/initialized" => {
                if self.phase != Phase::AwaitingInitialized || !fields(params, &["_meta"]) {
                    return Err(Error::Protocol);
                }
                self.phase = Phase::Ready;
                Ok(Action::Ignore)
            }
            // Cancellation reasons are content. They are intentionally discarded.
            "notifications/cancelled" if self.phase == Phase::Ready => {
                Ok(Id::parse(&params["requestId"]).map_or(Action::Ignore, Action::Cancel))
            }
            _ => Ok(Action::Ignore),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_ids_remain_reserved_and_session_counts_are_bounded() {
        let mut session = Session::new(true);
        for id in 0..MAX_IDS {
            assert!(matches!(
                session.accept(json!({"jsonrpc":"2.0","id":id,"method":"ping"})),
                Ok(Action::Reply(_))
            ));
        }
        assert!(matches!(
            session.accept(json!({"jsonrpc":"2.0","id":"more","method":"ping"})),
            Err(Error::Limit)
        ));
        let mut session = Session::new(true);
        for _ in 0..MAX_MESSAGES {
            assert!(matches!(
                session.accept(json!({"jsonrpc":"2.0","method":"notifications/unknown"})),
                Ok(Action::Ignore)
            ));
        }
        assert!(matches!(
            session.accept(json!({"jsonrpc":"2.0","method":"notifications/unknown"})),
            Err(Error::Limit)
        ));
        let mut session = Session::new(true);
        for id in [json!(1), json!("1")] {
            assert!(matches!(
                session.accept(json!({"jsonrpc":"2.0","id":id,"method":"ping"})),
                Ok(Action::Reply(_))
            ));
        }
        assert!(matches!(
            session.accept(json!({"jsonrpc":"2.0","id":1,"method":"ping"})),
            Err(Error::Protocol)
        ));
    }
}
