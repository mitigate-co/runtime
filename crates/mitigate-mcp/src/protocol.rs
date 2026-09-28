//! One bounded enumeration session. No tool calls, content requests or sampling.

use crate::{Error, Inventory, Result, Tool};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) trait Transport {
    async fn send(&mut self, message: Value) -> Result<()>;
    async fn receive(&mut self) -> Result<Value>;
}

fn label(value: &Value, limit: usize) -> Result<&str> {
    let text = value.as_str().ok_or(Error::Protocol)?;
    let unsafe_display = text.chars().any(|c| {
        c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    });
    if text.is_empty() || text.len() > limit || unsafe_display {
        return Err(Error::Protocol);
    }
    Ok(text)
}

struct Session<'a, T> {
    transport: &'a mut T,
    server_requests: BTreeSet<String>,
    unsolicited: usize,
}
impl<T: Transport> Session<'_, T> {
    async fn request(&mut self, id: u32, method: &str, params: Value) -> Result<Value> {
        self.transport
            .send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await?;
        for _ in 0..64 {
            let message = self.transport.receive().await?;
            let fields = message.as_object().ok_or(Error::Protocol)?;
            if message.get("jsonrpc") != Some(&json!("2.0")) {
                return Err(Error::Protocol);
            }
            if let Some(method) = message.get("method") {
                if fields
                    .keys()
                    .any(|k| !["jsonrpc", "id", "method", "params"].contains(&k.as_str()))
                    || message.get("params").is_some_and(|p| !p.is_object())
                {
                    return Err(Error::Protocol);
                }
                let method = label(method, 128)?;
                self.unsolicited += 1;
                if self.unsolicited > 256 {
                    return Err(Error::Limit);
                }
                if let Some(request_id) = message.get("id") {
                    match request_id {
                        Value::String(_) => {
                            label(request_id, 128)?;
                        }
                        Value::Number(n) if n.is_i64() || n.is_u64() => (),
                        _ => return Err(Error::Protocol),
                    }
                    // Incoming request IDs are a separate namespace from ours,
                    // but each must be unique for the entire connection.
                    if !self.server_requests.insert(request_id.to_string()) {
                        return Err(Error::Protocol);
                    }
                    let response = if method == "ping" {
                        json!({"jsonrpc":"2.0","id":request_id,"result":{}})
                    } else {
                        json!({"jsonrpc":"2.0","id":request_id,"error":{"code":-32601,"message":"Method not supported"}})
                    };
                    self.transport.send(response).await?;
                } else if method == "notifications/tools/list_changed" {
                    return Err(Error::Changed);
                }
                // Unsolicited logs/notifications are discarded, never printed.
                continue;
            }
            if fields
                .keys()
                .any(|k| !["jsonrpc", "id", "result", "error"].contains(&k.as_str()))
                || message.get("id") != Some(&json!(id))
                || fields.contains_key("result") == fields.contains_key("error")
            {
                return Err(Error::Protocol);
            }
            if let Some(error) = message.get("error") {
                if !error.is_object()
                    || error.get("code").and_then(Value::as_i64).is_none()
                    || error.get("message").and_then(Value::as_str).is_none()
                {
                    return Err(Error::Protocol);
                }
                return Err(Error::Upstream);
            }
            return message
                .get("result")
                .filter(|v| v.is_object())
                .cloned()
                .ok_or(Error::Protocol);
        }
        Err(Error::Limit)
    }
}

fn tool(value: &Value) -> Result<Tool> {
    let name = label(&value["name"], 128)?;
    if !name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return Err(Error::Protocol);
    }
    let input = value
        .get("inputSchema")
        .filter(|v| v.is_object())
        .ok_or(Error::Protocol)?;
    if input.get("type") != Some(&json!("object")) {
        return Err(Error::Protocol);
    }
    for schema in std::iter::once(input).chain(value.get("outputSchema")) {
        if !schema.is_object()
            || schema.get("properties").is_some_and(|v| !v.is_object())
            || serde_json::to_vec(schema)
                .map_err(|_| Error::Protocol)?
                .len()
                > 65_536
        {
            return Err(Error::Protocol);
        }
    }
    let description = match value.get("description") {
        Some(v) => Some(
            v.as_str()
                .filter(|s| s.len() <= 16_384)
                .ok_or(Error::Protocol)?
                .to_owned(),
        ),
        None => None,
    };
    Ok(Tool {
        name: name.to_owned(),
        description,
        input_schema: input.clone(),
        output_schema: value.get("outputSchema").cloned(),
    })
}

pub(crate) async fn inventory(transport: &mut impl Transport) -> Result<Inventory> {
    let mut session = Session {
        transport,
        server_requests: BTreeSet::new(),
        unsolicited: 0,
    };
    let initialization = json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "mitigate", "version": env!("CARGO_PKG_VERSION") }
    });
    let init = session.request(1, "initialize", initialization).await?;
    let version = label(&init["protocolVersion"], 16)?;
    if !["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"].contains(&version) {
        return Err(Error::Version);
    }
    let capabilities = init
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or(Error::Protocol)?;
    if capabilities
        .get("tools")
        .is_some_and(|v| !v.is_object() || v.get("listChanged").is_some_and(|c| !c.is_boolean()))
    {
        return Err(Error::Protocol);
    }
    let mut report = Inventory {
        protocol_version: version.to_owned(),
        server_name: label(&init["serverInfo"]["name"], 128)?.to_owned(),
        server_version: label(&init["serverInfo"]["version"], 128)?.to_owned(),
        tools_supported: capabilities.contains_key("tools"),
        tools: Vec::new(),
    };
    session
        .transport
        .send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .await?;
    if !report.tools_supported {
        return Ok(report);
    }
    let mut cursor = None;
    let mut cursors = BTreeSet::new();
    let mut names = BTreeSet::new();
    for page in 0..32 {
        let params = cursor.map_or_else(|| json!({}), |c: String| json!({"cursor":c}));
        let response = session.request(page + 2, "tools/list", params).await?;
        let tools = response
            .get("tools")
            .and_then(Value::as_array)
            .ok_or(Error::Protocol)?;
        if report.tools.len() + tools.len() > 512 {
            return Err(Error::Limit);
        }
        for value in tools {
            let tool = tool(value)?;
            if !names.insert(tool.name.clone()) {
                return Err(Error::Protocol);
            }
            report.tools.push(tool);
        }
        cursor = match response.get("nextCursor") {
            None => {
                report.tools.sort_by(|a, b| a.name.cmp(&b.name));
                return Ok(report);
            }
            Some(v) => {
                let next = label(v, 1024)?.to_owned();
                if !cursors.insert(next.clone()) {
                    return Err(Error::Limit);
                }
                Some(next)
            }
        };
    }
    Err(Error::Limit)
}
