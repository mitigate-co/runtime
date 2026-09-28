//! Managed upstream connection. Authorization belongs above this transport layer.
use crate::{
    Error, Inventory, LaunchConfig, Result, Snapshot,
    protocol::{self, Client},
    stdio::Session,
};
use serde_json::{Value, json};
use std::time::Duration;

/// Sanitized progress counters. Upstream free-form progress messages are omitted.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Progress {
    /// Nonnegative, monotonically increasing work completed.
    pub completed: f64,
    /// Optional nonnegative total, at least the completed amount.
    pub total: Option<f64>,
}

/// One caller-approved stdio server with retained protocol state and fingerprints.
///
/// This is an upstream transport, not a grant/policy evaluator. Callers must
/// authorize invocations before calling `call`. No Runtime CLI exposes unchecked
/// calls. Construction executes the reviewed program with caller OS privileges.
pub struct StdioServer {
    process: Session,
    client: Client,
    inventory: Inventory,
    baseline: Snapshot,
    deadline: Duration,
    usable: bool,
}

// A cancelled future must poison and terminate its connection before releasing
// the mutable borrow. Otherwise a late response could be consumed by a new call.
struct Operation<'a> {
    process: &'a mut Session,
    usable: &'a mut bool,
    completed: bool,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            *self.usable = false;
            self.process.interrupt();
        }
    }
}
impl StdioServer {
    /// Start, initialize and fully enumerate an explicitly authorized executable.
    /// Failure confirms cleanup; dropping construction kills its job/group.
    pub async fn connect(config: &LaunchConfig) -> Result<Self> {
        let mut process = Session::start(config)?;
        let mut client = Client::new();
        let deadline = Duration::from_millis(config.timeout_ms);
        let result = tokio::time::timeout(deadline, async {
            let mut inventory = protocol::initialize(&mut client, &mut process).await?;
            if inventory.tools_supported {
                inventory.tools = protocol::list_tools(&mut client, &mut process).await?;
            }
            let baseline = Snapshot::from_inventory(&inventory)?;
            Ok((inventory, baseline))
        })
        .await
        .map_err(|_| Error::Timeout)
        .and_then(|r| r);
        match result {
            Ok((inventory, baseline)) => Ok(Self {
                process,
                client,
                inventory,
                baseline,
                deadline,
                usable: true,
            }),
            Err(error) => {
                process.close().await?;
                Err(error)
            }
        }
    }

    /// Initial observed definitions. Not an authenticated execution identity.
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }

    /// Re-enumerate on the same connection and refuse any baseline drift.
    /// An error invalidates the connection; review/reconnect rather than retrying.
    pub async fn check_inventory(&mut self) -> Result<()> {
        if !self.usable {
            return Err(Error::Disconnected);
        }
        self.process.begin_transaction();
        self.client.begin_transaction();
        let mut operation = Operation {
            process: &mut self.process,
            usable: &mut self.usable,
            completed: false,
        };
        let result = tokio::time::timeout(
            self.deadline,
            refresh(
                &mut self.client,
                operation.process,
                &self.inventory,
                &self.baseline,
            ),
        )
        .await
        .map_err(|_| Error::Timeout)
        .and_then(|r| r);
        operation.completed = result.is_ok();
        drop(operation);
        if result.is_err() {
            self.process.close().await?;
        }
        result
    }

    /// Relay an already-authorized tool invocation after a fresh inventory check.
    ///
    /// Arguments/results stay local and are never printed or persisted here.
    /// The owner must evaluate grants, policy, schema review and approval first.
    /// This function only checks protocol/observed definition consistency.
    /// `progress` receives counters only, never upstream message text or tokens.
    /// Once a transaction starts, failure/cancellation terminates the process and
    /// forbids reuse. Invalid local input is refused without starting a transaction.
    pub async fn call(
        &mut self,
        name: &str,
        arguments: Value,
        mut progress: Option<&mut dyn FnMut(Progress)>,
    ) -> Result<Value> {
        if !self.usable {
            return Err(Error::Disconnected);
        }
        if !arguments.is_object() || !self.inventory.tools.iter().any(|tool| tool.name == name) {
            return Err(Error::Protocol);
        }
        // Validate size/complexity before any new upstream request. Raw content
        // never enters errors, including invalid input supplied by library callers.
        let bytes = serde_json::to_vec(&arguments).map_err(|_| Error::Protocol)?;
        if bytes.len() > 60_000 || mitigate_json::parse(&bytes).is_err() {
            return Err(Error::Limit);
        }
        self.process.begin_transaction();
        self.client.begin_transaction();
        let mut operation = Operation {
            process: &mut self.process,
            usable: &mut self.usable,
            completed: false,
        };
        let result = tokio::time::timeout(self.deadline, async {
            refresh(
                &mut self.client,
                operation.process,
                &self.inventory,
                &self.baseline,
            )
            .await?;
            let token = json!(self.client.next_request_id());
            let mut params = json!({"name":name,"arguments":arguments});
            if progress.is_some() {
                params["_meta"] = json!({"progressToken":token});
            }
            let mut previous = None;
            let mut on_progress = |value: &Value| -> Result<()> {
                if value.get("progressToken") != Some(&token) {
                    return Err(Error::Protocol);
                }
                let completed = value["progress"]
                    .as_f64()
                    .filter(|n| n.is_finite() && *n >= 0.0)
                    .ok_or(Error::Protocol)?;
                if previous.is_some_and(|old| completed <= old) {
                    return Err(Error::Protocol);
                }
                let total = match value.get("total") {
                    None => None,
                    Some(v) => Some(
                        v.as_f64()
                            .filter(|n| n.is_finite() && *n >= completed)
                            .ok_or(Error::Protocol)?,
                    ),
                };
                previous = Some(completed);
                if let Some(callback) = &mut progress {
                    callback(Progress { completed, total });
                }
                Ok(())
            };
            let result = self
                .client
                .request(
                    operation.process,
                    "tools/call",
                    params,
                    Some(&mut on_progress),
                )
                .await?;
            validate_result(&result)?;
            Ok(result)
        })
        .await
        .map_err(|_| Error::Timeout)
        .and_then(|r| r);
        operation.completed = result.is_ok();
        drop(operation);
        if result.is_err() {
            self.process.close().await?;
        }
        result
    }

    /// Terminate the process group/job and confirm completion within two seconds.
    /// Safe to repeat. Dropping the server kills but cannot await process reaping.
    pub async fn close(&mut self) -> Result<()> {
        self.usable = false;
        self.process.close().await
    }
}

async fn refresh(
    client: &mut Client,
    process: &mut Session,
    inventory: &Inventory,
    baseline: &Snapshot,
) -> Result<()> {
    if !inventory.tools_supported {
        client.request(process, "ping", json!({}), None).await?;
        return Ok(());
    }
    let current = Inventory {
        protocol_version: inventory.protocol_version.clone(),
        server_name: inventory.server_name.clone(),
        server_version: inventory.server_version.clone(),
        tools_supported: inventory.tools_supported,
        tools: protocol::list_tools(client, process).await?,
    };
    if !baseline
        .diff(&Snapshot::from_inventory(&current)?)?
        .is_empty()
    {
        return Err(Error::Changed);
    }
    Ok(())
}

fn validate_result(result: &Value) -> Result<()> {
    if result.get("isError").is_some_and(|v| !v.is_boolean())
        || result
            .get("structuredContent")
            .is_some_and(|v| !v.is_object())
        || result.get("_meta").is_some_and(|v| !v.is_object())
    {
        return Err(Error::Protocol);
    }
    let content = result["content"].as_array().ok_or(Error::Protocol)?;
    if content.len() > 256 {
        return Err(Error::Limit);
    }
    for block in content {
        let valid = match block["type"].as_str() {
            Some("text") => block["text"].is_string(),
            Some("image" | "audio") => block["data"].is_string() && block["mimeType"].is_string(),
            Some("resource_link") => block["uri"].is_string() && block["name"].is_string(),
            Some("resource") => {
                let resource = &block["resource"];
                resource["uri"].is_string()
                    && (resource.get("text").is_some() != resource.get("blob").is_some())
                    && resource
                        .get("text")
                        .or_else(|| resource.get("blob"))
                        .is_some_and(Value::is_string)
            }
            _ => false,
        };
        if !valid {
            return Err(Error::Protocol);
        }
    }
    Ok(())
}
