//! Executable stdio composition. No permissive or unreviewed invocation mode.
mod authority;
mod configuration;
pub(crate) mod context;
mod enforcement;
mod facts;

use crate::output;
use mitigate_audit::{AuditStore, Decision, EventDetails, Operation, ResultClass};
use mitigate_fingerprint::{Domain, fingerprint};
use mitigate_gateway::{CallerIdentity, Fault, ToolRequest, ToolService};
use mitigate_mcp::{LaunchConfig, LaunchReview, StdioServer};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct GatewayService {
    upstream: StdioServer,
    audit: Option<Arc<Mutex<AuditStore>>>,
    enforcement: Option<enforcement::Enforcement>,
}
impl ToolService for GatewayService {
    fn request_timeout(&self) -> Duration {
        self.enforcement
            .as_ref()
            .map_or(Duration::from_secs(30), |e| e.request_timeout())
    }
    fn tools_supported(&self) -> bool {
        self.upstream.inventory().tools_supported
    }
    async fn request(
        &mut self,
        caller: &CallerIdentity,
        request: ToolRequest,
        progress: Option<mitigate_gateway::ProgressSink>,
    ) -> Result<Value, Fault> {
        let request = match request {
            ToolRequest::Call {
                name, arguments, ..
            } if self.enforcement.is_some() => {
                return self
                    .enforcement
                    .as_ref()
                    .ok_or(Fault::GovernanceUnavailable)?
                    .call(caller, &mut self.upstream, name, arguments, progress)
                    .await;
            }
            request => request,
        };
        let started = Instant::now();
        let detail = if self.audit.is_some() {
            Some(self.audit_details(caller, &request)?)
        } else {
            None
        };
        let result = self.execute(request).await;
        if let (Some(audit), Some(mut detail)) = (&self.audit, detail) {
            detail.duration_ms = started.elapsed().as_millis().min(86_400_000) as u64;
            (detail.decision, detail.result_class) = match &result {
                Ok(_) => (Decision::InventoryOnly, ResultClass::Success),
                Err(Fault::Disabled) => (Decision::Deny, ResultClass::NotInvoked),
                Err(_) => (Decision::Error, ResultClass::Error),
            };
            let audit = Arc::clone(audit);
            tokio::task::spawn_blocking(move || {
                audit
                    .lock()
                    .map_err(|_| mitigate_audit::Error::Unavailable)?
                    .append(detail)
            })
            .await
            .map_err(|_| Fault::AuditUnavailable)?
            .map_err(|_| Fault::AuditUnavailable)?;
        }
        result
    }
}
impl GatewayService {
    fn audit_details(
        &self,
        caller: &CallerIdentity,
        request: &ToolRequest,
    ) -> Result<EventDetails, Fault> {
        let inventory = self.upstream.inventory();
        let server_ref = match self.upstream.launch_receipt() {
            Some(receipt) => receipt.launch_ref.clone(),
            None => fingerprint(Domain::ServerIdentity, &json!(inventory.server_name))
                .map_err(|_| Fault::AuditUnavailable)?,
        };
        let operation = match request {
            ToolRequest::List { .. } => Operation::Inventory,
            ToolRequest::Call { .. } => Operation::ToolCall,
        };
        let mut detail = EventDetails::new(caller, server_ref, operation);
        if let ToolRequest::Call { name, .. } = request
            && let Some(tool) = inventory.tools.iter().find(|t| &t.name == name)
        {
            detail.tool_ref = Some(
                fingerprint(Domain::ToolIdentity, &json!([detail.server_ref, tool.name]))
                    .map_err(|_| Fault::AuditUnavailable)?,
            );
            detail.schema_fingerprint = Some(
                fingerprint(Domain::InputSchema, &tool.input_schema)
                    .map_err(|_| Fault::AuditUnavailable)?,
            );
            let report = inventory
                .classify(&Default::default())
                .map_err(|_| Fault::AuditUnavailable)?;
            detail.capability_classes = report
                .tools
                .into_iter()
                .find(|t| t.name == name)
                .ok_or(Fault::AuditUnavailable)?
                .classification
                .classes;
        }
        Ok(detail)
    }
    async fn execute(&mut self, request: ToolRequest) -> Result<Value, Fault> {
        match request {
            ToolRequest::Call { .. } => Err(Fault::Disabled),
            ToolRequest::List { cursor } => {
                let start = match cursor {
                    None => 0,
                    Some(s) => s
                        .strip_prefix("m1:")
                        .and_then(|s| s.parse::<usize>().ok())
                        .ok_or(Fault::InvalidParams)?,
                };
                let count = self.upstream.inventory().tools.len();
                if start > count || (start == count && start != 0) {
                    return Err(Fault::InvalidParams);
                }
                self.upstream.check_inventory().await.map_err(|error| {
                    if matches!(
                        error,
                        mitigate_mcp::Error::Changed | mitigate_mcp::Error::LaunchChanged
                    ) {
                        Fault::Changed
                    } else {
                        Fault::Upstream
                    }
                })?;
                let mut tools = Vec::new();
                let mut next = start;
                for tool in self.upstream.inventory().tools.iter().skip(start).take(16) {
                    let mut value = json!({"name":tool.name,"inputSchema":tool.input_schema});
                    if let Some(description) = &tool.description {
                        value["description"] = json!(description);
                    }
                    if let Some(schema) = &tool.output_schema {
                        value["outputSchema"] = schema.clone();
                    }
                    tools.push(value);
                    let candidate = json!({"jsonrpc":"2.0","id":"x".repeat(128),"result":{"tools":tools,"nextCursor":"m1:512"}});
                    let bytes = serde_json::to_vec(&candidate).map_err(|_| Fault::Upstream)?;
                    if bytes.len() > 524_288 || mitigate_json::parse(&bytes).is_err() {
                        tools.pop();
                        if tools.is_empty() {
                            return Err(Fault::Upstream);
                        }
                        break;
                    }
                    next += 1;
                }
                let mut result = json!({"tools":tools});
                if next < count {
                    result["nextCursor"] = json!(format!("m1:{next}"));
                }
                Ok(result)
            }
        }
    }
}

fn profile(path: Option<&Path>) -> Result<CallerIdentity, mitigate_gateway::Error> {
    let Some(path) = path else {
        return Ok(CallerIdentity::default());
    };
    let read = || -> io::Result<Vec<u8>> {
        let metadata = path.symlink_metadata()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(io::Error::other("invalid profile"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(io::Error::other("invalid profile"));
            }
        }
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("invalid profile"));
        }
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        Ok(bytes)
    };
    CallerIdentity::from_profile(&read().map_err(|_| mitigate_gateway::Error::Profile)?)
}

pub(crate) fn run(
    launch_path: &Path,
    profile_path: Option<&Path>,
    audit_path: Option<&Path>,
    review_path: Option<&Path>,
    enforcement_path: Option<&Path>,
) -> io::Result<ExitCode> {
    // Reject profile/config before opening stdin or executing the upstream.
    let caller = match profile(profile_path) {
        Ok(caller) => caller,
        Err(error) => {
            output::error("gateway_profile_invalid", &error.to_string(), false)?;
            return Ok(ExitCode::from(2));
        }
    };
    let config = match LaunchConfig::from_file(launch_path) {
        Ok(config) => config,
        Err(error) => return super::mcp_error(error, false),
    };
    let review = match review_path.map(LaunchReview::from_file).transpose() {
        Ok(review) => review,
        Err(error) => return super::mcp_error(error, false),
    };
    let mut enforcement = match enforcement_path
        .map(enforcement::Enforcement::open)
        .transpose()
    {
        Ok(enforcement) => enforcement,
        Err(_) => {
            output::error(
                "gateway_governance_invalid",
                "Cannot open local governance. Check the explicit configuration, reviewed snapshot, trust, grants and initialized stores.",
                false,
            )?;
            return Ok(ExitCode::from(2));
        }
    };
    if enforcement.is_some() && review.is_none() {
        output::error(
            "gateway_review_required",
            "Enforcement requires an explicit launch review.",
            false,
        )?;
        return Ok(ExitCode::from(2));
    }
    let audit = match audit_path.map(AuditStore::open).transpose() {
        Ok(audit) => audit.map(|store| Arc::new(Mutex::new(store))),
        Err(error) => {
            output::error(error.code(), &error.to_string(), false)?;
            return Ok(ExitCode::from(2));
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            output::error(
                "gateway_runtime_unavailable",
                "Cannot start the local gateway runtime. Check OS process and thread limits.",
                false,
            )?;
            return Ok(ExitCode::from(2));
        }
    };
    let outcome = runtime.block_on(async {
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        tokio::pin!(shutdown);
        let connection = match &review {
            Some(review) => {
                StdioServer::connect_reviewed_with_shutdown(&config, review, &mut shutdown).await
            }
            None => StdioServer::connect_with_shutdown(&config, &mut shutdown).await,
        };
        let mut upstream = match connection {
            Ok(server) => server,
            Err(error) => return Err((error.code(), error.to_string())),
        };
        if let Some(enforcement) = &mut enforcement
            && enforcement.bind(&upstream).is_err()
        {
            upstream.close().await.map_err(|e| (e.code(), e.to_string()))?;
            return Err(("gateway_review_changed", "Observed definitions differ from the reviewed snapshot. Inspect and review before enforcement.".into()));
        }
        let audit = enforcement.as_ref().map(|e| Arc::clone(&e.audit)).or(audit);
        let mut service = GatewayService { upstream, audit, enforcement };
        let result = mitigate_gateway::serve(
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
            &mut service,
            caller,
            &mut shutdown,
        )
        .await;
        let upstream_cleanup = service.upstream.close().await;
        let governance_cleanup = match &service.enforcement {
            Some(enforcement) => enforcement.close().await,
            None => Ok(()),
        };
        upstream_cleanup.map_err(|e| (e.code(), e.to_string()))?;
        governance_cleanup.map_err(|_| ("gateway_cleanup_unavailable", "Local call cleanup could not be committed. Inspect approvals and audit before starting another session.".into()))?;
        result.map_err(|error| ("gateway_session_failed", error.to_string()))
    });
    // OS stdio and an already-started SQLite commit cannot be cancelled by dropping
    // their tasks. Upstream cleanup was awaited above. This single-command CLI
    // exits after reporting the outcome; SQLite recovers interrupted transactions
    // on reopen. A cancelled request never receives an audited success response.
    runtime.shutdown_timeout(Duration::from_millis(50));
    match outcome {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err((code, message)) => {
            output::error(code, &message, false)?;
            Ok(ExitCode::from(2))
        }
    }
}
