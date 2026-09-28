//! Executable stdio composition. No permissive or unreviewed invocation mode.
use crate::output;
use mitigate_gateway::{CallerIdentity, Fault, ToolRequest, ToolService};
use mitigate_mcp::{LaunchConfig, StdioServer};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    process::ExitCode,
    time::Duration,
};

struct InventoryService {
    upstream: StdioServer,
}
impl ToolService for InventoryService {
    fn tools_supported(&self) -> bool {
        self.upstream.inventory().tools_supported
    }
    async fn request(
        &mut self,
        _caller: &CallerIdentity,
        request: ToolRequest,
    ) -> Result<Value, Fault> {
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
                    if error == mitigate_mcp::Error::Changed {
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

pub(crate) fn run(launch_path: &Path, profile_path: Option<&Path>) -> io::Result<ExitCode> {
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
        let upstream = match StdioServer::connect_with_shutdown(&config, &mut shutdown).await {
            Ok(server) => server,
            Err(error) => return Err((error.code(), error.to_string())),
        };
        let mut service = InventoryService { upstream };
        let result = mitigate_gateway::serve(
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
            &mut service,
            caller,
            &mut shutdown,
        )
        .await;
        service
            .upstream
            .close()
            .await
            .map_err(|e| (e.code(), e.to_string()))?;
        result.map_err(|error| ("gateway_session_failed", error.to_string()))
    });
    // Tokio stdio uses blocking OS I/O that cannot be cancelled. Only these pipe
    // workers may remain; upstream cleanup was awaited above. This single-command
    // CLI exits immediately after reporting the outcome, ending those workers.
    runtime.shutdown_timeout(Duration::from_millis(50));
    match outcome {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err((code, message)) => {
            output::error(code, &message, false)?;
            Ok(ExitCode::from(2))
        }
    }
}
