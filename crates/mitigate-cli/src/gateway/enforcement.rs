//! Async owner of one local governance session. Only this request future can
//! dispatch; cancellation leaves metadata for explicit session cleanup.
use super::{
    authority::State,
    configuration::EnforcementConfig,
    facts::{self, ToolFacts},
};
use mitigate_audit::{AuditStore, EventDetails, Operation, ResultClass};
use mitigate_fingerprint::Fingerprint;
use mitigate_gateway::{CallerIdentity, Fault};
use mitigate_mcp::{CallFailure, Snapshot, StdioServer, classification::ClassificationOverrides};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub(super) struct Enforcement {
    state: Arc<Mutex<State>>,
    pub audit: Arc<Mutex<AuditStore>>,
    snapshot: Snapshot,
    overrides: ClassificationOverrides,
    session: Fingerprint,
    server: Option<Fingerprint>,
    tools: BTreeMap<String, ToolFacts>,
    approval_timeout: Duration,
}
struct CancellationGuard(Arc<AtomicBool>);
impl Drop for CancellationGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
impl Enforcement {
    pub fn open(path: &Path) -> Result<Self, Fault> {
        let config = EnforcementConfig::from_file(path)?;
        let (snapshot, overrides) = config.definitions()?;
        let state = State::open(&config)?;
        Ok(Self {
            audit: Arc::clone(&state.audit),
            state: Arc::new(Mutex::new(state)),
            snapshot,
            overrides,
            session: mitigate_policy::approvals::fresh_reference()
                .map_err(|_| Fault::GovernanceUnavailable)?,
            server: None,
            tools: BTreeMap::new(),
            approval_timeout: Duration::from_millis(config.approval_timeout_ms),
        })
    }
    pub fn bind(&mut self, server: &StdioServer) -> Result<(), Fault> {
        let (reference, tools) = facts::bind(server, &self.snapshot, &self.overrides)?;
        self.server = Some(reference);
        self.tools = tools;
        Ok(())
    }
    pub fn request_timeout(&self) -> Duration {
        self.approval_timeout + Duration::from_secs(30)
    }
    async fn work<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut State) -> Result<T, Fault> + Send + 'static,
    ) -> Result<T, Fault> {
        let state = Arc::clone(&self.state);
        tokio::task::spawn_blocking(move || {
            let mut state = state.lock().map_err(|_| Fault::GovernanceUnavailable)?;
            operation(&mut state)
        })
        .await
        .map_err(|_| Fault::GovernanceUnavailable)?
    }
    pub async fn close(&self) -> Result<(), Fault> {
        // This runs after the listener drops any request. Its worker queues behind
        // the same mutex as a cancelled commit; no approval can be revived later.
        self.work(|state| state.finish(ResultClass::Uncertain, Some(Fault::Denied)))
            .await
    }
    pub async fn call(
        &self,
        caller: &CallerIdentity,
        upstream: &mut StdioServer,
        name: String,
        arguments: Value,
        mut progress: Option<mitigate_gateway::ProgressSink>,
    ) -> Result<Value, Fault> {
        let server = self.server.clone().ok_or(Fault::GovernanceUnavailable)?;
        let detail = EventDetails::new(caller, server, Operation::ToolCall);
        let facts = self.tools.get(&name).cloned();
        let session = self.session.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let guard = CancellationGuard(Arc::clone(&cancelled));
        let outcome = async {
            self.work(move |state| state.begin(detail, facts, session, cancelled))
                .await?;
            // Reject invalid contracts/arguments before requesting human work.
            // The adapter repeats these checks at dispatch after any long wait.
            let tool = upstream
                .inventory()
                .tools
                .iter()
                .find(|t| t.name == name)
                .ok_or(Fault::InvalidParams)?;
            let input = mitigate_mcp::schema::ToolSchema::compile(&tool.input_schema)
                .await
                .map_err(|_| Fault::InvalidParams)?;
            if let Some(output) = &tool.output_schema {
                mitigate_mcp::schema::ToolSchema::compile(output)
                    .await
                    .map_err(|_| Fault::InvalidParams)?;
            }
            input
                .validate(&arguments)
                .await
                .map_err(|_| Fault::InvalidParams)?;
            if serde_json::to_vec(&arguments)
                .map_err(|_| Fault::InvalidParams)?
                .len()
                > 60_000
            {
                return Err(Fault::InvalidParams);
            }
            let wait = self.work(State::authorize_request).await?;
            if wait {
                let until = tokio::time::Instant::now() + self.approval_timeout;
                loop {
                    if tokio::time::Instant::now() >= until {
                        return Err(Fault::Denied);
                    }
                    if self.work(State::approved).await? {
                        break;
                    }
                    tokio::time::sleep_until(
                        (tokio::time::Instant::now() + Duration::from_millis(200)).min(until),
                    )
                    .await;
                }
            }
            let gate_entered = std::cell::Cell::new(false);
            let progress_requested = progress.is_some();
            let mut report = |p: mitigate_mcp::Progress| {
                if let Some(sink) = &mut progress {
                    sink.report(p.completed, p.total);
                }
            };
            let observer: Option<&mut dyn FnMut(mitigate_mcp::Progress)> = if progress_requested {
                Some(&mut report)
            } else {
                None
            };
            upstream
                .call_with_gate(&name, arguments, observer, || async {
                    gate_entered.set(true);
                    self.work(State::dispatch).await
                })
                .await
                .map_err(|error| match error {
                    CallFailure::Rejected(fault) => fault,
                    CallFailure::Upstream(
                        mitigate_mcp::Error::Changed | mitigate_mcp::Error::LaunchChanged,
                    ) => Fault::Changed,
                    CallFailure::Upstream(
                        mitigate_mcp::Error::SchemaMismatch
                        | mitigate_mcp::Error::Schema
                        | mitigate_mcp::Error::SchemaLimit,
                    ) if !gate_entered.get() => Fault::InvalidParams,
                    CallFailure::Upstream(_) => Fault::Upstream,
                })
        }
        .await;
        let result = match &outcome {
            Ok(value) if value.get("isError").and_then(Value::as_bool) == Some(true) => {
                ResultClass::Error
            }
            Ok(_) => ResultClass::Success,
            Err(_) => ResultClass::Uncertain,
        };
        let fault = outcome.as_ref().err().copied();
        self.work(move |state| state.finish(result, fault)).await?;
        drop(guard);
        outcome
    }
}
