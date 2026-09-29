//! Local authority and call lifecycle. Workers own metadata/storage, never a
//! transport or tool arguments, so a detached commit cannot execute a call.
#[cfg(test)]
mod tests;
use super::{configuration::EnforcementConfig, facts::ToolFacts};
use mitigate_audit::{
    ApprovalActor, ApprovalChoice, AuditStore, CallContext, CallPhase, Decision, EventDetails,
    OperatorSource, ResultClass,
};
use mitigate_fingerprint::Fingerprint;
use mitigate_gateway::Fault;
use mitigate_policy::{
    ActivePolicy, Decision as PolicyDecision, PolicyInput, PolicyStore, SystemClock,
    approvals::{self, ApprovalStore, Binding, Cancellation, Consumption, State as ApprovalState},
    controls::{Admission, Context, ControlStore},
    grants::{GrantContext, GrantSet},
    read_document,
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub(super) struct State {
    policy_store: PolicyStore,
    policy: ActivePolicy,
    policy_warning: bool,
    grants: PathBuf,
    approvals: ApprovalStore,
    controls: ControlStore,
    pub audit: Arc<Mutex<AuditStore>>,
    pub sync: Option<super::sync::Producer>,
    environment: Option<String>,
    approval_timeout_ms: u64,
    active: Option<Invocation>,
}
struct Invocation {
    detail: EventDetails,
    context: CallContext,
    started: Instant,
    cancelled: Arc<AtomicBool>,
    binding: Option<Binding>,
    dispatched: bool,
    sync_refs: Option<super::sync::InvocationRefs>,
}
impl Invocation {
    fn live(&self) -> Result<(), Fault> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(Fault::Denied)
        } else {
            Ok(())
        }
    }
    fn controls(&self) -> Result<Context, Fault> {
        Ok(Context {
            schema_version: 1,
            client: self.detail.client_ref.clone(),
            principal: self.detail.principal_ref.clone(),
            agent: self.detail.agent_ref.clone(),
            server: self.detail.server_ref.clone(),
            tool: self.detail.tool_ref.clone().ok_or(Fault::Denied)?,
        })
    }
    fn bind(&self, environment: Option<String>) -> Result<Binding, Fault> {
        let required = |v: &Option<Fingerprint>| v.clone().ok_or(Fault::Denied);
        Ok(Binding {
            schema_version: 1,
            client: required(&self.detail.client_ref)?,
            principal: self.detail.principal_ref.clone(),
            agent: self.detail.agent_ref.clone(),
            session_ref: self.context.session_ref.clone(),
            call_ref: self.context.call_ref.clone(),
            server: self.detail.server_ref.clone(),
            tool: required(&self.detail.tool_ref)?,
            schema_fingerprint: required(&self.detail.schema_fingerprint)?,
            definition_fingerprint: required(&self.context.definition_fingerprint)?,
            policy_ref: required(&self.detail.policy_ref)?,
            policy_version: self.detail.policy_version.ok_or(Fault::Denied)?,
            policy_bundle_hash: required(&self.context.policy_bundle_hash)?,
            capabilities: self.detail.capability_classes.clone(),
            environment,
        })
    }
}

pub(super) fn now() -> Result<u64, Fault> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Fault::GovernanceUnavailable)?
        .as_millis();
    if value > 9_007_199_254_740_991 {
        return Err(Fault::GovernanceUnavailable);
    }
    Ok(value as u64)
}
fn approval_failure(error: approvals::Error) -> Fault {
    // The closed library code never contains references, paths or SQL diagnostics.
    eprintln!("Mitigate: governance approval failure: {}", error.code());
    Fault::GovernanceUnavailable
}
fn control_failure(error: mitigate_policy::controls::Error) -> Fault {
    eprintln!("Mitigate: governance control failure: {}", error.code());
    Fault::GovernanceUnavailable
}
impl State {
    pub fn open(config: &EnforcementConfig) -> Result<Self, Fault> {
        let policy_store = PolicyStore::open(&config.policy_db, config.authority()?)
            .map_err(|_| Fault::GovernanceUnavailable)?;
        let policy = policy_store
            .load()
            .map_err(|_| Fault::GovernanceUnavailable)?;
        GrantSet::from_bytes(
            &read_document(&config.grants, 32_768).map_err(|_| Fault::GovernanceUnavailable)?,
        )
        .map_err(|_| Fault::GovernanceUnavailable)?;
        Ok(Self {
            policy_store,
            policy,
            policy_warning: false,
            grants: config.grants.clone(),
            approvals: ApprovalStore::open(&config.approvals_db)
                .map_err(|_| Fault::GovernanceUnavailable)?,
            controls: ControlStore::open(&config.controls_db)
                .map_err(|_| Fault::GovernanceUnavailable)?,
            audit: Arc::new(Mutex::new(
                AuditStore::open(&config.audit_db).map_err(|_| Fault::AuditUnavailable)?,
            )),
            environment: config.environment.clone(),
            approval_timeout_ms: config.approval_timeout_ms,
            active: None,
            sync: None,
        })
    }

    fn record(&self, call: &mut Invocation) -> Result<(), Fault> {
        call.detail.duration_ms = call.started.elapsed().as_millis().min(86_400_000) as u64;
        let consent = self.sync.as_ref().and_then(|producer| producer.permit());
        let receipt = self
            .audit
            .lock()
            .map_err(|_| Fault::AuditUnavailable)?
            .append_call(call.detail.clone(), call.context.clone())
            .map_err(|_| Fault::AuditUnavailable)?;
        if let (Some(producer), Some(consent)) = (&self.sync, consent) {
            producer.publish(
                consent,
                &call.detail,
                call.context.phase,
                receipt.event.time_ms,
                &mut call.sync_refs,
            );
        }
        Ok(())
    }
    fn with_call<T>(
        &mut self,
        work: impl FnOnce(&mut Self, &mut Invocation) -> Result<T, Fault>,
    ) -> Result<T, Fault> {
        let mut call = self.active.take().ok_or(Fault::GovernanceUnavailable)?;
        let result = work(self, &mut call);
        self.active = Some(call);
        result
    }

    // Loading a candidate is independent of the in-memory last-known-good.
    // Never replace it with an older or equal-version/different-message bundle.
    fn refresh_policy(&mut self) {
        let valid = match self.policy_store.load() {
            Ok(candidate) if candidate.receipt() == self.policy.receipt() => true,
            Ok(candidate)
                if candidate.receipt().policy_ref == self.policy.receipt().policy_ref
                    && candidate.receipt().version > self.policy.receipt().version =>
            {
                self.policy = candidate;
                true
            }
            _ => false,
        };
        if !valid && !self.policy_warning {
            eprintln!(
                "Mitigate: policy refresh rejected; the verified cached policy remains active."
            );
        }
        self.policy_warning = !valid;
    }

    fn evaluate(&mut self, call: &mut Invocation) -> Result<PolicyDecision, Fault> {
        call.live()?;
        self.refresh_policy();
        let receipt = self.policy.receipt();
        call.detail.policy_ref = Some(receipt.policy_ref.clone());
        call.detail.policy_version = Some(receipt.version);
        call.context.policy_bundle_hash = Some(
            serde_json::from_value(serde_json::json!(receipt.bundle_hash))
                .map_err(|_| Fault::GovernanceUnavailable)?,
        );
        let context = call.controls()?;
        let grants = GrantSet::from_bytes(
            &read_document(&self.grants, 32_768).map_err(|_| Fault::GovernanceUnavailable)?,
        )
        .map_err(|_| Fault::GovernanceUnavailable)?;
        let resolution = grants
            .evaluate(&GrantContext {
                schema_version: 1,
                client: context.client.clone(),
                principal: context.principal.clone(),
                agent: context.agent.clone(),
                server: context.server.clone(),
                tool: context.tool.clone(),
                capabilities: call.detail.capability_classes.clone(),
                environment: self.environment.clone(),
                time_ms: now()?,
            })
            .map_err(|_| Fault::GovernanceUnavailable)?;
        let policy = self
            .policy
            .evaluate(&PolicyInput {
                schema_version: 1,
                client: context.client,
                principal: context.principal,
                agent: context.agent,
                server: context.server,
                tool: context.tool,
                schema_fingerprint: call
                    .detail
                    .schema_fingerprint
                    .clone()
                    .ok_or(Fault::Denied)?,
                capabilities: call.detail.capability_classes.clone(),
                schema_changed: false,
                grant: resolution.state(),
                offline: true,
            })
            .map_err(|_| Fault::GovernanceUnavailable)?;
        let decision = resolution.constrain(policy);
        if let Some(binding) = &call.binding
            && binding != &call.bind(self.environment.clone())?
        {
            if let Some(reference) = &call.detail.approval_ref {
                self.approvals
                    .cancel(reference, Cancellation::ContextChanged, SystemClock)
                    .map_err(approval_failure)?;
            }
            call.detail.decision = Decision::Deny;
            return Err(Fault::Denied);
        }
        if decision == PolicyDecision::Deny {
            call.detail.decision = Decision::Deny;
            return Err(Fault::Denied);
        }
        call.live()?;
        Ok(decision)
    }

    fn admission(call: &mut Invocation, result: Admission) -> Result<(), Fault> {
        match result {
            Admission::Allowed { .. } => Ok(()),
            Admission::Disabled { .. } => {
                call.detail.decision = Decision::DisableTool;
                Err(Fault::Stopped)
            }
            Admission::RateLimited { .. } => {
                call.detail.decision = Decision::RateLimit;
                Err(Fault::RateLimited)
            }
        }
    }
    pub fn begin(
        &mut self,
        mut detail: EventDetails,
        facts: Option<ToolFacts>,
        session: Fingerprint,
        cancelled: Arc<AtomicBool>,
    ) -> Result<(), Fault> {
        if self.active.is_some() {
            return Err(Fault::AuditUnavailable);
        }
        let reference = approvals::fresh_reference().map_err(|_| Fault::GovernanceUnavailable)?;
        let definition = facts.as_ref().map(|f| f.definition.clone());
        if let Some(facts) = facts {
            detail.tool_ref = Some(facts.tool);
            detail.schema_fingerprint = Some(facts.schema);
            detail.capability_classes = facts.capabilities;
        }
        self.active = Some(Invocation {
            detail,
            context: CallContext {
                session_ref: session,
                call_ref: reference,
                phase: CallPhase::Decision,
                definition_fingerprint: definition,
                policy_bundle_hash: None,
                approval_actor: None,
            },
            started: Instant::now(),
            cancelled,
            binding: None,
            dispatched: false,
            sync_refs: None,
        });
        Ok(())
    }

    pub fn authorize_request(&mut self) -> Result<bool, Fault> {
        self.with_call(|state, call| {
            if call.detail.tool_ref.is_none() {
                return Err(Fault::InvalidParams);
            }
            let decision = state.evaluate(call)?;
            Self::admission(
                call,
                state
                    .controls
                    .preview(&call.controls()?, SystemClock)
                    .map_err(control_failure)?,
            )?;
            if decision != PolicyDecision::RequireApproval {
                return Ok(false);
            }
            let binding = call.bind(state.environment.clone())?;
            let record = state
                .approvals
                .request(binding.clone(), SystemClock, state.approval_timeout_ms)
                .map_err(approval_failure)?;
            call.detail.approval_ref = Some(record.approval_ref);
            call.binding = Some(binding);
            call.context.phase = CallPhase::ApprovalPending;
            call.detail.decision = Decision::RequireApproval;
            call.detail.result_class = ResultClass::Pending;
            state.record(call)?;
            Ok(true)
        })
    }

    pub fn approved(&mut self) -> Result<bool, Fault> {
        self.with_call(|state, call| {
            state.evaluate(call)?;
            Self::admission(
                call,
                state
                    .controls
                    .preview(&call.controls()?, SystemClock)
                    .map_err(control_failure)?,
            )?;
            let reference = call
                .detail
                .approval_ref
                .as_ref()
                .ok_or(Fault::GovernanceUnavailable)?;
            let record = state
                .approvals
                .get(reference, SystemClock)
                .map_err(approval_failure)?;
            if let Some(decision) = record.decisions.last() {
                call.context.approval_actor = Some(ApprovalActor {
                    operator_ref: decision.operator_ref.clone(),
                    source: OperatorSource::DeclaredLocal,
                    choice: match decision.choice {
                        approvals::Choice::Approve => ApprovalChoice::Approve,
                        approvals::Choice::Deny => ApprovalChoice::Deny,
                    },
                });
            }
            match record.state {
                ApprovalState::Requested => Ok(false),
                ApprovalState::Approved => Ok(true),
                _ => {
                    call.detail.decision = Decision::Deny;
                    Err(Fault::Denied)
                }
            }
        })
    }

    pub fn dispatch(&mut self) -> Result<(), Fault> {
        self.with_call(|state, call| {
            let decision = state.evaluate(call)?;
            if decision == PolicyDecision::RequireApproval && call.binding.is_none() {
                call.detail.decision = Decision::Deny;
                return Err(Fault::Denied);
            }
            call.live()?;
            Self::admission(
                call,
                state
                    .controls
                    .admit(&call.controls()?, SystemClock)
                    .map_err(control_failure)?,
            )?;
            if let Some(binding) = &call.binding {
                let reference = call
                    .detail
                    .approval_ref
                    .as_ref()
                    .ok_or(Fault::GovernanceUnavailable)?;
                match state
                    .approvals
                    .consume(reference, binding, SystemClock)
                    .map_err(approval_failure)?
                {
                    Consumption::Ready(permit) => {
                        call.context.approval_actor = Some(ApprovalActor {
                            operator_ref: permit.operator().clone(),
                            source: OperatorSource::DeclaredLocal,
                            choice: ApprovalChoice::Approve,
                        });
                    }
                    _ => {
                        let record = state
                            .approvals
                            .get(reference, SystemClock)
                            .map_err(approval_failure)?;
                        if let Some(decision) = record.decisions.last() {
                            call.context.approval_actor = Some(ApprovalActor {
                                operator_ref: decision.operator_ref.clone(),
                                source: OperatorSource::DeclaredLocal,
                                choice: match decision.choice {
                                    approvals::Choice::Approve => ApprovalChoice::Approve,
                                    approvals::Choice::Deny => ApprovalChoice::Deny,
                                },
                            });
                        }
                        call.detail.decision = Decision::Deny;
                        return Err(Fault::Denied);
                    }
                }
            }
            call.live()?;
            call.context.phase = CallPhase::Dispatch;
            call.detail.decision = Decision::AllowAndLog;
            call.detail.result_class = ResultClass::Pending;
            call.dispatched = true;
            // An append error may have uncertain commit durability. Never emit
            // a known pre-dispatch phase after this record might have committed.
            state.record(call)?;
            call.live()
        })
    }

    pub fn finish(&mut self, result: ResultClass, fault: Option<Fault>) -> Result<(), Fault> {
        let Some(mut call) = self.active.take() else {
            return Ok(());
        };
        let outcome = (|| {
            if !call.dispatched {
                if let Some(reference) = &call.detail.approval_ref {
                    self.approvals
                        .cancel(reference, Cancellation::SessionEnded, SystemClock)
                        .map_err(approval_failure)?;
                }
                call.context.phase = CallPhase::Decision;
                call.detail.result_class = ResultClass::NotInvoked;
                call.detail.decision = match fault {
                    Some(Fault::Denied) => Decision::Deny,
                    Some(Fault::Stopped) => Decision::DisableTool,
                    Some(Fault::RateLimited) => Decision::RateLimit,
                    _ => Decision::Error,
                };
            } else {
                call.context.phase = CallPhase::Completion;
                call.detail.result_class = result;
            }
            self.record(&mut call)
        })();
        if outcome.is_err() {
            self.active = Some(call);
        }
        outcome
    }
}
