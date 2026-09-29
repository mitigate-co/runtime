//! The only local-call projection into the producer channel. No audit export,
//! JSON blob, tool name, argument/result, operator, environment or evidence field.
use mitigate_audit::{
    Attribution as LocalAttribution, CallPhase, Decision as LocalDecision, EventDetails, Operation,
    ResultClass,
};
use mitigate_egress::{
    Attribution, Capability, CheckedEvent, Decision, DecisionFacts, Outcome, Phase, Rejection,
    SyncRef,
    references::{Kind, LocalKey},
};
use mitigate_fingerprint::Fingerprint;
use mitigate_mcp::classification::CapabilityClass;

pub(in crate::gateway) struct InvocationRefs {
    call: SyncRef,
    approval: Option<(Fingerprint, SyncRef)>,
}
impl InvocationRefs {
    pub fn new() -> Option<Self> {
        Some(Self {
            call: SyncRef::fresh().ok()?,
            approval: None,
        })
    }
    fn approval(&mut self, local: &Option<Fingerprint>) -> Option<Option<SyncRef>> {
        let Some(local) = local else {
            return Some(None);
        };
        if self
            .approval
            .as_ref()
            .is_none_or(|(known, _)| known != local)
        {
            self.approval = Some((local.clone(), SyncRef::fresh().ok()?));
        }
        Some(self.approval.as_ref().map(|(_, wire)| wire.clone()))
    }
}

// No Debug, Serialize, Deserialize or arbitrary string fields. Only the seven
// named stable domains can become local catalog keys; ephemeral IDs never do.
pub(super) struct Capture {
    pub keys: [Option<LocalKey>; 7],
    event: SyncRef,
    occurred_at_ms: u64,
    call: SyncRef,
    approval: Option<SyncRef>,
    attribution: Attribution,
    capabilities: Vec<Capability>,
    policy_version: Option<u64>,
    phase: Phase,
    decision: Decision,
    outcome: Outcome,
    duration_ms: u32,
}
impl Capture {
    pub fn from_call(
        detail: &EventDetails,
        phase: CallPhase,
        time_ms: u64,
        refs: &mut InvocationRefs,
    ) -> Option<Self> {
        if detail.operation != Operation::ToolCall || detail.capability_classes.len() > 11 {
            return None;
        }
        let mut keys = std::array::from_fn(|_| None);
        for (index, (kind, local)) in [
            (Kind::Client, detail.client_ref.as_ref()),
            (Kind::Principal, detail.principal_ref.as_ref()),
            (Kind::Agent, detail.agent_ref.as_ref()),
            (Kind::Server, Some(&detail.server_ref)),
            (Kind::Tool, detail.tool_ref.as_ref()),
            (Kind::Schema, detail.schema_fingerprint.as_ref()),
            (Kind::Policy, detail.policy_ref.as_ref()),
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(local) = local {
                let mut digest = [0; 32];
                for (i, byte) in digest.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&local.as_str()[i * 2..i * 2 + 2], 16).ok()?;
                }
                keys[index] = Some(LocalKey::new(kind, digest));
            }
        }
        let mut capabilities: Vec<_> = detail
            .capability_classes
            .iter()
            .map(|capability| match capability {
                CapabilityClass::ReadData => Capability::ReadData,
                CapabilityClass::WriteData => Capability::WriteData,
                CapabilityClass::DeleteData => Capability::DeleteData,
                CapabilityClass::ExecuteCode => Capability::ExecuteCode,
                CapabilityClass::CredentialAccess => Capability::CredentialAccess,
                CapabilityClass::ExternalCommunication => Capability::ExternalCommunication,
                CapabilityClass::BrowserAction => Capability::BrowserAction,
                CapabilityClass::IdentityAdmin => Capability::IdentityAdmin,
                CapabilityClass::FinancialAction => Capability::FinancialAction,
                CapabilityClass::InfrastructureChange => Capability::InfrastructureChange,
                CapabilityClass::Unknown => Capability::Unknown,
            })
            .collect();
        capabilities.sort_unstable();
        capabilities.dedup();
        Some(Self {
            keys,
            event: SyncRef::fresh().ok()?,
            occurred_at_ms: time_ms,
            call: refs.call.clone(),
            approval: refs.approval(&detail.approval_ref)?,
            attribution: match detail.attribution {
                LocalAttribution::Unknown => Attribution::Unknown,
                LocalAttribution::DeclaredProfile => Attribution::DeclaredProfile,
            },
            capabilities,
            policy_version: detail.policy_version,
            phase: match phase {
                CallPhase::Decision => Phase::Decision,
                CallPhase::ApprovalPending => Phase::ApprovalPending,
                CallPhase::Dispatch => Phase::Dispatch,
                CallPhase::Completion => Phase::Completion,
            },
            decision: match detail.decision {
                LocalDecision::AllowAndLog => Decision::AllowAndLog,
                LocalDecision::Deny => Decision::Deny,
                LocalDecision::RequireApproval => Decision::RequireApproval,
                LocalDecision::RateLimit => Decision::RateLimit,
                LocalDecision::DisableTool => Decision::DisableTool,
                LocalDecision::Error => Decision::Error,
                LocalDecision::InventoryOnly | LocalDecision::Allow => return None,
            },
            outcome: match detail.result_class {
                ResultClass::Pending => Outcome::Pending,
                ResultClass::Success => Outcome::Success,
                ResultClass::Error => Outcome::Error,
                ResultClass::Cancelled => Outcome::Cancelled,
                ResultClass::NotInvoked => Outcome::NotInvoked,
                ResultClass::Uncertain => Outcome::Uncertain,
            },
            duration_ms: detail.duration_ms.try_into().ok()?,
        })
    }
    pub fn bind(
        self,
        runtime_ref: SyncRef,
        mapped: Vec<SyncRef>,
    ) -> Result<CheckedEvent, Rejection> {
        if mapped.len() != self.keys.iter().flatten().count() {
            return Err(Rejection::Facts);
        }
        let mut mapped = mapped.into_iter();
        let [
            client_ref,
            principal_ref,
            agent_ref,
            server_ref,
            tool_ref,
            schema_ref,
            policy_ref,
        ] = self.keys.map(|key| key.and_then(|_| mapped.next()));
        CheckedEvent::decision(
            self.event,
            runtime_ref,
            self.occurred_at_ms,
            DecisionFacts {
                call_ref: self.call,
                client_ref,
                principal_ref,
                agent_ref,
                attribution: self.attribution,
                server_ref: server_ref.ok_or(Rejection::Facts)?,
                tool_ref,
                schema_ref,
                capabilities: self.capabilities,
                policy_ref,
                policy_version: self.policy_version,
                approval_ref: self.approval,
                phase: self.phase,
                decision: self.decision,
                outcome: self.outcome,
                duration_ms: self.duration_ms,
            },
        )
    }
}
