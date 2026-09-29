use super::*;
use mitigate_audit::{Operation, Retention};
use mitigate_gateway::CallerIdentity;
use mitigate_mcp::classification::CapabilityClass;
use mitigate_policy::{
    Authority, SignedBundle,
    controls::{Change, Rate, Target},
};
use serde_json::{Value, json};
use std::{fs, sync::atomic::AtomicUsize};

static NEXT: AtomicUsize = AtomicUsize::new(0);
fn reference(ch: char) -> Fingerprint {
    serde_json::from_value(json!(ch.to_string().repeat(64))).unwrap()
}
struct Fixture {
    root: PathBuf,
    config: EnforcementConfig,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    fn new(decision: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mitigate-enforcement-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let config = EnforcementConfig::from_bytes(&serde_json::to_vec(&json!({
            "schema_version":1,"policy_db":root.join("policy.sqlite"),"policy_authority":root.join("trust.json"),
            "grants":root.join("grants.json"),"approvals_db":root.join("approvals.sqlite"),
            "controls_db":root.join("controls.sqlite"),"audit_db":root.join("audit.sqlite"),
            "tool_snapshot":root.join("snapshot.json"),"classification_overrides":null,
            "environment":null,"approval_timeout_ms":5000
        })).unwrap()).unwrap();
        let authority = Authority {
            schema_version: 1,
            policy_ref: reference('a'),
            public_key: mitigate_policy::public_key(&[7; 32]),
        };
        fs::write(
            &config.policy_authority,
            serde_json::to_vec(&authority).unwrap(),
        )
        .unwrap();
        drop(PolicyStore::create(&config.policy_db, authority).unwrap());
        drop(ApprovalStore::create(&config.approvals_db).unwrap());
        drop(ControlStore::create(&config.controls_db).unwrap());
        drop(AuditStore::create(&config.audit_db, Retention::default()).unwrap());
        let fixture = Self { root, config };
        fixture.policy(1, decision);
        fixture.grants("allow");
        fixture
    }
    fn grants(&self, effect: &str) {
        fs::write(&self.config.grants, serde_json::to_vec(&json!({"schema_version":1,"grants":[{
            "grant_ref":"f".repeat(64),"effect":effect,"scope":{"client":null,"principal":null,"agent":null,
            "server":null,"tool":null,"capabilities":null,"environment":null,"not_before_ms":null,"expires_at_ms":null}
        }]})).unwrap()).unwrap();
    }
    fn policy(&self, version: u64, decision: &str) {
        let source = if decision == "deny" {
            "package mitigate.mcp\ndefault decision := \"deny\"".to_owned()
        } else {
            format!(
                "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"{decision}\" if {{ input.grant == \"explicit\" }}"
            )
        };
        let bundle = SignedBundle::sign(reference('a'), version, source, &[7; 32]).unwrap();
        PolicyStore::open(&self.config.policy_db, self.config.authority().unwrap())
            .unwrap()
            .activate(&bundle)
            .unwrap();
    }
    fn begin(&self, state: &mut State, known: bool) -> Arc<AtomicBool> {
        let caller = if known {
            CallerIdentity::from_profile(
                br#"{"schema_version":1,"client_ref":"authority-client-canary"}"#,
            )
            .unwrap()
        } else {
            CallerIdentity::default()
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        state
            .begin(
                EventDetails::new(&caller, reference('b'), Operation::ToolCall),
                Some(ToolFacts {
                    tool: reference('c'),
                    schema: reference('d'),
                    definition: reference('e'),
                    capabilities: vec![CapabilityClass::ReadData],
                }),
                reference('1'),
                Arc::clone(&cancelled),
            )
            .unwrap();
        cancelled
    }
    fn approval(&self) -> approvals::Record {
        ApprovalStore::open(&self.config.approvals_db)
            .unwrap()
            .list(SystemClock)
            .unwrap()
            .pop()
            .unwrap()
    }
    fn decide(&self, choice: approvals::Choice, operator: char) {
        let approval_ref = self.approval().approval_ref;
        ApprovalStore::open(&self.config.approvals_db)
            .unwrap()
            .decide(&approval_ref, choice, reference(operator), SystemClock)
            .unwrap();
    }
    fn records(&self) -> Vec<Value> {
        AuditStore::open(&self.config.audit_db)
            .unwrap()
            .page(0, 100)
            .unwrap()
            .records
            .into_iter()
            .map(|r| serde_json::to_value(r.event).unwrap())
            .collect()
    }
}

#[test]
fn a_clock_failure_while_awaiting_approval_preserves_blocked_local_authority() {
    let fixture = Fixture::new("require_approval");
    let mut state = State::open(&fixture.config).unwrap();
    fixture.begin(&mut state, true);
    assert_eq!(state.authorize_request(), Ok(true));
    ApprovalStore::open(&fixture.config.approvals_db)
        .unwrap()
        .list(now().unwrap() + 60_000)
        .unwrap();
    assert_eq!(state.approved(), Err(Fault::GovernanceUnavailable));
    assert_eq!(
        state.finish(ResultClass::NotInvoked, Some(Fault::GovernanceUnavailable)),
        Err(Fault::GovernanceUnavailable)
    );
    assert!(!state.active.as_ref().unwrap().dispatched);
    let records = fixture.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["call"]["phase"], "approval_pending");
}

#[test]
fn allowance_has_durable_correlated_dispatch_and_observed_completion_without_content() {
    let fixture = Fixture::new("allow");
    let mut state = State::open(&fixture.config).unwrap();
    fixture.begin(&mut state, true);
    assert_eq!(state.authorize_request(), Ok(false));
    state.dispatch().unwrap();
    let dispatch = fixture.records();
    assert_eq!(dispatch.len(), 1);
    assert_eq!(dispatch[0]["call"]["phase"], "dispatch");
    state.finish(ResultClass::Success, None).unwrap();
    let records = fixture.records();
    assert_eq!(
        records[1]["call"]["call_ref"],
        records[0]["call"]["call_ref"]
    );
    assert_eq!(records[1]["detail"]["result_class"], "success");
    assert_eq!(records[0]["detail"]["decision"], "allow_and_log");
    assert!(!serde_json::to_string(&records).unwrap().contains("canary"));
    assert!(state.active.is_none());
}

#[test]
fn optional_capture_requires_a_committed_audit_and_never_blocks_local_authority() {
    let fixture = Fixture::new("allow");
    let mut state = State::open(&fixture.config).unwrap();
    let (producer, receiver) =
        crate::gateway::sync::tests::producer(&fixture.root.join("queue.sqlite"));
    state.sync = Some(producer);
    fixture.begin(&mut state, true);
    assert_eq!(state.authorize_request(), Ok(false));
    assert!(receiver.try_recv().is_err());
    state.dispatch().unwrap();
    assert!(receiver.try_recv().is_ok());
    assert_eq!(fixture.records().len(), 1);
    // A lost optional worker cannot turn a successful local call into an error.
    drop(receiver);
    state.finish(ResultClass::Success, None).unwrap();
    assert_eq!(fixture.records().len(), 2);

    let (producer, receiver) =
        crate::gateway::sync::tests::producer(&fixture.root.join("other-queue.sqlite"));
    state.sync = Some(producer);
    fixture.begin(&mut state, true);
    state.authorize_request().unwrap();
    let audit = state.audit.clone();
    let poisoned = std::thread::spawn(move || {
        let _held = audit.lock().unwrap();
        panic!("synthetic audit failure");
    })
    .join();
    assert!(poisoned.is_err());
    assert_eq!(state.dispatch(), Err(Fault::AuditUnavailable));
    assert!(receiver.try_recv().is_err());
    assert_eq!(fixture.records().len(), 2);
}

#[test]
fn unknown_client_and_explicit_grant_denial_cannot_be_overridden_by_allow_policy() {
    for known in [false, true] {
        let fixture = Fixture::new("allow");
        if known {
            fixture.grants("deny");
        }
        let mut state = State::open(&fixture.config).unwrap();
        fixture.begin(&mut state, known);
        assert_eq!(state.authorize_request(), Err(Fault::Denied));
        state
            .finish(ResultClass::Uncertain, Some(Fault::Denied))
            .unwrap();
        let records = fixture.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["call"]["phase"], "decision");
        assert_eq!(records[0]["detail"]["result_class"], "not_invoked");
        if !known {
            assert!(records[0]["detail"]["client_ref"].is_null());
        }
    }
}

#[test]
fn approvals_are_consumed_once_and_revocation_is_attributed_before_dispatch() {
    for revoke in [false, true] {
        let fixture = Fixture::new("require_approval");
        let mut state = State::open(&fixture.config).unwrap();
        fixture.begin(&mut state, true);
        assert_eq!(state.authorize_request(), Ok(true));
        assert_eq!(state.approved(), Ok(false));
        fixture.decide(approvals::Choice::Approve, '2');
        assert_eq!(state.approved(), Ok(true));
        if revoke {
            fixture.decide(approvals::Choice::Deny, '3');
        }
        assert_eq!(
            state.dispatch(),
            if revoke { Err(Fault::Denied) } else { Ok(()) }
        );
        state
            .finish(ResultClass::Success, revoke.then_some(Fault::Denied))
            .unwrap();
        let records = fixture.records();
        let last = records.last().unwrap();
        assert_eq!(
            last["call"]["approval_actor"]["choice"],
            if revoke { "deny" } else { "approve" }
        );
        assert_eq!(
            last["call"]["approval_actor"]["operator_ref"],
            if revoke {
                "3".repeat(64)
            } else {
                "2".repeat(64)
            }
        );
        assert_eq!(
            fixture.approval().state,
            if revoke {
                ApprovalState::Denied
            } else {
                ApprovalState::Consumed
            }
        );
        assert_eq!(records.len(), if revoke { 2 } else { 3 });
    }
}

#[test]
fn policy_replacement_invalidates_waiting_approval_and_missing_policy_keeps_cached_authority() {
    let fixture = Fixture::new("require_approval");
    let mut state = State::open(&fixture.config).unwrap();
    fixture.begin(&mut state, true);
    state.authorize_request().unwrap();
    fixture.decide(approvals::Choice::Approve, '2');
    fixture.policy(2, "allow");
    assert_eq!(state.dispatch(), Err(Fault::Denied));
    assert_eq!(
        fixture.approval().cancellation,
        Some(Cancellation::ContextChanged)
    );
    state
        .finish(ResultClass::Uncertain, Some(Fault::Denied))
        .unwrap();

    // Replace the reader with a valid empty store to simulate an unavailable
    // refreshed bundle without platform access or altering the loaded policy.
    let other = fixture.root.join("empty-policy.sqlite");
    state.policy_store = PolicyStore::create(&other, fixture.config.authority().unwrap()).unwrap();
    fixture.begin(&mut state, true);
    assert_eq!(state.authorize_request(), Ok(false));
    state.dispatch().unwrap();
    state.finish(ResultClass::Success, None).unwrap();
    assert_eq!(state.policy.receipt().version, 2);
}

#[test]
fn live_control_and_grant_changes_are_rechecked_and_quota_is_not_refunded_after_dispatch() {
    let fixture = Fixture::new("allow");
    let mut state = State::open(&fixture.config).unwrap();
    fixture.begin(&mut state, true);
    assert_eq!(state.authorize_request(), Ok(false));
    let mut control = ControlStore::open(&fixture.config.controls_db).unwrap();
    control
        .apply(Change::Stop {}, reference('2'), SystemClock)
        .unwrap();
    assert_eq!(state.dispatch(), Err(Fault::Stopped));
    state
        .finish(ResultClass::Uncertain, Some(Fault::Stopped))
        .unwrap();
    control
        .apply(Change::Resume {}, reference('2'), SystemClock)
        .unwrap();
    fixture.begin(&mut state, true);
    assert_eq!(state.authorize_request(), Ok(false));
    fixture.grants("deny");
    assert_eq!(state.dispatch(), Err(Fault::Denied));
    state
        .finish(ResultClass::Uncertain, Some(Fault::Denied))
        .unwrap();
    fixture.grants("allow");
    control
        .apply(
            Change::SetLimit {
                target: Target::Global {},
                rate: Rate {
                    capacity: 1,
                    refill_tokens: 1,
                    period_ms: 86_400_000,
                },
            },
            reference('2'),
            SystemClock,
        )
        .unwrap();
    fixture.begin(&mut state, true);
    state.authorize_request().unwrap();
    state.dispatch().unwrap();
    state
        .finish(ResultClass::Uncertain, Some(Fault::Upstream))
        .unwrap();
    fixture.begin(&mut state, true);
    assert_eq!(state.authorize_request(), Err(Fault::RateLimited));
    state
        .finish(ResultClass::Uncertain, Some(Fault::RateLimited))
        .unwrap();
    assert_eq!(
        fixture.records().last().unwrap()["detail"]["decision"],
        "rate_limit"
    );
}

#[test]
fn cancellation_finishes_pending_metadata_and_grant_parse_errors_never_allow() {
    let fixture = Fixture::new("require_approval");
    let mut state = State::open(&fixture.config).unwrap();
    let cancelled = fixture.begin(&mut state, true);
    state.authorize_request().unwrap();
    cancelled.store(true, Ordering::Release);
    fixture.decide(approvals::Choice::Approve, '2');
    assert_eq!(state.dispatch(), Err(Fault::Denied));
    state
        .finish(ResultClass::Uncertain, Some(Fault::Denied))
        .unwrap();
    assert_eq!(fixture.approval().state, ApprovalState::Cancelled);
    fixture.begin(&mut state, true);
    fs::write(&fixture.config.grants, br#"{"canary":"no fallback"}"#).unwrap();
    assert_eq!(state.authorize_request(), Err(Fault::GovernanceUnavailable));
    state
        .finish(ResultClass::Uncertain, Some(Fault::GovernanceUnavailable))
        .unwrap();
}
