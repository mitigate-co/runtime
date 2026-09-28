//! Synthetic local metadata only; this harness does not grant or invoke tools.
use mitigate_audit::{
    AuditStore, CallContext, Decision, EventDetails, Operation, ResultClass, Retention,
};
use mitigate_gateway::CallerIdentity;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        for name in ["audit.sqlite", "audit.sqlite-journal"] {
            let _ = fs::remove_file(self.0.join(name));
        }
        let _ = fs::remove_dir(&self.0);
    }
}
fn run(cli: &Path, db: &Path, action: &str) -> std::process::Output {
    Command::new(cli)
        .args(["mcp", "audit", action, "--db"])
        .arg(db)
        .arg("--json")
        .output()
        .unwrap()
}
fn reference(ch: char) -> Value {
    json!(ch.to_string().repeat(64))
}

pub(super) fn verify(cli: &Path, legacy: Option<&Path>) {
    let root = std::env::temp_dir().join(format!("mitigate-audit-contract-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let fixture = Fixture(root);
    let db = fixture.0.join("audit.sqlite");
    let mut store = AuditStore::create(&db, Retention::default()).unwrap();
    let mut old = EventDetails::new(
        &CallerIdentity::default(),
        serde_json::from_value(reference('a')).unwrap(),
        Operation::Inventory,
    );
    old.decision = Decision::InventoryOnly;
    old.result_class = ResultClass::Success;
    let original = store.append(old).unwrap();
    if let Some(cli) = legacy {
        assert!(run(cli, &db, "verify").status.success());
    }
    let caller =
        CallerIdentity::from_profile(br#"{"schema_version":1,"client_ref":"audit-client-canary"}"#)
            .unwrap();
    let mut detail = EventDetails::new(
        &caller,
        serde_json::from_value(reference('a')).unwrap(),
        Operation::ToolCall,
    );
    detail.tool_ref = serde_json::from_value(reference('b')).unwrap();
    detail.schema_fingerprint = serde_json::from_value(reference('c')).unwrap();
    detail.policy_ref = serde_json::from_value(reference('d')).unwrap();
    detail.policy_version = Some(1);
    detail.approval_ref = serde_json::from_value(reference('e')).unwrap();
    detail.capability_classes = vec![mitigate_mcp::classification::CapabilityClass::ReadData];
    detail.decision = Decision::RequireApproval;
    detail.result_class = ResultClass::Pending;
    let mut context = json!({"session_ref":reference('1'),"call_ref":reference('2'),"phase":"approval_pending","definition_fingerprint":reference('3'),"policy_bundle_hash":reference('4'),"approval_actor":null});
    store
        .append_call(
            detail.clone(),
            serde_json::from_value::<CallContext>(context.clone()).unwrap(),
        )
        .unwrap();
    context["phase"] = json!("dispatch");
    context["approval_actor"] =
        json!({"operator_ref":reference('5'),"source":"declared_local","choice":"approve"});
    detail.decision = Decision::AllowAndLog;
    store
        .append_call(
            detail.clone(),
            serde_json::from_value(context.clone()).unwrap(),
        )
        .unwrap();
    context["phase"] = json!("completion");
    detail.result_class = ResultClass::Uncertain;
    store
        .append_call(detail, serde_json::from_value(context).unwrap())
        .unwrap();
    drop(store);
    let verified = run(cli, &db, "verify");
    assert!(verified.status.success());
    let listed = run(cli, &db, "list");
    assert!(listed.status.success());
    let value: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(value["records"][0]["hash"], original.hash);
    assert!(value["records"][0]["event"].get("call").is_none());
    assert_eq!(
        value["records"][3]["event"]["call"]["approval_actor"]["source"],
        "declared_local"
    );
    assert_eq!(
        value["records"][3]["event"]["detail"]["result_class"],
        "uncertain"
    );
    let human = Command::new(cli)
        .args(["mcp", "audit", "list", "--db"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(human.status.success());
    assert!(
        String::from_utf8(human.stdout)
            .unwrap()
            .contains("approval_pending")
    );
    for bytes in [&listed.stdout, &listed.stderr, &fs::read(&db).unwrap()] {
        assert!(
            !bytes
                .windows(b"audit-client-canary".len())
                .any(|b| b == b"audit-client-canary")
        );
    }
    if let Some(cli) = legacy {
        let rejected = run(cli, &db, "verify");
        assert!(!rejected.status.success());
        assert!(rejected.stdout.is_empty());
        let error: Value = serde_json::from_slice(&rejected.stderr).unwrap();
        assert_eq!(error["error"], "audit_integrity_failed");
    }
    assert_eq!(AuditStore::open(&db).unwrap().verify().unwrap().records, 4);
    println!(
        "Call audit verified: mixed versions, approval attribution, correlated phases, CLI export and retained chain integrity."
    );
}
