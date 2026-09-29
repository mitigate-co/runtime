//! Actual CLI privacy diagnostics, with isolated synthetic storage only.
use mitigate_egress::{
    SyncRef,
    outbox::{Admission, DeliveryOutcome, Limits, Outbox, Partition},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-privacy-cli-{}",
            SyncRef::fresh().unwrap().as_str()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mitigate"))
        .args(args)
        .env_remove("MITIGATE_TOKEN")
        .env_remove("MITIGATE_ORGANIZATION")
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .output()
        .unwrap()
}
fn report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn schema_inspection_distinguishes_supported_fields_from_observed_delivery() {
    let result = cli(&["egress", "inspect", "--json"]);
    let value = report(&result);
    assert_eq!(value["schema_version"], 3);
    assert_eq!(value["observed_scope"], "pending");
    assert_eq!(value["delivery_status"], "not_checked");
    assert!(value["destination"].is_null() && value["queue"].is_null());
    assert_eq!(value["observed_event_types"], json!([]));
    assert_eq!(value["observed_schema_versions"], json!([]));
    assert_eq!(
        value["supported_events"][0]["fields"],
        json!(mitigate_egress::EVENT_FIELDS)
    );
    assert_eq!(value["supported_events"][0]["max_event_bytes"], 4096);
    assert_eq!(value["supported_events"].as_array().unwrap().len(), 2);
    assert_eq!(value["supported_events"][1]["schema_version"], 2);
    assert_eq!(
        value["supported_events"][1]["fields"],
        json!(mitigate_egress::inventory::EVENT_FIELDS)
    );
    let human = cli(&["egress", "inspect"]);
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("Destination: not checked"));
    assert!(text.contains("No queue selected"));
}

#[test]
fn shipped_privacy_probe_rejects_every_family_and_preserves_neighbor_files() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("preserve"), b"private-neighbor-canary").unwrap();
    let result = cli(&[
        "privacy",
        "self-test",
        "--work-dir",
        fixture.0.to_str().unwrap(),
        "--json",
    ]);
    let value = report(&result);
    assert_eq!(value["passed"], true);
    assert_eq!(value["positive_control"], true);
    assert_eq!(value["queue_isolation"], true);
    assert_eq!(value["persisted_canaries_absent"], true);
    assert_eq!(value["network_requests"], 0);
    let checks = value["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 11);
    assert_eq!(
        checks
            .iter()
            .map(|c| c["attempted"].as_u64().unwrap())
            .sum::<u64>(),
        260
    );
    assert!(checks.iter().all(|c| c["attempted"] == c["rejected"]));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("canary"));
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
    assert_eq!(
        fs::read(fixture.0.join("preserve")).unwrap(),
        b"private-neighbor-canary"
    );
    let human = cli(&[
        "privacy",
        "self-test",
        "--work-dir",
        fixture.0.to_str().unwrap(),
    ]);
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("Privacy self-test: passed"));
}

#[test]
fn queue_inspection_is_content_free_exactly_scoped_and_read_only() {
    let fixture = Fixture::new();
    let path = fixture.0.join("private-path-canary.sqlite");
    let mut event: Value =
        serde_json::from_slice(include_bytes!("../../../examples/egress/decision.json")).unwrap();
    let partition = Partition {
        runtime_ref: SyncRef::fresh().unwrap(),
        enrollment_ref: SyncRef::fresh().unwrap(),
    };
    event["runtime_ref"] = json!(partition.runtime_ref);
    let mut store = Outbox::create(&path, partition.clone(), Limits::default()).unwrap();
    assert_eq!(
        store.admit(&serde_json::to_vec(&event).unwrap()),
        Ok(Admission::Queued)
    );
    assert!(matches!(
        store.admit(br#"{"arguments":"private-arguments-canary"}"#),
        Ok(Admission::Rejected(_))
    ));
    let mut inventory: Value = serde_json::from_slice(include_bytes!(
        "../../../examples/egress/inventory-part.json"
    ))
    .unwrap();
    inventory["runtime_ref"] = json!(partition.runtime_ref);
    inventory["event_id"] = json!(SyncRef::fresh().unwrap());
    assert_eq!(
        store.admit(&serde_json::to_vec(&inventory).unwrap()),
        Ok(Admission::Queued)
    );
    drop(store);
    let before = fs::read(&path).unwrap();
    let args = [
        "egress",
        "inspect",
        "--db",
        path.to_str().unwrap(),
        "--runtime-ref",
        partition.runtime_ref.as_str(),
        "--enrollment-ref",
        partition.enrollment_ref.as_str(),
        "--json",
    ];
    let result = cli(&args);
    let value = report(&result);
    assert_eq!(value["queue"]["pending"], 2);
    assert_eq!(value["observed_scope"], "pending");
    assert_eq!(
        value["observed_event_types"],
        json!(["mcp_tool_decision", "mcp_inventory_snapshot"])
    );
    assert_eq!(value["observed_schema_versions"], json!([1, 2]));
    assert_eq!(value["queue"]["recent"][1]["action"], "privacy_rejected");
    assert_eq!(value["queue"]["recent"][1]["rejection"], "prohibited_field");
    assert!(!String::from_utf8_lossy(&result.stdout).contains("canary"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains(event["event_id"].as_str().unwrap()));
    assert_eq!(fs::read(&path).unwrap(), before);
    let mut wrong = args;
    wrong[7] = "ref_99999999999999999999999999999999";
    let result = cli(&wrong);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("canary"));
    assert_eq!(fs::read(&path).unwrap(), before);
    let mut store = Outbox::open(&path, partition.clone()).unwrap();
    for _ in 0..2 {
        let lease = store.claim().unwrap().unwrap();
        store.complete(lease, DeliveryOutcome::Accepted).unwrap();
    }
    drop(store);
    let delivered = fs::read(&path).unwrap();
    let value = report(&cli(&args));
    assert_eq!(value["observed_event_types"], json!([]));
    assert_eq!(value["observed_schema_versions"], json!([]));
    assert_eq!(value["queue"]["pending_contracts"], json!([]));
    assert_eq!(value["queue"]["receipts"], 2);
    assert_eq!(fs::read(&path).unwrap(), delivered);
    fs::write(&path, b"corrupt-content-canary").unwrap();
    let result = cli(&args);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("canary"));
    assert_eq!(fs::read(&path).unwrap(), b"corrupt-content-canary");
}

#[test]
fn invalid_inspection_scope_and_probe_paths_never_echo_values() {
    for args in [
        vec!["egress", "inspect", "--db", "private-path-canary", "--json"],
        vec![
            "egress",
            "inspect",
            "--db",
            "private-path-canary",
            "--runtime-ref",
            "invalid-ref-canary",
            "--enrollment-ref",
            "ref_99999999999999999999999999999999",
            "--json",
        ],
        vec![
            "privacy",
            "self-test",
            "--work-dir",
            "missing-parent-canary/does-not-exist",
            "--json",
        ],
    ] {
        let result = cli(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let error: Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(error["schema_version"], 1);
        assert!(!String::from_utf8_lossy(&result.stderr).contains("canary"));
    }
}
