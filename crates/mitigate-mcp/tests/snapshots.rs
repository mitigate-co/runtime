//! Change detection must distinguish identity, schema and description semantics.
use mitigate_mcp::{ChangeKind, Error, Inventory, Snapshot, Tool};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

fn inventory() -> Inventory {
    Inventory {
        protocol_version: "2025-11-25".into(),
        server_name: "fixture".into(),
        server_version: "1.0.0".into(),
        tools_supported: true,
        tools: vec![Tool {
            name: "read_status".into(),
            description: Some("Read status".into()),
            input_schema: json!({"type":"object","properties":{"limit":{"type":"number","maximum":1}}}),
            output_schema: None,
        }],
    }
}

#[test]
fn equivalent_schema_encodings_and_description_whitespace_do_not_change_fingerprints() {
    let before = Snapshot::from_inventory(&inventory()).unwrap();
    let mut after = inventory();
    after.tools[0].description = Some("  Read\n\tstatus  ".into());
    after.tools[0].input_schema = serde_json::from_str(
        r#"{"properties":{"limit":{"maximum":1.0,"type":"number"}},"type":"object"}"#,
    )
    .unwrap();
    assert!(
        before
            .diff(&Snapshot::from_inventory(&after).unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn separates_description_input_output_identity_and_server_version_changes() {
    let before = Snapshot::from_inventory(&inventory()).unwrap();
    let mut after = inventory();
    after.tools[0].description = Some("Delete status".into());
    let diff = before
        .diff(&Snapshot::from_inventory(&after).unwrap())
        .unwrap();
    assert_eq!(diff.tools.len(), 1);
    assert!(diff.tools[0].description_changed);
    assert!(!diff.tools[0].input_schema_changed);
    assert!(!diff.server_facts_changed);
    let mut after = inventory();
    after.tools[0].input_schema["properties"]["limit"]["maximum"] = json!(2);
    after.tools[0].output_schema = Some(json!({"type":"object"}));
    let diff = before
        .diff(&Snapshot::from_inventory(&after).unwrap())
        .unwrap();
    assert!(diff.tools[0].input_schema_changed);
    assert!(diff.tools[0].output_schema_changed);
    assert!(!diff.tools[0].description_changed);
    let mut after = inventory();
    after.server_version = "2.0.0".into();
    let diff = before
        .diff(&Snapshot::from_inventory(&after).unwrap())
        .unwrap();
    assert!(diff.server_facts_changed);
    assert!(!diff.server_identity_changed);
    assert!(diff.tools.is_empty());
    after.server_name = "another".into();
    let diff = before
        .diff(&Snapshot::from_inventory(&after).unwrap())
        .unwrap();
    assert!(diff.server_identity_changed);
    assert!(diff.tools[0].identity_changed);
}

#[test]
fn additions_removals_and_unsupported_tools_are_explicit() {
    let before = Snapshot::from_inventory(&inventory()).unwrap();
    let mut after = inventory();
    after.tools[0].name = "write_status".into();
    let diff = before
        .diff(&Snapshot::from_inventory(&after).unwrap())
        .unwrap();
    assert_eq!(diff.tools[0].kind, ChangeKind::Removed);
    assert_eq!(diff.tools[1].kind, ChangeKind::Added);
    after.tools.clear();
    after.tools_supported = false;
    let diff = before
        .diff(&Snapshot::from_inventory(&after).unwrap())
        .unwrap();
    assert!(diff.tools_supported_changed);
    assert_eq!(diff.tools[0].kind, ChangeKind::Removed);
}

#[test]
fn rejects_tampered_ambiguous_and_incompatible_snapshots() {
    let snapshot = Snapshot::from_inventory(&inventory()).unwrap();
    let original = serde_json::to_value(&snapshot).unwrap();
    for mutation in 0..8 {
        let mut value = original.clone();
        match mutation {
            0 => value["schema_version"] = json!(2),
            1 => value["fingerprint_profile"] = json!("unknown"),
            2 => value["credential"] = json!("credential-canary"),
            3 => value["tools"][0]["input_schema"] = json!("schema-canary"),
            4 => value["tools"][0]["name"] = json!("\u{001b}escape"),
            5 => value["tools"][0]["identity"] = json!("0".repeat(64)),
            6 => value["tools"]
                .as_array_mut()
                .unwrap()
                .push(original["tools"][0].clone()),
            _ => value["tools_supported"] = json!(false),
        }
        assert_eq!(
            Snapshot::from_bytes(&serde_json::to_vec(&value).unwrap()).err(),
            Some(Error::Snapshot)
        );
    }
    assert_eq!(
        Snapshot::from_bytes(br#"{"schema_version":1,"schema_version":1}"#).err(),
        Some(Error::Snapshot)
    );
    assert_eq!(
        Snapshot::from_bytes(&vec![b' '; 1_048_577]).err(),
        Some(Error::Snapshot)
    );
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Local(PathBuf);
impl Drop for Local {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn explicit_snapshot_files_are_private_non_overwriting_and_content_free() {
    let root = Local(std::env::temp_dir().join(format!(
        "mitigate-snapshot-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir(&root.0).unwrap();
    let path = root.0.join("snapshot.json");
    let mut data = inventory();
    data.tools[0].description = Some("description-canary".into());
    data.tools[0].input_schema["default"] = json!("schema-canary");
    let snapshot = Snapshot::from_inventory(&data).unwrap();
    snapshot.write_new(&path).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("canary"));
    assert_eq!(snapshot.write_new(&path), Err(Error::Snapshot));
    assert_eq!(bytes, fs::read(&path).unwrap());
    assert!(
        snapshot
            .diff(&Snapshot::from_file(&path).unwrap())
            .unwrap()
            .is_empty()
    );
    let decoded: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded["schema_version"], 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
