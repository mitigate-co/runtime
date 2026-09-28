use super::*;
use mitigate_mcp::classification::CapabilityClass;
use serde_json::{Value, json};

const EXAMPLE: &str = include_str!("../../../examples/policies/read-and-review.rego");
fn input_json() -> Value {
    json!({"schema_version":1,"client":null,"principal":"a".repeat(64),"agent":null,
        "server":"b".repeat(64),"tool":"c".repeat(64),"schema_fingerprint":"d".repeat(64),
        "capabilities":["read_data"],"schema_changed":false,"grant":"explicit","offline":false})
}
fn input() -> PolicyInput {
    PolicyInput::from_bytes(&serde_json::to_vec(&input_json()).unwrap()).unwrap()
}

#[test]
fn real_regorus_decisions_and_input_changes_do_not_reuse_results() {
    let mut policy = Policy::compile(EXAMPLE).unwrap();
    let mut input = input();
    assert_eq!(policy.evaluate(&input), Ok(Decision::Allow));
    input.capabilities = vec![CapabilityClass::DeleteData];
    assert_eq!(policy.evaluate(&input), Ok(Decision::RequireApproval));
    input.grant = GrantState::Denied;
    assert_eq!(policy.evaluate(&input), Ok(Decision::Deny));
    input.grant = GrantState::Explicit;
    input.schema_changed = true;
    assert_eq!(policy.evaluate(&input), Ok(Decision::Deny));
    input.schema_changed = false;
    input.principal = None;
    assert_eq!(policy.evaluate(&input), Ok(Decision::Deny));
    input = self::input();
    input.offline = true;
    assert_eq!(policy.evaluate(&input), Ok(Decision::Allow));
    input.capabilities.push(CapabilityClass::Unknown);
    assert_eq!(policy.evaluate(&input), Ok(Decision::Deny));
    input = self::input();
    input.grant = GrantState::None;
    assert_eq!(policy.evaluate(&input), Ok(Decision::Deny));
}

#[test]
fn bounded_profile_rejects_expansion_side_effects_and_indirect_calls() {
    for body in [
        "print(input)",
        "trace(input)",
        "http.send({})",
        "time.now_ns() > 0",
        "x := count; x(input.capabilities) == 1",
        "count(input.capabilities, 1)",
        "some x in input.capabilities",
        "every x in input.capabilities { true }",
        "[x | some x in input.capabilities] == []",
        "data.hidden == true",
        "input[\"offline\"]",
        "true with input.offline as false",
        "count(\"payload\") == 7",
        "input.capabilities[_] == \"read_data\"",
        "1 + 1 == 2",
        "numbers.range(0, 999) == []",
        "x = x",
        "input.raw_arguments == null",
        "decision == \"allow\"",
    ] {
        let source = format!(
            "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"allow\" if {{ {body} }}"
        );
        assert!(
            matches!(Policy::compile(&source), Err(Error::Profile)),
            "accepted forbidden body: {body}"
        );
    }
    for source in [
        "package mitigate.mcp\ndefault decision := \"allow\"",
        "package mitigate.mcp\ndecision := \"allow\"",
        "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := input.grant if { true }",
        "package mitigate.mcp\ndefault decision := \"deny\"\nf(x) := x",
        "package mitigate.mcp\nimport data.hidden\ndefault decision := \"deny\"",
        "package wrong\ndefault decision := \"deny\"",
        "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"canary\" if { true }",
    ] {
        assert!(Policy::compile(source).is_err());
    }
}

#[test]
fn lexical_limits_precede_dependency_parser() {
    for expression in [
        "1e99999999999999999999 == 1".into(),
        "9".repeat(16_000),
        format!("{}true{}", "(".repeat(1000), ")".repeat(1000)),
        format!("\"{}\" == \"x\"", "s".repeat(129)),
        "\"\\u0061\" == \"a\"".into(),
        "`raw` == `raw`".into(),
        format!("true{}", ";true".repeat(600)),
    ] {
        let source = format!(
            "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"allow\" if {{ {expression} }}"
        );
        assert!(matches!(Policy::compile(&source), Err(Error::Profile)));
    }
    assert!(Policy::compile(&"#".repeat(MAX_SOURCE + 1)).is_err());
}

#[test]
fn conflicting_decisions_fail_closed_without_policy_source_in_error() {
    let source = "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"allow\" if { input.offline }\ndecision := \"deny\" if { input.offline }";
    let mut policy = Policy::compile(source).unwrap();
    let mut input = input();
    assert_eq!(policy.evaluate(&input), Ok(Decision::Deny));
    input.offline = true;
    assert_eq!(policy.evaluate(&input), Err(Error::Evaluation));
    input.offline = false;
    assert_eq!(policy.evaluate(&input), Ok(Decision::Deny));
    assert!(!Error::Evaluation.to_string().contains("input.offline"));
}

#[test]
fn input_is_closed_and_unknowns_remain_null() {
    let mut value = input_json();
    value["principal"] = Value::Null;
    let parsed = PolicyInput::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(parsed).unwrap()["principal"],
        Value::Null
    );
    for (key, bad) in [
        ("metadata", json!({"secret":"synthetic-canary"})),
        ("raw_arguments", json!({})),
        ("schema_version", json!(2)),
        ("capabilities", json!(["read_data", "read_data"])),
        ("grant", json!("inferred")),
        ("principal", json!("user@example.invalid")),
        ("capabilities", json!(["made_up"])),
    ] {
        let mut value = input_json();
        value[key] = bad;
        assert!(matches!(
            PolicyInput::from_bytes(&serde_json::to_vec(&value).unwrap()),
            Err(Error::Input)
        ));
    }
    let mut missing = input_json();
    missing.as_object_mut().unwrap().remove("agent");
    assert!(PolicyInput::from_bytes(&serde_json::to_vec(&missing).unwrap()).is_err());
    assert!(PolicyInput::from_bytes(br#"{"client":null,"client":null}"#).is_err());
    let mut input = input();
    input.capabilities = vec![CapabilityClass::ReadData; 12];
    assert_eq!(
        Policy::compile(EXAMPLE).unwrap().evaluate(&input),
        Err(Error::Input)
    );
}

fn authority() -> Authority {
    Authority {
        schema_version: 1,
        policy_ref: input().server,
        public_key: public_key(&[7; 32]),
    }
}
fn signed(version: u64, source: &str) -> SignedBundle {
    SignedBundle::sign(authority().policy_ref, version, source.into(), &[7; 32]).unwrap()
}
const DENY: &str = "package mitigate.mcp\ndefault decision := \"deny\"";
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mitigate-policy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("policy.db")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn signatures_bind_every_manifest_field_and_independent_trust() {
    let bundle = signed(1, EXAMPLE);
    let authority = authority();
    let bytes = bundle.to_bytes().unwrap();
    let mut active = SignedBundle::from_bytes(&bytes)
        .unwrap()
        .verify(&authority)
        .unwrap();
    assert_eq!(active.evaluate(&input()), Ok(Decision::Allow));
    for (field, value) in [
        ("source", json!(DENY)),
        ("version", json!(2)),
        ("profile", json!("other")),
        ("schema_version", json!(2)),
        ("policy_ref", json!("f".repeat(64))),
    ] {
        let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
        tampered["manifest"][field] = value;
        let result = SignedBundle::from_bytes(&serde_json::to_vec(&tampered).unwrap())
            .and_then(|b| b.verify(&authority));
        assert!(matches!(result, Err(Error::Signature)));
    }
    let mut other = authority.clone();
    other.public_key = public_key(&[8; 32]);
    assert!(matches!(bundle.verify(&other), Err(Error::Signature)));
    other.public_key = "0".repeat(64);
    assert!(Authority::from_bytes(&serde_json::to_vec(&other).unwrap()).is_err());
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["signature"] = json!("0".repeat(128));
    assert!(
        SignedBundle::from_bytes(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .verify(&authority)
            .is_err()
    );
    value["metadata"] = json!("source-canary");
    assert!(SignedBundle::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(SignedBundle::from_bytes(br#"{"manifest":{},"manifest":{},"signature":""}"#).is_err());
    for version in [0, 9_007_199_254_740_992, u64::MAX] {
        assert!(
            SignedBundle::sign(authority.policy_ref.clone(), version, DENY.into(), &[7; 32])
                .is_err()
        );
    }
}

#[test]
fn atomic_activation_restart_and_monotonic_versions() {
    let dir = Directory::new();
    let mut store = PolicyStore::create(&dir.db(), authority()).unwrap();
    assert!(matches!(store.load(), Err(Error::NoPolicy)));
    assert!(PolicyStore::create(&dir.db(), authority()).is_err());
    let mut active = store.activate(&signed(1, EXAMPLE)).unwrap();
    let original = active.receipt().clone();
    assert_eq!(active.evaluate(&input()), Ok(Decision::Allow));
    assert!(matches!(
        store.activate(&signed(1, DENY)),
        Err(Error::Rollback)
    ));
    active.refresh(&mut store, &signed(2, DENY)).unwrap();
    assert_eq!(active.evaluate(&input()), Ok(Decision::Deny));
    assert!(active.refresh(&mut store, &signed(1, EXAMPLE)).is_err());
    drop(store);
    let mut loaded = PolicyStore::open(&dir.db(), authority())
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(loaded.receipt().version, 2);
    assert_ne!(loaded.receipt().bundle_hash, original.bundle_hash);
    assert_eq!(loaded.evaluate(&input()), Ok(Decision::Deny));
}

#[test]
fn unavailable_or_corrupt_storage_preserves_loaded_policy() {
    let dir = Directory::new();
    let mut store = PolicyStore::create(&dir.db(), authority()).unwrap();
    let mut active = store.activate(&signed(1, EXAMPLE)).unwrap();
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        active.refresh(&mut store, &signed(2, DENY)),
        Err(Error::Storage)
    );
    assert_eq!(active.evaluate(&input()), Ok(Decision::Allow));
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(store.load().unwrap().receipt().version, 1);
    conn.execute("UPDATE policy SET version=8", []).unwrap();
    assert!(store.load().is_err());
    assert!(active.refresh(&mut store, &signed(9, DENY)).is_err());
    assert_eq!(active.evaluate(&input()), Ok(Decision::Allow));
    assert!(PolicyStore::open(&dir.db(), authority()).is_err());
    drop(conn);
    drop(store);
}

#[test]
fn competing_writers_and_schema_tampering_fail_closed() {
    let dir = Directory::new();
    let mut first = PolicyStore::create(&dir.db(), authority()).unwrap();
    let mut second = PolicyStore::open(&dir.db(), authority()).unwrap();
    first.activate(&signed(2, EXAMPLE)).unwrap();
    assert!(matches!(
        second.activate(&signed(1, DENY)),
        Err(Error::Rollback)
    ));
    second.activate(&signed(3, DENY)).unwrap();
    assert_eq!(first.load().unwrap().receipt().version, 3);
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER tamper AFTER UPDATE ON policy BEGIN DELETE FROM policy; END",
    )
    .unwrap();
    assert!(first.activate(&signed(4, EXAMPLE)).is_err());
    assert_eq!(
        conn.query_row("SELECT version FROM policy", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    drop(conn);
    drop(first);
    drop(second);
}

#[test]
fn bad_replacement_never_displaces_last_verified_bundle() {
    let dir = Directory::new();
    let mut store = PolicyStore::create(&dir.db(), authority()).unwrap();
    let mut active = store.activate(&signed(1, EXAMPLE)).unwrap();
    let wrong = SignedBundle::sign(authority().policy_ref, 2, DENY.into(), &[8; 32]).unwrap();
    assert_eq!(active.refresh(&mut store, &wrong), Err(Error::Signature));
    assert_eq!(active.receipt().version, 1);
    assert_eq!(store.load().unwrap().receipt().version, 1);
    let mut wrong_authority = authority();
    wrong_authority.public_key = public_key(&[8; 32]);
    assert!(PolicyStore::open(&dir.db(), wrong_authority).is_err());
    assert!(PolicyStore::open(&dir.0, authority()).is_err());
    assert!(PolicyStore::open(&dir.0.join("missing"), authority()).is_err());
}

#[test]
fn even_validly_signed_unsupported_source_cannot_activate() {
    use ed25519_dalek::Signer;
    let dir = Directory::new();
    let mut store = PolicyStore::create(&dir.db(), authority()).unwrap();
    let mut active = store.activate(&signed(1, EXAMPLE)).unwrap();
    let mut envelope: Value = serde_json::from_slice(&signed(2, DENY).to_bytes().unwrap()).unwrap();
    envelope["manifest"]["source"] = json!(
        "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"allow\" if { print(\"source-canary\") }"
    );
    let mut message = b"mitigate-mcp-policy-bundle-v1\0".to_vec();
    message.extend(mitigate_fingerprint::canonicalize(&envelope["manifest"]).unwrap());
    envelope["signature"] = json!(crate::bundle::encode_hex(
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .sign(&message)
            .to_bytes()
    ));
    let bundle = SignedBundle::from_bytes(&serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert_eq!(active.refresh(&mut store, &bundle), Err(Error::Profile));
    assert_eq!(active.evaluate(&input()), Ok(Decision::Allow));
    assert_eq!(store.load().unwrap().receipt().version, 1);
}

#[cfg(unix)]
#[test]
fn private_unix_store_and_symlink_rejection() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Directory::new();
    let store = PolicyStore::create(&dir.db(), authority()).unwrap();
    drop(store);
    assert_eq!(
        std::fs::metadata(dir.db()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let link = dir.0.join("alias.db");
    symlink(dir.db(), &link).unwrap();
    assert!(PolicyStore::open(&link, authority()).is_err());
    std::fs::set_permissions(dir.db(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(PolicyStore::open(&dir.db(), authority()).is_err());
}
