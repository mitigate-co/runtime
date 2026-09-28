//! The real CLI stays offline and preserves public source claims without authority.
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

const FIXTURE: &[u8] = include_bytes!("../../../examples/registry/catalog.json");
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("mitigate-registry-cli-{name}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn catalog(&self) -> PathBuf {
        self.0.join("selected-public-catalog.json")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn cli(path: &std::path::Path, subject: &str, machine: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mitigate"));
    command
        .args(["mcp", "registry", "lookup", "--catalog"])
        .arg(path)
        .args(["--subject", subject]);
    if machine {
        command.arg("--json");
    }
    command
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .env_remove("MITIGATE_TOKEN")
        .env_remove("MITIGATE_ORGANIZATION")
        .output()
        .unwrap()
}
fn report(result: &Output) -> Value {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
fn lookup_shows_sources_conflicting_claims_and_explicit_no_authority() {
    let fixture = Fixture::new();
    let path = fixture.catalog();
    fs::write(&path, FIXTURE).unwrap();
    let output = cli(&path, "io.example/synthetic-server", true);
    let value = report(&output);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["found"], true);
    assert_eq!(value["publisher_authenticated"], false);
    assert_eq!(value["grants_access"], false);
    assert_eq!(value["facts"].as_array().unwrap().len(), 6);
    assert_eq!(value["sources"].as_array().unwrap().len(), 2);
    let claims: Vec<_> = value["facts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["assertion"]["kind"] == "package")
        .collect();
    assert_eq!(claims.len(), 2);
    assert_ne!(
        claims[0]["assertion"]["version"],
        claims[1]["assertion"]["version"]
    );
    let human = cli(&path, "io.example/synthetic-server", false);
    assert!(human.status.success() && human.stderr.is_empty());
    let text = String::from_utf8(human.stdout).unwrap();
    for expected in [
        "Unsigned source claims. No access granted.",
        "synthetic-publisher",
        "synthetic-review",
        "1.0.0",
        "0.9.0",
        "confidence=",
        "observed_ms=",
        "retrieved_ms=",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    assert_eq!(fs::read(&path).unwrap(), FIXTURE);
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[test]
fn unknown_and_expired_are_diagnostic_results_without_installation_or_refresh() {
    let fixture = Fixture::new();
    let path = fixture.catalog();
    let mut catalog: Value = serde_json::from_slice(FIXTURE).unwrap();
    catalog["generated_at_ms"] = json!(1000);
    catalog["expires_at_ms"] = json!(2000);
    for source in catalog["sources"].as_array_mut().unwrap() {
        source["retrieved_at_ms"] = json!(1000);
    }
    for fact in catalog["facts"].as_array_mut().unwrap() {
        fact["observed_at_ms"] = json!(1000);
        if fact["assertion"]["kind"] == "release" {
            fact["assertion"]["published_at_ms"] = json!(0);
        }
    }
    let before = serde_json::to_vec(&catalog).unwrap();
    fs::write(&path, &before).unwrap();
    let value = report(&cli(&path, "io.example/synthetic-server", true));
    assert_eq!(value["freshness"], "expired");
    assert_eq!(value["facts"].as_array().unwrap().len(), 6);
    let unknown = report(&cli(&path, "io.example/absent", true));
    assert_eq!(unknown["found"], false);
    assert_eq!(unknown["facts"], json!([]));
    assert_eq!(unknown["sources"], json!([]));
    let human = cli(&path, "io.example/absent", false);
    assert!(String::from_utf8_lossy(&human.stdout).contains("Safety is unknown."));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[test]
fn invalid_public_catalogs_and_private_paths_never_leak_in_error_output() {
    let fixture = Fixture::new();
    let path = fixture.catalog();
    for content in [
        b"private-source-canary".to_vec(),
        {
            let mut value: Value = serde_json::from_slice(FIXTURE).unwrap();
            value["facts"][0]["assertion"]["metadata"] = json!({"secret":"private-source-canary"});
            serde_json::to_vec(&value).unwrap()
        },
        {
            let mut value: Value = serde_json::from_slice(FIXTURE).unwrap();
            value["facts"][0]["source_ref"] = json!("missing-source-canary");
            serde_json::to_vec(&value).unwrap()
        },
    ] {
        fs::write(&path, &content).unwrap();
        let result = cli(&path, "io.example/synthetic-server", true);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let error: Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(error["schema_version"], 1);
        assert!(!String::from_utf8_lossy(&result.stderr).contains("canary"));
        assert_eq!(fs::read(&path).unwrap(), content);
    }
    fs::write(&path, FIXTURE).unwrap();
    for (path, subject) in [
        (
            fixture.0.join("missing-private-path-canary"),
            "io.example/synthetic-server",
        ),
        (path, "invalid-subject-canary"),
    ] {
        for machine in [true, false] {
            let result = cli(&path, subject, machine);
            assert_eq!(result.status.code(), Some(2));
            assert!(result.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&result.stderr).contains("canary"));
        }
    }
}

#[test]
fn catalog_selection_is_required_and_help_is_actionable() {
    let result = Command::new(env!("CARGO_BIN_EXE_mitigate"))
        .args([
            "mcp",
            "registry",
            "lookup",
            "--subject",
            "io.example/synthetic-server",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let result = Command::new(env!("CARGO_BIN_EXE_mitigate"))
        .args(["mcp", "registry", "lookup", "--help"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(
        text.contains("--catalog") && text.contains("--subject") && text.contains("no network")
    );
}
