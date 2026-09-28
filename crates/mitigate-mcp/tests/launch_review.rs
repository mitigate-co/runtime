//! Exact launch binding without executing any selected program.
use mitigate_mcp::{Error, LaunchConfig, LaunchReview};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mitigate-launch-review-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("fixture.exe"), b"synthetic executable bytes").unwrap();
        fs::write(path.join("entry.js"), b"synthetic code artifact").unwrap();
        Self(path)
    }
    fn value(&self) -> Value {
        json!({"schema_version":1,"executable_path":self.0.join("fixture.exe"),"working_directory":self.0,
            "argv":["argument-canary"],"artifact_paths":[self.0.join("entry.js")],
            "secret_references":[{"environment_key":"KEY","secret_ref":"sec_0123456789abcdef0123456789abcdef"}]})
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn config(value: &Value) -> LaunchConfig {
    LaunchConfig::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[tokio::test]
async fn review_is_private_salted_and_binds_every_launch_fact_without_secret_lookup() {
    let f = Fixture::new();
    let value = f.value();
    // Fake native secret reference need not exist: review never reads it.
    let review = LaunchReview::create(&config(&value)).await.unwrap();
    assert_eq!(
        review.receipt().launch_ref,
        review.check(&config(&value)).await.unwrap().launch_ref
    );
    let another = LaunchReview::create(&config(&value)).await.unwrap();
    assert_ne!(review.receipt().launch_ref, another.receipt().launch_ref);
    let serialized = serde_json::to_string(&review).unwrap();
    for canary in [
        "argument-canary",
        "entry.js",
        "fixture.exe",
        "sec_0123456789abcdef0123456789abcdef",
        "KEY",
    ] {
        assert!(!serialized.contains(canary));
    }
    let report = serde_json::to_string(&review.receipt()).unwrap();
    let salt = serde_json::to_value(&review).unwrap()["salt"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!report.contains(&salt));
    assert_eq!(review.receipt().artifact_count, 1);
    let path = f.0.join("review.json");
    review.write_new(&path).unwrap();
    assert_eq!(review.write_new(&path).err(), Some(Error::LaunchReview));
    let restored = LaunchReview::from_file(&path).unwrap();
    assert_eq!(restored.receipt().launch_ref, review.receipt().launch_ref);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let other = f.0.join("other");
    fs::create_dir(&other).unwrap();
    let other_exe = f.0.join("other.exe");
    fs::copy(f.0.join("fixture.exe"), &other_exe).unwrap();
    for (field, replacement) in [
        ("argv", json!(["changed-canary"])),
        ("working_directory", json!(other)),
        ("executable_path", json!(other_exe)),
        ("timeout_ms", json!(31000)),
        ("artifact_paths", json!([])),
        (
            "secret_references",
            json!([{"environment_key":"KEY","secret_ref":"sec_1123456789abcdef0123456789abcdef"}]),
        ),
        (
            "secret_references",
            json!([{"environment_key":"OTHER_KEY","secret_ref":"sec_0123456789abcdef0123456789abcdef"}]),
        ),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert_eq!(
            review.check(&config(&changed)).await.err(),
            Some(Error::LaunchChanged)
        );
    }
    fs::write(f.0.join("entry.js"), b"modified code artifact").unwrap();
    assert_eq!(
        review.check(&config(&value)).await.err(),
        Some(Error::LaunchChanged)
    );
    fs::write(f.0.join("entry.js"), b"synthetic code artifact").unwrap();
    fs::write(f.0.join("fixture.exe"), b"modified executable bytes").unwrap();
    assert_eq!(
        review.check(&config(&value)).await.err(),
        Some(Error::LaunchChanged)
    );
}

#[tokio::test]
async fn invalid_documents_artifact_paths_and_sizes_fail_before_execution() {
    let f = Fixture::new();
    let value = f.value();
    let review = LaunchReview::create(&config(&value)).await.unwrap();
    let doc = serde_json::to_value(&review).unwrap();
    for (field, replacement) in [
        ("schema_version", json!(2)),
        ("profile", json!("unknown")),
        ("salt", json!("canary")),
        ("metadata", json!("secret-canary")),
        ("artifact_sha256", json!(vec!["1".repeat(64); 33])),
    ] {
        let mut bad = doc.clone();
        bad[field] = replacement;
        assert!(LaunchReview::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    assert!(LaunchReview::from_bytes(br#"{"schema_version":1,"schema_version":1}"#).is_err());
    assert!(LaunchReview::from_bytes(&vec![b' '; 8193]).is_err());
    for artifacts in [
        json!([f.0]),
        json!([f.0.join("absent.js")]),
        json!([f.0.join("entry.js"), f.0.join("entry.js")]),
        json!([f.0.join("fixture.exe")]),
    ] {
        let mut bad = value.clone();
        bad["artifact_paths"] = artifacts;
        assert!(LaunchReview::create(&config(&bad)).await.is_err());
    }
    let oversized = fs::File::create(f.0.join("huge.bin")).unwrap();
    oversized.set_len(268_435_457).unwrap();
    let mut bad = value.clone();
    bad["artifact_paths"] = json!([f.0.join("huge.bin")]);
    assert!(LaunchReview::create(&config(&bad)).await.is_err());
    drop(oversized);
    for artifacts in [
        json!(["relative.js"]),
        json!(vec![f.0.join("entry.js"); 33]),
    ] {
        let mut bad = value.clone();
        bad["artifact_paths"] = artifacts;
        assert!(LaunchConfig::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_retargeting_changes_binding_and_review_symlinks_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new();
    let mut value = f.value();
    let alias = f.0.join("alias.js");
    symlink(f.0.join("entry.js"), &alias).unwrap();
    value["artifact_paths"] = json!([alias]);
    let review = LaunchReview::create(&config(&value)).await.unwrap();
    let path = f.0.join("review.json");
    review.write_new(&path).unwrap();
    let link = f.0.join("review-link.json");
    symlink(&path, &link).unwrap();
    assert!(LaunchReview::from_file(&link).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LaunchReview::from_file(&path).is_err());
    fs::write(f.0.join("other.js"), b"synthetic code artifact").unwrap();
    fs::remove_file(&alias).unwrap();
    symlink(f.0.join("other.js"), &alias).unwrap();
    assert_eq!(
        review.check(&config(&value)).await.err(),
        Some(Error::LaunchChanged)
    );
}
