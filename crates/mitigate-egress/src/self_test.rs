//! Executable local privacy probe. It uses only fixed synthetic data, an
//! exclusively owned temporary directory and the production admission boundary.
use crate::{
    CheckedEvent, SyncRef,
    outbox::{Action, Admission, Limits, Outbox, Partition},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

/// One fixed fixture family, with no fixture values or backend messages.
#[derive(Serialize)]
pub struct Check {
    /// Stable reviewed category, never supplied by workload content.
    pub category: &'static str,
    /// Number of hostile candidates attempted.
    pub attempted: u32,
    /// Number refused by the actual queue admission path.
    pub rejected: u32,
}
/// Local-only privacy test result. This is not a telemetry event or certification.
#[derive(Serialize)]
pub struct Report {
    /// Result format version.
    pub schema_version: u8,
    /// True only if positive, hostile-admission and persisted-canary checks passed.
    pub passed: bool,
    /// Positive control: the known-safe candidate was admitted and deduplicated.
    pub positive_control: bool,
    /// Closed fixture families and observed counts.
    pub checks: Vec<Check>,
    /// No extra pending events or receipts and the rejection count matched.
    pub queue_isolation: bool,
    /// None of the synthetic content markers appeared in retained database bytes.
    pub persisted_canaries_absent: bool,
    /// Fixed zero: this probe owns no network sender.
    pub network_requests: u32,
}
/// Operational failures expose no path, fixture content or underlying exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The chosen parent cannot host a private exclusive temporary directory.
    Workspace,
    /// Synthetic serialization/reference generation or queue setup failed.
    Setup,
    /// Bounded local storage cannot complete the probe.
    Storage,
    /// The owned fixture directory could not be removed.
    Cleanup,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Workspace => "privacy test workspace unavailable; choose a writable --work-dir",
            Self::Setup => "privacy test setup failed; keep optional sync disabled and inspect this installation",
            Self::Storage => "privacy test storage unavailable; check free space and access, then retry",
            Self::Cleanup => "privacy test cleanup failed; inspect temporary storage before retrying",
        })
    }
}
impl std::error::Error for Error {}

struct Workspace {
    path: PathBuf,
    removed: bool,
}
impl Workspace {
    fn create(parent: &Path) -> Result<Self, Error> {
        let suffix = SyncRef::fresh().map_err(|_| Error::Setup)?;
        let path = parent.join(format!("mitigate-privacy-{}", suffix.as_str()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .recursive(false)
            .create(&path)
            .map_err(|_| Error::Workspace)?;
        Ok(Self {
            path,
            removed: false,
        })
    }
    fn remove(&mut self) -> Result<(), Error> {
        fs::remove_dir_all(&self.path).map_err(|_| Error::Cleanup)?;
        self.removed = true;
        Ok(())
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        // Only a directory exclusively created above, never an operator's store.
        if !self.removed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

const FIELDS: &[&str] = &[
    "/event_type",
    "/event_id",
    "/runtime_ref",
    "/facts/call_ref",
    "/facts/client_ref",
    "/facts/principal_ref",
    "/facts/agent_ref",
    "/facts/attribution",
    "/facts/server_ref",
    "/facts/tool_ref",
    "/facts/schema_ref",
    "/facts/policy_ref",
    "/facts/approval_ref",
    "/facts/phase",
    "/facts/decision",
    "/facts/outcome",
];
const CONTENT: &[(&str, &str)] = &[
    ("api_key", "sk_test_synthetic_privacy_canary_7ea1849bc135"), // gitleaks:allow -- synthetic non-provider privacy fixture
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.synthetic_signature", // gitleaks:allow -- unsigned synthetic privacy fixture
    ),
    ("email", "privacy-canary@example.invalid"),
    ("ssn", "123-45-6789"),
    ("card", "4111111111111111"),
    ("source_code", "fn private_code_canary() { return 42; }"),
    ("high_entropy", "9Ga1qUKgC1Yo7MxEH0dZhTPnV6ScIbRN2eLuBvWK"),
];

fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|_| Error::Setup)
}
fn probe(store: &mut Outbox, check: &mut Check, bytes: &[u8]) -> Result<(), Error> {
    check.attempted += 1;
    if matches!(
        store.admit(bytes).map_err(|_| Error::Storage)?,
        Admission::Rejected(_)
    ) {
        check.rejected += 1;
    }
    Ok(())
}

/// Inject all documented synthetic privacy families into a new private outbox.
/// Never reads a real queue, native credentials, home config or workload file.
/// Success includes explicit removal of the owned scratch directory. No sender.
pub fn run(parent: &Path) -> Result<Report, Error> {
    let mut workspace = Workspace::create(parent)?;
    let result = exercise(&workspace.path.join("outbox.sqlite"));
    workspace.remove()?;
    result
}

fn exercise(path: &Path) -> Result<Report, Error> {
    let mut safe: Value =
        serde_json::from_slice(include_bytes!("../../../examples/egress/decision.json"))
            .map_err(|_| Error::Setup)?;
    let partition = Partition {
        runtime_ref: SyncRef::fresh().map_err(|_| Error::Setup)?,
        enrollment_ref: SyncRef::fresh().map_err(|_| Error::Setup)?,
    };
    safe["runtime_ref"] = json!(partition.runtime_ref);
    safe["event_id"] = json!(SyncRef::fresh().map_err(|_| Error::Setup)?);
    let bytes = encode(&safe)?;
    let mut store =
        Outbox::create(path, partition, Limits::default()).map_err(|_| Error::Storage)?;
    let positive_control = CheckedEvent::from_bytes(&bytes).is_ok()
        && store.admit(&bytes).map_err(|_| Error::Storage)? == Admission::Queued
        && store.admit(&bytes).map_err(|_| Error::Storage)? == Admission::Duplicate;
    let long_text = "synthetic_document_canary ".repeat(80);
    let mut checks = Vec::new();
    for &(category, content) in CONTENT
        .iter()
        .chain(std::iter::once(&("long_text", long_text.as_str())))
    {
        let mut check = Check {
            category,
            attempted: 0,
            rejected: 0,
        };
        for field in FIELDS {
            let mut candidate = safe.clone();
            *candidate.pointer_mut(field).ok_or(Error::Setup)? = json!(content);
            probe(&mut store, &mut check, &encode(&candidate)?)?;
        }
        let mut candidate = safe.clone();
        candidate["facts"]["capabilities"] = json!([content]);
        probe(&mut store, &mut check, &encode(&candidate)?)?;
        checks.push(check);
    }
    let mut nested = Check {
        category: "nested_unknown",
        attempted: 0,
        rejected: 0,
    };
    for pointer in ["", "/facts"] {
        let mut candidate = safe.clone();
        candidate.pointer_mut(pointer).ok_or(Error::Setup)?["future"] =
            json!({"private_field":"nested_canary"});
        probe(&mut store, &mut nested, &encode(&candidate)?)?;
    }
    checks.push(nested);
    let mut prohibited = Check {
        category: "prohibited_keys",
        attempted: 0,
        rejected: 0,
    };
    for field in [
        "prompt",
        "content",
        "arguments",
        "result_body",
        "source_code",
        "metadata",
        "authorization",
    ] {
        let mut candidate = safe.clone();
        candidate["facts"][field] = json!("prohibited_canary");
        probe(&mut store, &mut prohibited, &encode(&candidate)?)?;
    }
    checks.push(prohibited);
    let mut malformed = Check {
        category: "ambiguous_or_oversized",
        attempted: 0,
        rejected: 0,
    };
    probe(
        &mut store,
        &mut malformed,
        br#"{"schema_version":1,"schema_version":1}"#,
    )?;
    probe(
        &mut store,
        &mut malformed,
        &vec![b' '; crate::MAX_EVENT_BYTES + 1],
    )?;
    checks.push(malformed);
    let report = store.inspect().map_err(|_| Error::Storage)?;
    let rejected: u64 = checks.iter().map(|c| u64::from(c.attempted)).sum();
    let queue_isolation = report.pending == 1
        && report.receipts == 0
        && report
            .counters
            .iter()
            .any(|c| c.action == Action::PrivacyRejected && c.totals.events == rejected);
    drop(store);
    let bytes = fs::read(path).map_err(|_| Error::Storage)?;
    let persisted_canaries_absent = CONTENT
        .iter()
        .map(|(_, c)| *c)
        .chain([
            "private_code_canary",
            "synthetic_document_canary",
            "nested_canary",
            "prohibited_canary",
        ])
        .all(|needle| !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()));
    Ok(Report {
        schema_version: 1,
        passed: positive_control
            && queue_isolation
            && persisted_canaries_absent
            && checks
                .iter()
                .all(|c| c.attempted > 0 && c.attempted == c.rejected),
        positive_control,
        checks,
        queue_isolation,
        persisted_canaries_absent,
        network_requests: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_test_checks_real_admission_and_cleans_only_its_owned_workspace() {
        let workspace = Workspace::create(&std::env::temp_dir()).unwrap();
        let marker = workspace.path.join("preserve");
        fs::write(&marker, b"owned-test-marker").unwrap();
        let result = run(&workspace.path).unwrap();
        assert!(result.passed);
        assert_eq!(result.checks.len(), 11);
        assert_eq!(result.checks.iter().map(|c| c.attempted).sum::<u32>(), 147);
        assert_eq!(fs::read_dir(&workspace.path).unwrap().count(), 1);
        assert_eq!(fs::read(&marker).unwrap(), b"owned-test-marker");
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("canary"));
        for &(_, content) in CONTENT {
            assert!(!encoded.contains(content));
        }
        assert_eq!(run(&marker).err(), Some(Error::Workspace));
    }
}
