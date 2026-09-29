//! Executable synthetic mapping-to-outbox boundary; no account or network.
use mitigate_egress::{
    Attribution, Capability, CheckedEvent, Decision, DecisionFacts, Outcome, Phase, SyncRef,
    outbox::{Admission, Limits, Outbox, Partition},
    references::{Kind, LocalKey, ReferenceMap},
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("references.sqlite"));
        let _ = fs::remove_file(self.0.join("outbox.sqlite"));
        let _ = fs::remove_dir(&self.0);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "mitigate-mapping-fixture-{}",
        SyncRef::fresh()?.as_str()
    ));
    fs::create_dir(&path)?;
    let fixture = Fixture(path);
    let partition = Partition {
        runtime_ref: SyncRef::fresh()?,
        enrollment_ref: SyncRef::fresh()?,
    };
    let keys = [
        Kind::Client,
        Kind::Server,
        Kind::Tool,
        Kind::Schema,
        Kind::Policy,
    ]
    .map(|kind| LocalKey::new(kind, [0xa5; 32]));
    let mut mappings =
        ReferenceMap::create(&fixture.0.join("references.sqlite"), partition.clone())?;
    let mapped = mappings.resolve(&keys)?;
    drop(mappings);
    let mut reopened = ReferenceMap::open(&fixture.0.join("references.sqlite"), partition.clone())?;
    if reopened.resolve(&keys)? != mapped {
        return Err("synthetic mapping recovery failed".into());
    }
    let [client, server, tool, schema, policy]: [SyncRef; 5] = mapped
        .try_into()
        .map_err(|_| "synthetic mapping count failed")?;
    let event = CheckedEvent::decision(
        SyncRef::fresh()?,
        partition.runtime_ref.clone(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
        DecisionFacts {
            call_ref: SyncRef::fresh()?,
            client_ref: Some(client),
            principal_ref: None,
            agent_ref: None,
            attribution: Attribution::DeclaredProfile,
            server_ref: server,
            tool_ref: Some(tool),
            schema_ref: Some(schema),
            capabilities: vec![Capability::ReadData],
            policy_ref: Some(policy),
            policy_version: Some(1),
            approval_ref: None,
            phase: Phase::Dispatch,
            decision: Decision::AllowAndLog,
            outcome: Outcome::Pending,
            duration_ms: 0,
        },
    )?;
    let mut queue = Outbox::create(
        &fixture.0.join("outbox.sqlite"),
        partition,
        Limits::default(),
    )?;
    if queue.admit(event.as_bytes())? != Admission::Queued {
        return Err("synthetic admission failed".into());
    }
    let lease = queue.claim()?.ok_or("synthetic lease missing")?;
    if lease.event().as_bytes() != event.as_bytes()
        || String::from_utf8_lossy(lease.event().as_bytes()).contains(&"a5".repeat(16))
    {
        return Err("synthetic mapping boundary failed".into());
    }
    queue.purge()?;
    drop(queue);
    drop(reopened);
    println!(
        "Reference mapping verified: independent IDs, restart recovery and checked queue admission. No network requests."
    );
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!(
            "Synthetic reference-mapping verification failed; no local keys or backend diagnostics displayed."
        );
        std::process::exit(1);
    }
}
