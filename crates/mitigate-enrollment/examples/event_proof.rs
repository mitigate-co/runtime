//! Public synthetic signature only. No credentials, user input or network access.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mitigate_egress::{
    SyncRef,
    outbox::{Admission, Limits, Outbox, Partition},
};
use mitigate_enrollment::{EnrollmentIdentity, EnrollmentKey, PlatformOrigin};
use mitigate_secrets::Secret;
use std::{fs, io::Write, path::PathBuf};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "mitigate-event-proof-{}",
        SyncRef::fresh()?.as_str()
    ));
    fs::create_dir(&path)?;
    let fixture = Fixture(path);
    let key = EnrollmentKey::from_secret(Secret::from_bytes(
        URL_SAFE_NO_PAD.encode([23; 32]).into_bytes(),
    )?)?;
    let identity = EnrollmentIdentity::from_references(
        serde_json::from_str("\"ref_22222222222222222222222222222222\"")?,
        serde_json::from_str("\"ref_99999999999999999999999999999999\"")?,
    )?;
    let mut outbox = Outbox::create(
        &fixture.0.join("outbox.sqlite"),
        Partition {
            runtime_ref: identity.runtime_ref().clone(),
            enrollment_ref: identity.enrollment_ref().clone(),
        },
        Limits::default(),
    )?;
    assert_eq!(
        outbox.admit(include_bytes!("../../../examples/egress/decision.json"))?,
        Admission::Queued
    );
    let lease = outbox.claim()?.expect("synthetic queued event");
    let event = key.sign_event(
        &PlatformOrigin::parse("https://mitigate.example")?,
        &identity,
        &lease,
    )?;
    // Only this hard-coded public fixture is printable. Production delivery
    // never formats event bodies, signatures or identifiers into ordinary logs.
    std::io::stdout().lock().write_all(event.as_bytes())?;
    Ok(())
}
