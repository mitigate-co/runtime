use super::*;
use crate::EnrollmentKey;
use ed25519_dalek::{Signature, VerifyingKey};
use mitigate_egress::{
    CheckedEvent,
    outbox::{Admission, DeliveryOutcome, Limits, Outbox, Partition},
};
use mitigate_secrets::Secret;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

struct Fixture {
    outbox: Outbox,
    identity: EnrollmentIdentity,
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture(directory: &Directory) -> Fixture {
    let identity = EnrollmentIdentity::from_references(reference('2'), reference('9')).unwrap();
    let partition = Partition {
        runtime_ref: identity.runtime_ref().clone(),
        enrollment_ref: identity.enrollment_ref().clone(),
    };
    Fixture {
        outbox: Outbox::create(
            &directory.0.join("queue.sqlite"),
            partition,
            Limits::default(),
        )
        .unwrap(),
        identity,
    }
}
fn directory() -> Directory {
    let dir = std::env::temp_dir().join(format!(
        "mitigate-signed-event-{}",
        SyncRef::fresh().unwrap().as_str()
    ));
    fs::create_dir(&dir).unwrap();
    Directory(dir)
}
fn reference(digit: char) -> SyncRef {
    serde_json::from_value(json!(format!("ref_{}", digit.to_string().repeat(32)))).unwrap()
}
fn key() -> EnrollmentKey {
    EnrollmentKey::from_secret(
        Secret::from_bytes(URL_SAFE_NO_PAD.encode([23; 32]).into_bytes()).unwrap(),
    )
    .unwrap()
}
fn origin() -> PlatformOrigin {
    PlatformOrigin::parse("https://mitigate.example").unwrap()
}
fn event() -> &'static [u8] {
    include_bytes!("../../../../examples/egress/decision.json")
}
fn lease(f: &mut Fixture) -> Lease {
    assert_eq!(f.outbox.admit(event()), Ok(Admission::Queued));
    f.outbox.claim().unwrap().unwrap()
}
fn receipt(signed: &SignedEvent) -> Value {
    json!({"schema_version":1,"event_id":signed.event_id,"runtime_ref":signed.identity.runtime_ref(),"enrollment_ref":signed.identity.enrollment_ref(),"event_digest":signed.digest,"status":"accepted"})
}

#[test]
fn signature_binds_the_exact_canonical_event_and_every_transport_scope() {
    verify_signed_event(event());
    verify_signed_event(include_bytes!(
        "../../../../examples/egress/inventory-part.json"
    ));
}
fn verify_signed_event(input: &[u8]) {
    let dir = directory();
    let mut f = fixture(&dir);
    assert_eq!(f.outbox.admit(input), Ok(Admission::Queued));
    let lease = f.outbox.claim().unwrap().unwrap();
    let signed = key().sign_event(&origin(), &f.identity, &lease).unwrap();
    assert!(signed.as_bytes().len() <= MAX_SIGNED_EVENT_BYTES);
    let envelope: Value = serde_json::from_slice(signed.as_bytes()).unwrap();
    assert_eq!(envelope.as_object().unwrap().len(), 4);
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(
        envelope["enrollment_ref"],
        json!(f.identity.enrollment_ref())
    );
    let canonical =
        CheckedEvent::from_bytes(&serde_json::to_vec(&envelope["event"]).unwrap()).unwrap();
    assert_eq!(canonical.as_bytes(), lease.event().as_bytes());
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    let fields = [
        "mitigate.runtime.event.v1",
        origin().as_str(),
        "POST",
        EVENT_PATH,
        f.identity.runtime_ref().as_str(),
        f.identity.enrollment_ref().as_str(),
        canonical.event_id().as_str(),
        &digest,
    ]
    .map(str::to_owned);
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(envelope["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let public = SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes();
    let verifier = VerifyingKey::from_bytes(&public).unwrap();
    verifier
        .verify_strict(
            format!("{}\n", fields.join("\n")).as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .unwrap();
    for index in 0..fields.len() {
        let mut changed = fields.clone();
        changed[index].push('x');
        assert!(
            verifier
                .verify_strict(
                    format!("{}\n", changed.join("\n")).as_bytes(),
                    &Signature::from_bytes(&signature)
                )
                .is_err()
        );
    }
    assert!(
        verifier
            .verify_strict(
                fields.join("\n").as_bytes(),
                &Signature::from_bytes(&signature)
            )
            .is_err()
    );
    assert_eq!(signed.origin().as_str(), origin().as_str());
    assert_eq!(
        key()
            .sign_event(&origin(), &f.identity, &lease)
            .unwrap()
            .as_bytes(),
        signed.as_bytes()
    );
    assert_eq!(f.outbox.inspect().unwrap().pending, 1);
    // A validated receipt does not implicitly complete or mutate the queue.
    let confirmed = signed
        .verify_receipt(&serde_json::to_vec(&receipt(&signed)).unwrap())
        .unwrap();
    assert!(confirmed.event_id() == lease.event().event_id());
    assert_eq!(f.outbox.inspect().unwrap().pending, 1);
    f.outbox.complete(lease, DeliveryOutcome::Accepted).unwrap();
    assert_eq!(f.outbox.inspect().unwrap().pending, 0);
    assert_eq!(f.outbox.admit(input), Ok(Admission::Duplicate));
}

#[test]
fn wrong_enrollment_never_signs_and_rejected_content_never_obtains_a_lease() {
    let dir = directory();
    let mut f = fixture(&dir);
    for candidate in [
        br#"{"arguments":"private-canary"}"#.as_slice(),
        br#"{"metadata":{"code":"private-canary"}}"#,
    ] {
        assert!(matches!(
            f.outbox.admit(candidate),
            Ok(Admission::Rejected(_))
        ));
        assert!(f.outbox.claim().unwrap().is_none());
    }
    let lease = lease(&mut f);
    for identity in [
        EnrollmentIdentity::from_references(reference('3'), reference('9')).unwrap(),
        EnrollmentIdentity::from_references(reference('2'), reference('8')).unwrap(),
    ] {
        assert_eq!(
            key().sign_event(&origin(), &identity, &lease).err(),
            Some(Error::Scope)
        );
    }
    assert_eq!(f.outbox.inspect().unwrap().pending, 1);
}

#[test]
fn receipts_are_closed_bounded_and_cannot_acknowledge_another_body() {
    let dir = directory();
    let mut f = fixture(&dir);
    let lease = lease(&mut f);
    let signed = key().sign_event(&origin(), &f.identity, &lease).unwrap();
    let accepted = receipt(&signed);
    for field in accepted.as_object().unwrap().keys() {
        let mut missing = accepted.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(
            signed
                .verify_receipt(&serde_json::to_vec(&missing).unwrap())
                .err(),
            Some(Error::Receipt)
        );
        let mut changed = accepted.clone();
        changed[field] = json!("private-canary");
        assert_eq!(
            signed
                .verify_receipt(&serde_json::to_vec(&changed).unwrap())
                .err(),
            Some(Error::Receipt)
        );
    }
    let mut extra = accepted.clone();
    extra["metadata"] = json!({"secret":"private-canary"});
    let mut wrong = accepted.clone();
    wrong["event_id"] = json!(reference('a'));
    let mut version = accepted.clone();
    version["schema_version"] = json!(2);
    let mut digest = accepted.clone();
    digest["event_digest"] = json!("A".repeat(43));
    let text = serde_json::to_string(&accepted).unwrap();
    for bad in [
        serde_json::to_vec(&extra).unwrap(),
        serde_json::to_vec(&wrong).unwrap(),
        serde_json::to_vec(&version).unwrap(),
        serde_json::to_vec(&digest).unwrap(),
        text.replacen('{', "{\"schema_version\":1,", 1).into_bytes(),
        vec![b' '; MAX_EVENT_RECEIPT_BYTES + 1],
        b"null".to_vec(),
        b"[]".to_vec(),
        b"{broken private-canary".to_vec(),
    ] {
        let error = signed.verify_receipt(&bad).err().unwrap();
        assert_eq!(error, Error::Receipt);
        assert!(!error.to_string().contains("canary"));
    }
    assert_eq!(f.outbox.inspect().unwrap().pending, 1);
}
