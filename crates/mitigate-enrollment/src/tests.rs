use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use mitigate_secrets::Secret;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const GRANT: &str = "00000000-0000-4000-8000-000000000001";
const ORIGIN: &str = "https://mitigate.example";
fn secret(value: &str) -> Secret {
    Secret::from_bytes(value.as_bytes().to_vec()).unwrap()
}
fn code() -> EnrollmentCode {
    EnrollmentCode::from_secret(secret(&format!(
        "mcp1:{GRANT}:{}",
        URL_SAFE_NO_PAD.encode([41; 32])
    )))
    .unwrap()
}
fn identity() -> EnrollmentIdentity {
    EnrollmentIdentity::from_references(
        serde_json::from_value(json!("ref_11111111111111111111111111111111")).unwrap(),
        serde_json::from_value(json!("ref_22222222222222222222222222222222")).unwrap(),
    )
    .unwrap()
}
fn claim() -> EnrollmentClaim {
    EnrollmentKey::from_secret(secret(&URL_SAFE_NO_PAD.encode([23; 32])))
        .unwrap()
        .claim(
            &PlatformOrigin::parse(ORIGIN).unwrap(),
            &code(),
            &identity(),
        )
        .unwrap()
}
fn receipt() -> Value {
    json!({"schema_version": 1, "enrollment": {"enrollment_ref":"ref_22222222222222222222222222222222", "runtime_ref":"ref_11111111111111111111111111111111", "enrolled_at_ms":1790614800000u64,"status":"active"}})
}

#[test]
fn code_accepts_only_canonical_bounded_secret_input() {
    let valid = format!("mcp1:{GRANT}:{}", "A".repeat(43));
    assert_eq!(
        EnrollmentCode::from_secret(secret(&valid))
            .unwrap()
            .grant_id(),
        GRANT
    );
    for bad in [
        valid.replace("mcp1:", "mcp2:"),
        valid.replace("-4000-", "-5000-"),
        valid.replace("-8000-", "-c000-"),
        format!("{valid}="),
        format!(" {valid}"),
        format!("{valid}\n"),
        valid[..84].to_owned(),
        format!("mcp1:{GRANT}:{}B", "A".repeat(42)),
        valid.replace(':', "/"),
        format!("mcp1:{GRANT}:{}+", "A".repeat(42)),
        "é".repeat(42) + "x",
        "secret-canary".to_owned(),
    ] {
        assert_eq!(
            EnrollmentCode::from_secret(secret(&bad)).err(),
            Some(Error::Code)
        );
    }
}

#[test]
fn origin_rejects_normalization_and_destination_ambiguity() {
    for valid in [
        ORIGIN,
        "https://mitigate.example:8443",
        "https://[::1]:8443",
    ] {
        assert_eq!(PlatformOrigin::parse(valid).unwrap().as_str(), valid);
    }
    for bad in [
        "http://mitigate.example",
        "https://mitigate.example/",
        "https://MITIGATE.example",
        "https://mitigate.example:443",
        "https://name:secret-canary@mitigate.example",
        "https://mitigate.example?token=secret-canary",
        "https://mitigate.example#secret-canary",
        " https://mitigate.example",
        "https://mitigate.example\n",
        "https://mitigate.example/path",
        "file:///private",
        "https://é.example",
        "https://*.mitigate.example",
    ] {
        assert_eq!(PlatformOrigin::parse(bad).err(), Some(Error::Origin));
    }
    assert_eq!(
        PlatformOrigin::parse(&format!("https://{}.example", "x".repeat(256))).err(),
        Some(Error::Origin)
    );
}

#[test]
fn signature_matches_an_independent_openssl_vector_and_binds_every_field() {
    let signed = claim();
    let value: Value = serde_json::from_slice(signed.as_bytes()).unwrap();
    let vector: Value =
        serde_json::from_slice(include_bytes!("../fixtures/enrollment-v1.json")).unwrap();
    assert_eq!(value, vector["claim"]);
    assert_eq!(signed.origin().as_str(), ORIGIN);
    assert_eq!(value.as_object().unwrap().len(), 6);
    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(value["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(value["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = VerifyingKey::from_bytes(&key_bytes).unwrap();
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest([41; 32]));
    let fields = [
        "mitigate.runtime.enrollment.v1",
        ORIGIN,
        GRANT,
        &digest,
        value["public_key"].as_str().unwrap(),
        identity().runtime_ref().as_str(),
        identity().enrollment_ref().as_str(),
    ]
    .map(str::to_owned);
    let transcript = format!("{}\n", fields.join("\n"));
    key.verify_strict(transcript.as_bytes(), &Signature::from_bytes(&signature))
        .unwrap();
    for i in 0..fields.len() {
        let mut changed = fields.clone();
        changed[i].push('x');
        assert!(
            key.verify_strict(
                format!("{}\n", changed.join("\n")).as_bytes(),
                &Signature::from_bytes(&signature)
            )
            .is_err()
        );
    }
    assert!(
        key.verify_strict(
            transcript.trim_end().as_bytes(),
            &Signature::from_bytes(&signature)
        )
        .is_err()
    );
}

#[test]
fn keys_and_references_restore_identical_claims_without_silent_rotation() {
    let key = EnrollmentKey::generate().unwrap();
    let restored = EnrollmentKey::from_secret(key.to_secret().unwrap()).unwrap();
    let origin = PlatformOrigin::parse(ORIGIN).unwrap();
    let identity = EnrollmentIdentity::fresh().unwrap();
    assert_ne!(
        identity.runtime_ref().as_str(),
        identity.enrollment_ref().as_str()
    );
    let first = key.claim(&origin, &code(), &identity).unwrap();
    let second = restored.claim(&origin, &code(), &identity).unwrap();
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_ne!(
        first.as_bytes(),
        EnrollmentKey::generate()
            .unwrap()
            .claim(&origin, &code(), &identity)
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        EnrollmentIdentity::from_references(
            identity.runtime_ref().clone(),
            identity.runtime_ref().clone()
        )
        .err()
        .map(|e| e == Error::Identity),
        Some(true)
    );
    for bad in [
        "secret-canary".to_owned(),
        "A".repeat(44),
        "A".repeat(42) + "B",
        "A".repeat(42) + "=",
    ] {
        assert_eq!(
            EnrollmentKey::from_secret(secret(&bad)).err(),
            Some(Error::Key)
        );
    }
}

#[test]
fn receipts_require_exact_binding_closed_shape_and_unambiguous_json() {
    let signed = claim();
    let valid = receipt();
    let received = signed
        .verify_receipt(&serde_json::to_vec(&valid).unwrap())
        .unwrap();
    assert_eq!(received.enrolled_at_ms(), 1790614800000);
    assert_eq!(
        received.runtime_ref().as_str(),
        identity().runtime_ref().as_str()
    );
    assert_eq!(
        received.enrollment_ref().as_str(),
        identity().enrollment_ref().as_str()
    );
    let mut candidates = Vec::new();
    for (field, bad) in [
        ("runtime_ref", json!("ref_33333333333333333333333333333333")),
        (
            "enrollment_ref",
            json!("ref_33333333333333333333333333333333"),
        ),
        ("status", json!("revoked")),
        ("enrolled_at_ms", json!(253402300800000u64)),
        ("enrolled_at_ms", json!(-1)),
        ("enrolled_at_ms", json!(1.5)),
        ("token", json!("secret-canary")),
        ("actor_id", json!(GRANT)),
    ] {
        let mut next = valid.clone();
        next["enrollment"][field] = bad;
        candidates.push(next);
    }
    let mut next = valid.clone();
    next["schema_version"] = json!(2);
    candidates.push(next);
    let mut next = valid.clone();
    next["secret-canary"] = json!("secret-canary");
    candidates.push(next);
    let mut next = valid.clone();
    next["enrollment"].as_object_mut().unwrap().remove("status");
    candidates.push(next);
    for candidate in candidates {
        assert_eq!(
            signed
                .verify_receipt(&serde_json::to_vec(&candidate).unwrap())
                .err(),
            Some(Error::Receipt)
        );
    }
    for bytes in [
        vec![0xff],
        vec![b' '; 1025],
        serde_json::to_string(&valid)
            .unwrap()
            .replace(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
            )
            .into_bytes(),
        serde_json::to_string(&valid)
            .unwrap()
            .replace("\"schema_version\":1", "\"schema_version\":1e0")
            .into_bytes(),
        serde_json::to_string(&valid)
            .unwrap()
            .replace("1790614800000", "1790614800000e0")
            .into_bytes(),
    ] {
        assert_eq!(signed.verify_receipt(&bytes).err(), Some(Error::Receipt));
    }
}

#[test]
fn errors_never_embed_rejected_input_and_proofs_are_not_telemetry() {
    for error in [
        Error::Code,
        Error::Origin,
        Error::Key,
        Error::Identity,
        Error::Randomness,
        Error::Receipt,
        Error::Encoding,
    ] {
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
    }
    assert!(mitigate_egress::CheckedEvent::from_bytes(claim().as_bytes()).is_err());
}
