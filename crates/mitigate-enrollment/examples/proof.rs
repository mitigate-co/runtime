//! Public synthetic proof only. Does not read input, native storage or the network.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mitigate_enrollment::{EnrollmentCode, EnrollmentIdentity, EnrollmentKey, PlatformOrigin};
use mitigate_secrets::Secret;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = EnrollmentKey::from_secret(Secret::from_bytes(
        URL_SAFE_NO_PAD.encode([23; 32]).into_bytes(),
    )?)?;
    let code = EnrollmentCode::from_secret(Secret::from_bytes(
        format!(
            "mcp1:00000000-0000-4000-8000-000000000001:{}",
            URL_SAFE_NO_PAD.encode([41; 32])
        )
        .into_bytes(),
    )?)?;
    let identity = EnrollmentIdentity::from_references(
        serde_json::from_str("\"ref_11111111111111111111111111111111\"")?,
        serde_json::from_str("\"ref_22222222222222222222222222222222\"")?,
    )?;
    let claim = key.claim(
        &PlatformOrigin::parse("https://mitigate.example")?,
        &code,
        &identity,
    )?;
    // Only this hard-coded public fixture may be printed. Real claims contain a
    // bootstrap credential and must never be sent to logs, audit or telemetry.
    std::io::stdout().lock().write_all(claim.as_bytes())?;
    Ok(())
}
