//! Opt-in synthetic native-store fixture. No network or customer credentials.
use mitigate_enrollment::{
    EnrollmentCode, PlatformOrigin,
    storage::{EnrollmentStore, Status},
};
use mitigate_secrets::{Secret, SecretRef};
use std::{fs, path::PathBuf, process::ExitCode};

struct Cleanup {
    path: PathBuf,
    dir: PathBuf,
    origin: PlatformOrigin,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.path.exists() && EnrollmentStore::forget(&self.path, &self.origin).is_err() {
            eprintln!(
                "Synthetic enrollment cleanup could not be confirmed; its private anchor was retained."
            );
            return;
        }
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.dir);
    }
}
fn require(value: bool) -> Result<(), Box<dyn std::error::Error>> {
    if value {
        Ok(())
    } else {
        Err("synthetic enrollment check failed".into())
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    require(std::env::args().skip(1).eq(["--allow-native-fixture"]))?;
    let origin = PlatformOrigin::parse("https://mitigate.example")?;
    let dir = std::env::temp_dir().join(format!(
        "mitigate-native-enrollment-{}",
        SecretRef::generate()?.as_str()
    ));
    fs::create_dir(&dir)?;
    let cleanup = Cleanup {
        path: dir.join("enrollment"),
        dir,
        origin,
    };
    let code = EnrollmentCode::from_secret(Secret::from_bytes(
        format!(
            "mcp1:00000000-0000-4000-8000-000000000001:{}",
            "A".repeat(43)
        )
        .into_bytes(),
    )?)?;
    let pending = EnrollmentStore::create(&cleanup.path, cleanup.origin.clone(), code)?;
    require(pending.status() == Status::Pending)?;
    let first = pending.claim()?;
    drop(pending);
    let restored = EnrollmentStore::open(&cleanup.path, &cleanup.origin)?;
    require(first.as_bytes() == restored.claim()?.as_bytes())?;
    let receipt = serde_json::to_vec(&serde_json::json!({"schema_version":1,"enrollment":{
        "runtime_ref":restored.identity().runtime_ref(),
        "enrollment_ref":restored.identity().enrollment_ref(),
        "enrolled_at_ms":1790614800000u64,"status":"active"
    }}))?;
    let confirmed = restored.confirm(&receipt)?;
    require(confirmed.claim().is_err())?;
    drop(confirmed);
    let restored = EnrollmentStore::open(&cleanup.path, &cleanup.origin)?;
    require(
        restored.status()
            == Status::Confirmed {
                enrolled_at_ms: 1790614800000,
            },
    )?;
    drop(restored);
    EnrollmentStore::forget(&cleanup.path, &cleanup.origin)?;
    require(
        EnrollmentStore::open(&cleanup.path, &cleanup.origin).err()
            == Some(mitigate_enrollment::storage::Error::Missing),
    )?;
    EnrollmentStore::forget(&cleanup.path, &cleanup.origin)?;
    println!(
        "Native enrollment verified: pending restart, identical proof, confirmed restart and exact deletion. No network requests."
    );
    Ok(())
}
fn main() -> ExitCode {
    if run().is_ok() {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "Native enrollment fixture failed. Use --allow-native-fixture with an unlocked native credential store."
        );
        ExitCode::from(2)
    }
}
