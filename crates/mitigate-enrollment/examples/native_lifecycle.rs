//! Opt-in synthetic native-store fixture. No network or customer credentials.
use mitigate_enrollment::{
    EnrollmentCode, PlatformOrigin,
    storage::{EnrollmentStore, Status},
};
use mitigate_secrets::{Secret, SecretRef};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

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
    let mut arguments = std::env::args_os().skip(1);
    require(
        arguments
            .next()
            .is_some_and(|a| a == "--allow-native-fixture"),
    )?;
    let cli = match arguments.next() {
        None => None,
        Some(flag) => {
            require(flag == "--cli")?;
            Some(PathBuf::from(
                arguments.next().ok_or("missing fixture executable")?,
            ))
        }
    };
    require(arguments.next().is_none())?;
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
    if let Some(cli) = &cli {
        check_cli(cli, &cleanup, "status", "pending")?;
    }
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
    if let Some(cli) = &cli {
        check_cli(cli, &cleanup, "status", "confirmed")?;
        // The deliberately nonexistent example host proves a confirmed retry
        // remains local instead of trying to resolve or contact Platform again.
        check_cli(cli, &cleanup, "retry", "confirmed")?;
    }
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
fn check_cli(
    cli: &Path,
    cleanup: &Cleanup,
    action: &str,
    status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(cli)
        .args([
            "enroll",
            action,
            "--platform",
            cleanup.origin.as_str(),
            "--state",
        ])
        .arg(&cleanup.path)
        .arg("--json")
        .stdin(std::process::Stdio::null())
        .output()?;
    require(output.status.success() && output.stderr.is_empty())?;
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    require(
        value["schema_version"] == 1 && value["status"] == status && value["sync_enabled"] == false,
    )?;
    if status == "confirmed" {
        require(value["enrolled_at_ms"] == 1790614800000u64)?;
    }
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
