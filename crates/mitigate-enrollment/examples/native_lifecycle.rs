//! Opt-in synthetic native-store fixture. No network or customer credentials.
use mitigate_egress::outbox::{Admission, Limits, Outbox, Partition};
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
        let _ = fs::remove_file(self.dir.join("outbox.sqlite"));
        let _ = fs::remove_file(self.dir.join("foreign.sqlite"));
        let _ = fs::remove_file(self.dir.join("sync.json"));
        let _ = fs::remove_file(self.dir.join("sync.sqlite"));
        let _ = fs::remove_file(self.dir.join("sync.sqlite.references.sqlite"));
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
    let (cli, capture_cli) = match arguments.next() {
        None => (None, None),
        Some(flag) => {
            require(flag == "--cli" || flag == "--capture-cli")?;
            let path = PathBuf::from(arguments.next().ok_or("missing fixture executable")?);
            (
                if flag == "--cli" {
                    Some(path.clone())
                } else {
                    None
                },
                Some(path),
            )
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
    let mut outbox = Outbox::create(
        &cleanup.dir.join("outbox.sqlite"),
        Partition {
            runtime_ref: pending.identity().runtime_ref().clone(),
            enrollment_ref: pending.identity().enrollment_ref().clone(),
        },
        Limits::default(),
    )?;
    let mut event: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../examples/egress/decision.json"))?;
    event["runtime_ref"] = serde_json::json!(pending.identity().runtime_ref());
    require(outbox.admit(&serde_json::to_vec(&event)?)? == Admission::Queued)?;
    #[cfg(feature = "https")]
    {
        require(
            mitigate_enrollment::event_https::deliver_next(&pending, &mut outbox).err()
                == Some(mitigate_enrollment::event_https::Error::Enrollment(
                    mitigate_enrollment::storage::Error::Pending,
                )),
        )?;
        require(outbox.inspect()?.leased == 0)?;
    }
    let lease = outbox.claim()?.ok_or("missing synthetic event")?;
    require(
        pending.sign_event(&lease).err() == Some(mitigate_enrollment::storage::Error::Pending),
    )?;
    #[cfg(feature = "https")]
    require(
        mitigate_enrollment::event_https::submit(&pending, &mut outbox, &lease).err()
            == Some(mitigate_enrollment::event_https::Error::Enrollment(
                mitigate_enrollment::storage::Error::Pending,
            )),
    )?;
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
    #[cfg(feature = "https")]
    {
        let mut foreign = Outbox::create(
            &cleanup.dir.join("foreign.sqlite"),
            Partition {
                runtime_ref: confirmed.identity().runtime_ref().clone(),
                enrollment_ref: mitigate_egress::SyncRef::fresh()?,
            },
            Limits::default(),
        )?;
        require(foreign.admit(&serde_json::to_vec(&event)?)? == Admission::Queued)?;
        require(
            mitigate_enrollment::event_https::deliver_next(&confirmed, &mut foreign).err()
                == Some(mitigate_enrollment::event_https::Error::Enrollment(
                    mitigate_enrollment::storage::Error::Scope,
                )),
        )?;
        require(foreign.inspect()?.leased == 0)?;
        outbox.purge()?;
        outbox.set_paused(false)?;
        require(outbox.admit(&serde_json::to_vec(&event)?)? == Admission::Queued)?;
        let current = outbox.claim()?.ok_or("missing synthetic event")?;
        outbox.set_paused(true)?;
        require(
            mitigate_enrollment::event_https::submit(&confirmed, &mut outbox, &current).err()
                == Some(mitigate_enrollment::event_https::Error::NotReady),
        )?;
        require(
            mitigate_enrollment::event_https::deliver_next(&confirmed, &mut outbox)?
                == mitigate_enrollment::event_https::Delivery::Idle,
        )?;
    }
    let signed = confirmed.sign_event(&lease)?;
    require(signed.origin().as_str() == cleanup.origin.as_str())?;
    drop(confirmed);
    let restored = EnrollmentStore::open(&cleanup.path, &cleanup.origin)?;
    require(
        restored.status()
            == Status::Confirmed {
                enrolled_at_ms: 1790614800000,
            },
    )?;
    require(restored.sign_event(&lease)?.as_bytes() == signed.as_bytes())?;
    require(outbox.inspect()?.pending == 1)?;
    drop(restored);
    if let Some(cli) = &cli {
        check_cli(cli, &cleanup, "status", "confirmed")?;
        // The deliberately nonexistent example host proves a confirmed retry
        // remains local instead of trying to resolve or contact Platform again.
        check_cli(cli, &cleanup, "retry", "confirmed")?;
    }
    let profile_path = cleanup.dir.join("sync.json");
    let sync_queue_path = cleanup.dir.join("sync.sqlite");
    let sync = if let Some(cli) = &cli {
        check_sync_cli(cli, &cleanup, "enable", "enabled")?;
        mitigate_enrollment::storage::sync::SyncProfile::open(&profile_path)?
    } else {
        mitigate_enrollment::storage::sync::SyncProfile::create(
            &profile_path,
            &cleanup.path,
            &cleanup.origin,
            &sync_queue_path,
            Limits::default(),
        )?
    };
    let mut sync_queue = Outbox::open(&sync_queue_path, sync.inspect()?.partition)?;
    require(sync_queue.admit(&serde_json::to_vec(&event)?)? == Admission::Queued)?;
    require(sync.pause()?.paused)?;
    require(!sync.resume()?.paused)?;
    require(sync.pause()?.paused)?;
    #[cfg(feature = "https")]
    require(sync.deliver_next()? == mitigate_enrollment::event_https::Delivery::Idle)?;
    if let Some(cli) = &cli {
        check_sync_cli(cli, &cleanup, "status", "paused")?;
        check_sync_cli(cli, &cleanup, "resume", "enabled")?;
        check_sync_cli(cli, &cleanup, "pause", "paused")?;
        check_sync_cli(cli, &cleanup, "send", "waiting")?;
        check_sync_cli(cli, &cleanup, "purge", "purged")?;
    }
    require(sync.purge()?.pending == 0)?;
    drop(sync_queue);
    if let Some(cli) = &capture_cli {
        require(!sync.resume()?.paused)?;
        let fixture = cli.with_file_name(if cfg!(windows) {
            "mitigate-test-mcp.exe"
        } else {
            "mitigate-test-mcp"
        });
        let output = Command::new(fixture)
            .arg("sync-capture-contract")
            .arg(cli)
            .arg(&profile_path)
            .stdin(std::process::Stdio::null())
            .output()?;
        if !output.status.success() {
            // This child has synthetic fixtures only; do not expose its raw diagnostics.
            return Err("actual CLI sync-capture fixture failed".into());
        }
        require(sync.inspect()?.paused && sync.inspect()?.pending == 0)?;
        println!("Actual CLI sync capture fixture passed.");
    }
    // Missing mapping state must never rotate identifiers or resume consent.
    // Shutdown/purge remain usable without this optional local catalog.
    let catalog = cleanup.dir.join("sync.sqlite.references.sqlite");
    fs::remove_file(&catalog)?;
    require(matches!(
        sync.resume(),
        Err(mitigate_enrollment::storage::sync::Error::References(_))
    ))?;
    require(sync.inspect()?.paused && !catalog.exists())?;
    require(sync.pause()?.paused)?;
    require(sync.purge()?.pending == 0)?;
    drop(mitigate_egress::references::ReferenceMap::create(
        &catalog,
        Partition {
            runtime_ref: mitigate_egress::SyncRef::fresh()?,
            enrollment_ref: mitigate_egress::SyncRef::fresh()?,
        },
    )?);
    require(matches!(
        sync.resume(),
        Err(mitigate_enrollment::storage::sync::Error::References(
            mitigate_egress::references::Error::Storage(mitigate_egress::outbox::Error::Partition)
        ))
    ))?;
    require(sync.inspect()?.paused)?;
    fs::remove_file(&catalog)?;
    // Preserve the legacy controller behavior with the same confirmed native
    // enrollment, without silently creating a new catalog for the old profile.
    let original_profile = fs::read(&profile_path)?;
    let mut legacy: serde_json::Value = serde_json::from_slice(&original_profile)?;
    legacy["schema_version"] = serde_json::json!(1);
    legacy
        .as_object_mut()
        .ok_or("invalid synthetic profile")?
        .remove("reference_file");
    fs::write(&profile_path, serde_json::to_vec(&legacy)?)?;
    let legacy = mitigate_enrollment::storage::sync::SyncProfile::open(&profile_path)?;
    require(!legacy.resume()?.paused)?;
    require(legacy.pause()?.paused && !catalog.exists())?;
    fs::write(&profile_path, original_profile)?;
    outbox.purge()?;
    drop(outbox);
    EnrollmentStore::forget(&cleanup.path, &cleanup.origin)?;
    require(
        sync.resume().err()
            == Some(mitigate_enrollment::storage::sync::Error::Enrollment(
                mitigate_enrollment::storage::Error::Missing,
            )),
    )?;
    require(sync.pause()?.paused)?;
    require(sync.purge()?.pending == 0)?;
    require(
        EnrollmentStore::open(&cleanup.path, &cleanup.origin).err()
            == Some(mitigate_enrollment::storage::Error::Missing),
    )?;
    EnrollmentStore::forget(&cleanup.path, &cleanup.origin)?;
    println!(
        "Native enrollment and sync verified: recovery, confirmed signing, consent, pause/drain, purge and exact deletion. No network requests."
    );
    Ok(())
}
fn check_sync_cli(
    cli: &Path,
    cleanup: &Cleanup,
    action: &str,
    status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(cli);
    command
        .args(["sync", action, "--profile"])
        .arg(cleanup.dir.join("sync.json"))
        .arg("--json");
    if action == "enable" {
        command
            .arg("--enrollment")
            .arg(&cleanup.path)
            .args(["--platform", cleanup.origin.as_str(), "--outbox"])
            .arg(cleanup.dir.join("sync.sqlite"));
    }
    if action == "purge" {
        command.arg("--confirm");
    }
    let output = command.stdin(std::process::Stdio::null()).output()?;
    require(output.status.success() && output.stderr.is_empty())?;
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    require(value["schema_version"] == 1 && value["status"] == status)?;
    if action == "pause" || action == "purge" {
        require(value["delivery_drained"] == true)?;
    }
    require(!String::from_utf8_lossy(&output.stdout).contains("sec_"))?;
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
        value["schema_version"] == 2
            && value["status"] == status
            && value["sync_status"] == "not_checked",
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
