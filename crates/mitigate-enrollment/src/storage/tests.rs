use super::*;
mod signing;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    path::PathBuf,
    rc::Rc,
};

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    BeforeWrite,
    AfterWrite,
    LostWrite,
    CorruptWrite,
    BeforeDelete,
    AfterDelete,
    LostDelete,
}
#[derive(Clone, Default)]
struct MemoryVault(Rc<Memory>);
#[derive(Default)]
struct Memory {
    values: RefCell<BTreeMap<String, Secret>>,
    fault: Cell<Fault>,
    reads: Cell<usize>,
    writes: Cell<usize>,
}
impl Vault for MemoryVault {
    fn read(&self, reference: &SecretRef) -> Result<Secret, mitigate_secrets::Error> {
        self.0.reads.set(self.0.reads.get() + 1);
        self.0
            .values
            .borrow()
            .get(reference.as_str())
            .ok_or(mitigate_secrets::Error::Missing)?
            .expose(|v| Secret::from_bytes(v.as_bytes().to_vec()))
    }
    fn put(&self, reference: &SecretRef, value: Secret) -> Result<(), mitigate_secrets::Error> {
        self.0.writes.set(self.0.writes.get() + 1);
        let fault = self.0.fault.take();
        if matches!(fault, Fault::BeforeWrite) {
            return Err(mitigate_secrets::Error::Unavailable);
        }
        if matches!(fault, Fault::LostWrite) {
            return Ok(());
        }
        let value = if matches!(fault, Fault::CorruptWrite) {
            secret("synthetic-corrupt-record")
        } else {
            value
        };
        self.0
            .values
            .borrow_mut()
            .insert(reference.as_str().to_owned(), value);
        if matches!(fault, Fault::AfterWrite) {
            Err(mitigate_secrets::Error::Unavailable)
        } else {
            Ok(())
        }
    }
    fn delete(&self, reference: &SecretRef) -> Result<(), mitigate_secrets::Error> {
        let fault = self.0.fault.take();
        if matches!(fault, Fault::BeforeDelete) {
            return Err(mitigate_secrets::Error::Unavailable);
        }
        if matches!(fault, Fault::LostDelete) {
            return Ok(());
        }
        self.0.values.borrow_mut().remove(reference.as_str());
        if matches!(fault, Fault::AfterDelete) {
            Err(mitigate_secrets::Error::Unavailable)
        } else {
            Ok(())
        }
    }
}
struct Fixture {
    dir: PathBuf,
    path: PathBuf,
    vault: MemoryVault,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mitigate-enrollment-{}",
            SecretRef::generate().unwrap().as_str()
        ));
        fs::create_dir(&dir).unwrap();
        Self {
            path: dir.join("enrollment"),
            dir,
            vault: MemoryVault::default(),
        }
    }
    fn create(&self) -> Result<Session<MemoryVault>, Error> {
        Session::create(&self.path, origin(), code(), self.vault.clone())
    }
    fn open(&self) -> Result<Session<MemoryVault>, Error> {
        Session::open(&self.path, &origin(), self.vault.clone())
    }
    fn forget(&self) -> Result<(), Error> {
        forget(&self.path, &origin(), self.vault.clone())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.dir);
    }
}
fn origin() -> PlatformOrigin {
    PlatformOrigin::parse("https://mitigate.example").unwrap()
}
fn secret(value: &str) -> Secret {
    Secret::from_bytes(value.as_bytes().to_vec()).unwrap()
}
fn code() -> EnrollmentCode {
    EnrollmentCode::from_secret(secret(&format!(
        "mcp1:00000000-0000-4000-8000-000000000001:{}",
        "A".repeat(43)
    )))
    .unwrap()
}
fn receipt(session: &Session<MemoryVault>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"schema_version":1,"enrollment":{
        "runtime_ref":session.record.identity.runtime_ref(),
        "enrollment_ref":session.record.identity.enrollment_ref(),
        "enrolled_at_ms":1790614800000u64,"status":"active"
    }}))
    .unwrap()
}
#[test]
fn pending_restart_preserves_proof_without_plaintext_secret_files() {
    let fixture = Fixture::new();
    let session = fixture.create().unwrap();
    assert_eq!(session.status(), Status::Pending);
    let claim = session.claim().unwrap();
    let key = session.record.key.to_secret().unwrap();
    let runtime_ref = session.record.identity.runtime_ref().as_str().to_owned();
    assert_eq!(fixture.create().err(), Some(Error::Exists));
    // Windows enforces the held byte-range lock even for unrelated reads.
    // Inspect the public file only after the enrollment operation releases it.
    drop(session);
    let anchor = fs::read_to_string(&fixture.path).unwrap();
    assert!(!anchor.contains("mcp1:"));
    assert!(!anchor.contains(&"A".repeat(43)));
    assert!(!key.expose(|seed| anchor.contains(seed)));
    assert!(!anchor.contains(&runtime_ref));
    let resumed = fixture.open().unwrap();
    assert_eq!(resumed.claim().unwrap().as_bytes(), claim.as_bytes());
    assert_eq!(fixture.vault.0.writes.get(), 1);
}
#[test]
fn confirmation_drops_bootstrap_token_and_restores_only_confirmed_state() {
    let fixture = Fixture::new();
    let session = fixture.create().unwrap();
    let seed = session.record.key.to_secret().unwrap();
    let bytes = receipt(&session);
    let session = session.confirm(&bytes).unwrap();
    assert_eq!(
        session.status(),
        Status::Confirmed {
            enrolled_at_ms: 1790614800000
        }
    );
    assert_eq!(session.claim().err(), Some(Error::Confirmed));
    let native = fixture.vault.read(&session.anchor.reference).unwrap();
    native.expose(|v| {
        assert!(!v.contains("mcp1:"));
        assert!(!v.contains(&"A".repeat(43)));
        assert!(seed.expose(|seed| v.contains(seed)));
    });
    drop(session);
    assert_eq!(
        fixture.open().unwrap().status(),
        Status::Confirmed {
            enrolled_at_ms: 1790614800000
        }
    );
}
#[test]
fn initial_write_failures_never_release_unconfirmed_pending_material() {
    for (fault, outcome) in [
        (Fault::BeforeWrite, Some(Error::Missing)),
        (Fault::AfterWrite, None),
        (Fault::LostWrite, Some(Error::Missing)),
        (Fault::CorruptWrite, Some(Error::Integrity)),
    ] {
        let fixture = Fixture::new();
        fixture.vault.0.fault.set(fault);
        assert!(fixture.create().is_err());
        assert!(fixture.path.is_file());
        if matches!(fault, Fault::AfterWrite) {
            let recovered = fixture.open().unwrap();
            let claim = recovered.claim().unwrap();
            drop(recovered);
            assert_eq!(
                fixture.open().unwrap().claim().unwrap().as_bytes(),
                claim.as_bytes()
            );
        } else {
            assert_eq!(fixture.open().err(), outcome);
        }
        assert_eq!(fixture.vault.0.writes.get(), 1);
        assert_eq!(fixture.create().err(), Some(Error::Exists));
    }
}
#[test]
fn interrupted_confirmation_reconciles_native_state_without_rotating_identity() {
    for fault in [Fault::BeforeWrite, Fault::AfterWrite, Fault::LostWrite] {
        let fixture = Fixture::new();
        let session = fixture.create().unwrap();
        let original = session.claim().unwrap();
        let bytes = receipt(&session);
        fixture.vault.0.fault.set(fault);
        assert!(session.confirm(&bytes).is_err());
        let recovered = fixture.open().unwrap();
        if matches!(fault, Fault::AfterWrite) {
            assert!(matches!(recovered.status(), Status::Confirmed { .. }));
            assert_eq!(recovered.claim().err(), Some(Error::Confirmed));
        } else {
            assert_eq!(recovered.status(), Status::Pending);
            assert_eq!(recovered.claim().unwrap().as_bytes(), original.as_bytes());
            assert!(recovered.confirm(&bytes).is_ok());
        }
    }
}
#[test]
fn bad_receipt_or_wrong_platform_cannot_mutate_persisted_state() {
    let fixture = Fixture::new();
    let session = fixture.create().unwrap();
    let before = session.claim().unwrap();
    assert_eq!(
        session.confirm(b"{\"secret\":\"synthetic-canary\"}").err(),
        Some(Error::Receipt)
    );
    assert_eq!(
        fixture.open().unwrap().claim().unwrap().as_bytes(),
        before.as_bytes()
    );
    let reads = fixture.vault.0.reads.get();
    let other = PlatformOrigin::parse("https://different.example").unwrap();
    assert_eq!(
        Session::open(&fixture.path, &other, fixture.vault.clone()).err(),
        Some(Error::Origin)
    );
    assert_eq!(
        forget(&fixture.path, &other, fixture.vault.clone()),
        Err(Error::Origin)
    );
    assert_eq!(fixture.vault.0.reads.get(), reads);
    assert_eq!(fixture.vault.0.writes.get(), 1);
}
#[test]
fn exclusive_lock_prevents_concurrent_open_forget_and_late_replacement() {
    let fixture = Fixture::new();
    let session = fixture.create().unwrap();
    assert_eq!(fixture.open().err(), Some(Error::Busy));
    assert_eq!(fixture.forget(), Err(Error::Busy));
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage::tests::external_lock_probe",
            "--ignored",
        ])
        .env("MITIGATE_ENROLLMENT_LOCK_PROBE", &fixture.path)
        .output()
        .unwrap();
    assert!(child.status.success(), "child lock check failed");
    drop(session);
    assert!(fixture.open().is_ok());
    fixture.forget().unwrap();
    assert_eq!(fixture.open().err(), Some(Error::Missing));
    assert_eq!(fixture.create().err(), Some(Error::Exists));
    fixture.forget().unwrap();
}
#[test]
#[ignore = "invoked as a child by the exclusive lock test"]
fn external_lock_probe() {
    let path = std::env::var_os("MITIGATE_ENROLLMENT_LOCK_PROBE").expect("fixture path");
    assert_eq!(
        Anchor::open(Path::new(&path), &origin()).err(),
        Some(Error::Busy)
    );
}
#[test]
fn forget_requires_observed_deletion_and_can_reconcile_uncertain_success() {
    for fault in [Fault::BeforeDelete, Fault::AfterDelete, Fault::LostDelete] {
        let fixture = Fixture::new();
        drop(fixture.create().unwrap());
        fixture.vault.0.fault.set(fault);
        assert_eq!(fixture.forget(), Err(Error::Storage));
        if matches!(fault, Fault::AfterDelete) {
            assert_eq!(fixture.open().err(), Some(Error::Missing));
        } else {
            assert!(fixture.open().is_ok());
        }
        fixture.forget().unwrap();
        assert_eq!(fixture.open().err(), Some(Error::Missing));
    }
}
#[test]
fn malformed_or_swapped_native_records_fail_closed_and_are_not_deleted() {
    let fixture = Fixture::new();
    let session = fixture.create().unwrap();
    let reference = session.anchor.reference.clone();
    let original = fixture.vault.read(&reference).unwrap();
    let seed = session.record.key.to_secret().unwrap();
    let enrollment_ref = session.record.identity.enrollment_ref().as_str().to_owned();
    let runtime_ref = session.record.identity.runtime_ref().as_str().to_owned();
    drop(session);
    let candidates = original.expose(|value| {
        vec![
            value.replace("local.v1", "local.v2"),
            value.replace("https://mitigate.example", "https://different.example"),
            value.replace(reference.as_str(), "sec_11111111111111111111111111111111"),
            value.replace("\npending\n", "\nunknown\n"),
            value.replace(&enrollment_ref, &runtime_ref),
            value.replace(&runtime_ref, "ref_invalid"),
            seed.expose(|seed| value.replace(seed, "invalid-seed-canary")),
            value.replace("mcp1:", "mcp2:"),
            format!("{value}extra\n"),
            value.trim_end().to_owned(),
            "x".repeat(769),
        ]
    });
    for candidate in candidates {
        fixture.vault.put(&reference, secret(&candidate)).unwrap();
        assert_eq!(fixture.open().err(), Some(Error::Integrity));
        assert_eq!(fixture.forget(), Err(Error::Integrity));
        assert!(fixture.vault.read(&reference).is_ok());
    }
    fixture.vault.put(&reference, original).unwrap();
    assert!(fixture.open().is_ok());
}
#[test]
fn confirmed_native_timestamps_require_canonical_bounded_integers() {
    let fixture = Fixture::new();
    let pending = fixture.create().unwrap();
    let bytes = receipt(&pending);
    let confirmed = pending.confirm(&bytes).unwrap();
    let reference = confirmed.anchor.reference.clone();
    let original = fixture.vault.read(&reference).unwrap();
    drop(confirmed);
    for time in [
        "-1",
        "01",
        "1e0",
        "1.0",
        "253402300800000",
        "18446744073709551616",
        "",
        " 1",
    ] {
        let changed = original.expose(|value| value.replace("1790614800000", time));
        fixture.vault.put(&reference, secret(&changed)).unwrap();
        assert_eq!(fixture.open().err(), Some(Error::Integrity));
    }
}
#[test]
fn damaged_anchors_and_nonprivate_paths_never_reach_native_storage() {
    let fixture = Fixture::new();
    drop(fixture.create().unwrap());
    let original = fs::read(&fixture.path).unwrap();
    let reads = fixture.vault.0.reads.get();
    for bytes in [
        vec![],
        vec![0xff],
        vec![b'x'; 385],
        [original.clone(), b"extra\n".to_vec()].concat(),
    ] {
        fs::write(&fixture.path, bytes).unwrap();
        assert!(fixture.open().is_err());
        assert_eq!(fixture.vault.0.reads.get(), reads);
    }
    fs::write(&fixture.path, &original).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(fixture.open().err(), Some(Error::Path));
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = fixture.dir.join("alias");
        symlink(&fixture.path, &link).unwrap();
        assert_eq!(
            Session::open(&link, &origin(), fixture.vault.clone()).err(),
            Some(Error::Path)
        );
        fs::remove_file(link).unwrap();
    }
    assert_eq!(fixture.vault.0.reads.get(), reads);
    assert!(fixture.open().is_ok());
}
#[test]
fn native_adapter_rejects_nested_async_execution_without_panicking() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let reference = SecretRef::generate().unwrap();
    runtime.block_on(async {
        assert_eq!(
            NativeVault.read(&reference).err(),
            Some(mitigate_secrets::Error::Unavailable)
        );
        let fixture = Fixture::new();
        assert_eq!(
            EnrollmentStore::create(&fixture.path, origin(), code()).err(),
            Some(Error::Storage)
        );
        assert!(!fixture.path.exists());
    });
}
