use crate::{Error, SERVICE, Secret, SecretRef};
use keyring_core::{Entry, api::CredentialStoreApi};

fn safe_error(error: keyring_core::Error) -> Error {
    // Do not use Display/Debug/source: keyring errors can embed rejected data.
    match error {
        keyring_core::Error::NoEntry => Error::Missing,
        _ => Error::Unavailable,
    }
}
fn entry(reference: &SecretRef) -> Result<Entry, Error> {
    #[cfg(windows)]
    let result = windows_native_keyring_store::Store::new().and_then(|store| {
        store.build(
            SERVICE,
            reference.as_str(),
            Some(&std::collections::HashMap::from([("persistence", "Local")])),
        )
    });
    #[cfg(target_os = "macos")]
    let result = apple_native_keyring_store::keychain::Store::new()
        .and_then(|store| store.build(SERVICE, reference.as_str(), None));
    result.map_err(safe_error)
}
pub async fn read(reference: &SecretRef) -> Result<Secret, Error> {
    let reference = reference.clone();
    // Native permission prompts must not block the relay's async reactor. If the
    // caller cancels, the completed value is dropped; this task cannot spawn an
    // upstream. OS calls themselves cannot be cancelled by dropping this handle.
    tokio::task::spawn_blocking(move || {
        Secret::from_bytes(entry(&reference)?.get_secret().map_err(safe_error)?)
    })
    .await
    .map_err(|_| Error::Unavailable)?
}
pub async fn put(reference: &SecretRef, secret: Secret) -> Result<(), Error> {
    let reference = reference.clone();
    tokio::task::spawn_blocking(move || {
        secret.expose(|s| {
            entry(&reference)?
                .set_secret(s.as_bytes())
                .map_err(safe_error)
        })
    })
    .await
    .map_err(|_| Error::Unavailable)?
}
pub async fn delete(reference: &SecretRef) -> Result<(), Error> {
    let reference = reference.clone();
    tokio::task::spawn_blocking(move || entry(&reference)?.delete_credential().map_err(safe_error))
        .await
        .map_err(|_| Error::Unavailable)?
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    #[ignore = "explicit native-store fixture; creates and deletes one synthetic entry"]
    fn native_windows_record_uses_local_persistence() {
        let reference = SecretRef::generate().unwrap();
        let record = entry(&reference).unwrap();
        assert!(matches!(
            record.get_secret(),
            Err(keyring_core::Error::NoEntry)
        ));
        record.set_secret(b"synthetic-persistence-fixture").unwrap();
        struct Cleanup(Entry);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.0.delete_credential();
            }
        }
        let cleanup = Cleanup(record);
        let attributes = cleanup.0.get_attributes().unwrap();
        assert!(attributes["persistence"].eq_ignore_ascii_case("local"));
        cleanup.0.delete_credential().unwrap();
        assert!(matches!(
            cleanup.0.get_secret(),
            Err(keyring_core::Error::NoEntry)
        ));
    }
}
