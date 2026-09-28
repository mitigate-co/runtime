use super::Vault;
use mitigate_secrets::{Error, NativeStore, Secret, SecretRef, SecretStore};
use std::{future::Future, time::Duration};

pub(super) struct NativeVault;
pub(super) fn check_thread() -> Result<(), super::Error> {
    if tokio::runtime::Handle::try_current().is_ok() {
        Err(super::Error::Storage)
    } else {
        Ok(())
    }
}
fn run<T>(operation: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
    // Nested block_on would panic. Require a synchronous caller or dedicated
    // blocking worker; management operations deliberately wait for native prompts.
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(Error::Unavailable);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .map_err(|_| Error::Unavailable)?;
    let result = runtime.block_on(operation);
    runtime.shutdown_timeout(Duration::from_millis(50));
    result
}
impl Vault for NativeVault {
    fn read(&self, reference: &SecretRef) -> Result<Secret, Error> {
        run(NativeStore.read(reference))
    }
    fn put(&self, reference: &SecretRef, value: Secret) -> Result<(), Error> {
        run(NativeStore.put(reference, value))
    }
    fn delete(&self, reference: &SecretRef) -> Result<(), Error> {
        run(NativeStore.delete(reference))
    }
}
