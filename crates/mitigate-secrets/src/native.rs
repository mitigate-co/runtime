//! Deliberately narrow OS adapters. No default/global store or broad searches.
#[cfg(any(windows, target_os = "macos"))]
mod keyring;
#[cfg(any(windows, target_os = "macos"))]
pub(crate) use keyring::{delete, put, read};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{delete, put, read};

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod unsupported {
    use crate::{Error, Secret, SecretRef};
    pub async fn read(_: &SecretRef) -> Result<Secret, Error> {
        Err(Error::Unsupported)
    }
    pub async fn put(_: &SecretRef, _: Secret) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    pub async fn delete(_: &SecretRef) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub(crate) use unsupported::{delete, put, read};
