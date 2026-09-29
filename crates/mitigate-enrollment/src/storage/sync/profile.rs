use super::Error;
use crate::PlatformOrigin;
use mitigate_egress::outbox::Partition;
use mitigate_secrets::SecretRef;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub schema_version: u8,
    pub platform: String,
    pub enrollment_file: PathBuf,
    pub outbox_file: PathBuf,
    pub native_reference: String,
    pub partition: Partition,
}
impl Record {
    pub fn validate(&self) -> Result<PlatformOrigin, Error> {
        if self.schema_version != 1
            || !self.enrollment_file.is_absolute()
            || !self.outbox_file.is_absolute()
            || self.enrollment_file == self.outbox_file
            || self.partition.runtime_ref == self.partition.enrollment_ref
            || SecretRef::parse(&self.native_reference).is_err()
        {
            return Err(Error::Profile);
        }
        PlatformOrigin::parse(&self.platform).map_err(|_| Error::Profile)
    }
}
pub(super) fn new_path(path: &Path) -> Result<PathBuf, Error> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or(Error::Profile)?;
    Ok(parent
        .canonicalize()
        .map_err(|_| Error::Profile)?
        .join(name))
}
pub(super) fn read(path: &Path) -> Result<Record, Error> {
    validate(&fs::symlink_metadata(path).map_err(|_| Error::Profile)?)?;
    let file = File::open(path).map_err(|_| Error::Profile)?;
    validate(&file.metadata().map_err(|_| Error::Profile)?)?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Profile)?;
    if bytes.len() > MAX_BYTES as usize {
        return Err(Error::Profile);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::Profile)
}
pub(super) fn encode(record: &Record) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(record).map_err(|_| Error::Profile)?;
    if bytes.len() > MAX_BYTES as usize {
        return Err(Error::Profile);
    }
    Ok(bytes)
}
pub(super) fn reserve(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Exists
        } else {
            Error::Storage
        }
    })?;
    validate(&file.metadata().map_err(|_| Error::Storage)?)?;
    Ok(file)
}
pub(super) fn finish(mut file: File, path: &Path, bytes: &[u8]) -> Result<(), Error> {
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::Storage)?;
    #[cfg(unix)]
    File::open(path.parent().ok_or(Error::Profile)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::Storage)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn validate(meta: &Metadata) -> Result<(), Error> {
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_BYTES {
        return Err(Error::Profile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Profile);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(Error::Profile);
        }
    }
    Ok(())
}
