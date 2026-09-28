//! Explicit local documents only. No directory traversal or automatic discovery.
use crate::Error;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub(crate) fn safe_file(path: &Path, max: u64, private: bool) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max {
        return Err(Error::Path);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(Error::Path);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Path);
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}
/// Read a bounded explicitly selected regular local document. No source errors
/// or paths escape. Protect its parent directory from other writers.
pub fn read_document(path: &Path, max: usize) -> Result<Vec<u8>, Error> {
    if max == 0 || max > 32_768 {
        return Err(Error::Input);
    }
    safe_file(path, max as u64, false)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| Error::Path)?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Path)?;
    if bytes.len() > max {
        return Err(Error::Path);
    }
    Ok(bytes)
}
/// Create a new local document exclusively, private on Unix/inherited ACL on
/// Windows. Never overwrite. Failure may leave a partial file for inspection.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > 32_768 {
        return Err(Error::Input);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| Error::Path)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::Storage)
}
