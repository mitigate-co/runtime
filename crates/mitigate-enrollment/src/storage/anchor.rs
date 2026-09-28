use super::Error;
use crate::PlatformOrigin;
use mitigate_secrets::SecretRef;
use std::{
    fs::{self, File, Metadata, OpenOptions, TryLockError},
    io::{Read, Write},
    ops::{Deref, DerefMut},
    path::Path,
};

const MAGIC: &str = "mitigate.enrollment.anchor.v1";
const MAX_ANCHOR: u64 = 384;
pub(super) struct Anchor {
    // Immutable inode: never unlink/replace while any operation can hold its lock.
    _file: LockedFile,
    pub origin: PlatformOrigin,
    pub reference: SecretRef,
}
struct LockedFile(File);
impl Deref for LockedFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.0
    }
}
impl DerefMut for LockedFile {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.0
    }
}
impl Drop for LockedFile {
    fn drop(&mut self) {
        // A concurrently spawned child can briefly inherit the open description
        // before close-on-exec. Release our operation's lock explicitly instead
        // of waiting for every inherited descriptor to close. Never pass this
        // handle to another operation that is expected to retain its lock.
        let _ = self.0.unlock();
    }
}
impl Anchor {
    pub fn create(
        path: &Path,
        origin: PlatformOrigin,
        reference: SecretRef,
    ) -> Result<Self, Error> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Exists
            } else {
                Error::Path
            }
        })?;
        let mut file = lock(file)?;
        validate(&file.metadata().map_err(|_| Error::Path)?)?;
        write!(
            file,
            "{MAGIC}\n{}\n{}\n",
            origin.as_str(),
            reference.as_str()
        )
        .map_err(|_| Error::Storage)?;
        file.sync_all().map_err(|_| Error::Storage)?;
        #[cfg(unix)]
        {
            // Persist the directory entry before creating a native credential.
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| Error::Storage)?;
        }
        Ok(Self {
            _file: file,
            origin,
            reference,
        })
    }
    pub fn open(path: &Path, origin: &PlatformOrigin) -> Result<Self, Error> {
        validate(&fs::symlink_metadata(path).map_err(|_| Error::Path)?)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| Error::Path)?;
        let mut file = lock(file)?;
        validate(&file.metadata().map_err(|_| Error::Path)?)?;
        let mut value = String::new();
        (&mut *file)
            .take(MAX_ANCHOR + 1)
            .read_to_string(&mut value)
            .map_err(|_| Error::Integrity)?;
        if value.len() > MAX_ANCHOR as usize {
            return Err(Error::Integrity);
        }
        let mut fields = value.split('\n');
        if fields.next() != Some(MAGIC) {
            return Err(Error::Integrity);
        }
        let stored = PlatformOrigin::parse(fields.next().ok_or(Error::Integrity)?)
            .map_err(|_| Error::Integrity)?;
        let reference = SecretRef::parse(fields.next().ok_or(Error::Integrity)?)
            .map_err(|_| Error::Integrity)?;
        if fields.next() != Some("") || fields.next().is_some() {
            return Err(Error::Integrity);
        }
        if &stored != origin {
            return Err(Error::Origin);
        }
        Ok(Self {
            _file: file,
            origin: stored,
            reference,
        })
    }
}
fn lock(file: File) -> Result<LockedFile, Error> {
    file.try_lock().map_err(|e| match e {
        TryLockError::WouldBlock => Error::Busy,
        TryLockError::Error(_) => Error::Storage,
    })?;
    Ok(LockedFile(file))
}
fn validate(meta: &Metadata) -> Result<(), Error> {
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_ANCHOR {
        return Err(Error::Path);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Path);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(Error::Path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn releasing_owner_unlocks_despite_an_inherited_description() {
        let dir = std::env::temp_dir().join(format!(
            "mitigate-anchor-{}",
            SecretRef::generate().unwrap().as_str()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("enrollment");
        let origin = PlatformOrigin::parse("https://mitigate.example").unwrap();
        let anchor = Anchor::create(&path, origin.clone(), SecretRef::generate().unwrap()).unwrap();
        let inherited = anchor._file.try_clone().unwrap();
        drop(anchor);
        let reopened = Anchor::open(&path, &origin);
        assert!(reopened.is_ok());
        drop(reopened);
        drop(inherited);
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
