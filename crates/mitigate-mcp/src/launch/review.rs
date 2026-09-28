//! Explicit local launch review. Raw configuration/environment never serialize.
use super::LaunchConfig;
use crate::{Error, Result};
use mitigate_fingerprint::{Domain, Fingerprint, fingerprint};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const PROFILE: &str = "mitigate-local-launch-v1";
const MAX_REVIEW: usize = 8192;
const MAX_FILE: u64 = 268_435_456;
const MAX_TOTAL: u64 = 536_870_912;

/// An explicit local review, not an authorization or authenticated publisher.
/// The salt is local-only. This document is not a Platform telemetry event.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchReview {
    schema_version: u32,
    profile: String,
    salt: Fingerprint,
    launch_ref: Fingerprint,
    executable_sha256: Fingerprint,
    artifact_sha256: Vec<Fingerprint>,
}
/// Content-free local launch evidence. Never includes paths, argv, environment
/// values, the review salt or native credential values. Not automatic telemetry.
#[derive(Clone, Serialize)]
pub struct LaunchReceipt {
    /// Version one.
    pub schema_version: u32,
    /// Versioned review profile.
    pub profile: &'static str,
    /// Exact salted launch binding, suitable for local grant/server references.
    pub launch_ref: Fingerprint,
    /// SHA-256 of the explicitly selected executable bytes.
    pub executable_sha256: Fingerprint,
    /// Number of additional explicitly selected code/lockfile artifacts.
    pub artifact_count: usize,
}
impl LaunchReview {
    /// Fingerprint explicitly selected code and current launch environment.
    /// Does not execute code, discover files, contact servers or read credentials.
    pub async fn create(config: &LaunchConfig) -> Result<Self> {
        let config = config.clone();
        blocking(move |cancel| {
            let mut bytes = [0; 32];
            getrandom::fill(&mut bytes).map_err(|_| Error::LaunchReview)?;
            let salt = hex(&bytes)?;
            let (review, _) = inspect(&config, salt, cancel)?;
            Ok(review)
        })
        .await
    }
    /// Recompute the complete binding without executing code or consuming a grant.
    pub async fn check(&self, config: &LaunchConfig) -> Result<LaunchReceipt> {
        Ok(self.prepare(config).await?.verified.receipt)
    }
    /// Local diagnostic evidence, excluding the salt and configuration contents.
    pub fn receipt(&self) -> LaunchReceipt {
        LaunchReceipt {
            schema_version: 1,
            profile: PROFILE,
            launch_ref: self.launch_ref.clone(),
            executable_sha256: self.executable_sha256.clone(),
            artifact_count: self.artifact_sha256.len(),
        }
    }
    /// Parse the private bounded review format, rejecting ambiguous fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REVIEW {
            return Err(Error::LaunchReview);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::LaunchReview)?;
        let review: Self = serde_json::from_value(value).map_err(|_| Error::LaunchReview)?;
        review.validate()?;
        Ok(review)
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.profile != PROFILE || self.artifact_sha256.len() > 32 {
            return Err(Error::LaunchReview);
        }
        Ok(())
    }
    /// Read an explicitly selected private regular review file. Protect its parent.
    pub fn from_file(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::LaunchReview)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_REVIEW as u64
        {
            return Err(Error::LaunchReview);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::LaunchReview);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(Error::LaunchReview);
            }
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Error::LaunchReview)?
            .take((MAX_REVIEW + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::LaunchReview)?;
        Self::from_bytes(&bytes)
    }
    /// Write a new private review exclusively. Existing reviews are never replaced.
    pub fn write_new(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::LaunchReview)?;
        if bytes.len() > MAX_REVIEW {
            return Err(Error::LaunchReview);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|_| Error::LaunchReview)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::LaunchReview)
    }
    pub(crate) async fn prepare(&self, config: &LaunchConfig) -> Result<PreparedLaunch> {
        self.validate()?;
        let config = config.clone();
        let expected = self.clone();
        blocking(move |cancel| {
            let (current, prepared) = inspect(&config, expected.salt.clone(), cancel)?;
            if current.launch_ref != expected.launch_ref
                || current.executable_sha256 != expected.executable_sha256
                || current.artifact_sha256 != expected.artifact_sha256
            {
                return Err(Error::LaunchChanged);
            }
            Ok(prepared)
        })
        .await
    }
}

pub(crate) struct PreparedLaunch {
    pub executable: PathBuf,
    pub cwd: PathBuf,
    pub environment: BTreeMap<String, OsString>,
    pub verified: VerifiedLaunch,
}
#[derive(Clone)]
pub(crate) struct VerifiedLaunch {
    pub receipt: LaunchReceipt,
    files: Vec<FilePin>,
}
#[derive(Clone)]
struct FilePin {
    requested: PathBuf,
    resolved: PathBuf,
    sha256: Fingerprint,
}
impl VerifiedLaunch {
    pub async fn check_files(&self) -> Result<()> {
        let files = self.files.clone();
        blocking(move |cancel| {
            let mut total = 0;
            for pin in files {
                if fs::canonicalize(&pin.requested).map_err(|_| Error::LaunchChanged)?
                    != pin.resolved
                    || hash_file(&pin.resolved, &mut total, cancel)? != pin.sha256
                {
                    return Err(Error::LaunchChanged);
                }
            }
            Ok(())
        })
        .await
    }
}
fn inspect(
    config: &LaunchConfig,
    salt: Fingerprint,
    cancel: &AtomicBool,
) -> Result<(LaunchReview, PreparedLaunch)> {
    config.validate()?;
    let (executable, cwd) = config.paths()?;
    let environment = config.environment()?;
    let mut total = 0;
    let executable_sha256 = hash_file(&executable, &mut total, cancel)?;
    let mut files = vec![FilePin {
        requested: config.executable_path.clone().into(),
        resolved: executable.clone(),
        sha256: executable_sha256.clone(),
    }];
    let mut seen = BTreeSet::from([executable.clone()]);
    let mut artifacts = Vec::new();
    let mut artifact_sha256 = Vec::new();
    for requested in &config.artifact_paths {
        let path = fs::canonicalize(requested).map_err(|_| Error::LaunchReview)?;
        if !seen.insert(path.clone()) {
            return Err(Error::LaunchReview);
        }
        let hash = hash_file(&path, &mut total, cancel)?;
        artifacts.push(json!({"requested":requested,"resolved":text_path(&path)?,"sha256":hash}));
        artifact_sha256.push(hash.clone());
        files.push(FilePin {
            requested: requested.into(),
            resolved: path,
            sha256: hash,
        });
    }
    // Credential VALUES are intentionally absent. Rotation at the same native
    // reference is allowed; changing the target reference invalidates review.
    let secrets: BTreeMap<_, _> = config
        .secret_references
        .iter()
        .map(|s| (&s.environment_key, &s.secret_ref))
        .collect();
    let mut env = BTreeMap::new();
    for (key, value) in &environment {
        env.insert(key, value.to_str().ok_or(Error::Environment)?);
    }
    let allowed: BTreeSet<_> = config.allowed_environment_keys.iter().collect();
    let facts = json!({"profile":PROFILE,"salt":salt,"schema_version":config.schema_version,"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "executable_path":config.executable_path,"executable_resolved":text_path(&executable)?,"executable_sha256":executable_sha256,
        "working_directory":config.working_directory,"cwd_resolved":text_path(&cwd)?,"argv":config.argv,
        "environment":env,"allowed_environment_keys":allowed,"secret_references":secrets,"timeout_ms":config.timeout_ms,"artifacts":artifacts});
    let launch_ref =
        fingerprint(Domain::LaunchConfiguration, &facts).map_err(|_| Error::LaunchReview)?;
    let review = LaunchReview {
        schema_version: 1,
        profile: PROFILE.into(),
        salt,
        launch_ref,
        executable_sha256,
        artifact_sha256,
    };
    let verified = VerifiedLaunch {
        receipt: review.receipt(),
        files,
    };
    Ok((
        review,
        PreparedLaunch {
            executable,
            cwd,
            environment,
            verified,
        },
    ))
}
fn text_path(path: &Path) -> Result<&str> {
    path.to_str().ok_or(Error::LaunchReview)
}
fn hex(bytes: &[u8]) -> Result<Fingerprint> {
    let text: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    serde_json::from_value(json!(text)).map_err(|_| Error::LaunchReview)
}
fn hash_file(path: &Path, total: &mut u64, cancel: &AtomicBool) -> Result<Fingerprint> {
    if cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    // Refuse devices/directories/FIFOs before opening. The protected local
    // directory remains the boundary against a privileged replacement race.
    let selected = fs::metadata(path).map_err(|_| Error::LaunchReview)?;
    if !selected.is_file()
        || selected.len() == 0
        || selected.len() > MAX_FILE
        || total.saturating_add(selected.len()) > MAX_TOTAL
    {
        return Err(Error::LaunchReview);
    }
    let mut file = File::open(path).map_err(|_| Error::LaunchReview)?;
    let before = file.metadata().map_err(|_| Error::LaunchReview)?;
    if !before.is_file()
        || before.len() == 0
        || before.len() > MAX_FILE
        || total.saturating_add(before.len()) > MAX_TOTAL
    {
        return Err(Error::LaunchReview);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 65_536];
    let mut read = 0;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let count = file.read(&mut buffer).map_err(|_| Error::LaunchReview)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > before.len() || total.saturating_add(read) > MAX_TOTAL {
            return Err(Error::LaunchChanged);
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|_| Error::LaunchReview)?;
    if read != before.len()
        || after.len() != before.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(Error::LaunchChanged);
    }
    *total += read;
    hex(&digest.finalize())
}
async fn blocking<T: Send + 'static>(
    operation: impl FnOnce(&AtomicBool) -> Result<T> + Send + 'static,
) -> Result<T> {
    struct Cancel(Arc<AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let cancel = Cancel(Arc::new(AtomicBool::new(false)));
    let worker = Arc::clone(&cancel.0);
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || operation(&worker)),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|_| Error::LaunchReview)?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn dropped_review_signals_blocking_worker_before_it_continues() {
        use std::{
            future::{Future, poll_fn},
            sync::mpsc::sync_channel,
            task::Poll,
            time::Duration,
        };
        let (started_tx, started_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let (done_tx, done_rx) = sync_channel(1);
        let mut work = Box::pin(blocking(move |cancel| {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            done_tx.send(cancel.load(Ordering::Relaxed)).unwrap();
            Ok(())
        }));
        poll_fn(|cx| {
            assert!(work.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(work);
        release_tx.send(()).unwrap();
        assert!(done_rx.recv_timeout(Duration::from_secs(5)).unwrap());
    }
}
