//! Native enrollment lifecycle, serialized by one immutable local anchor file.
//! All operations are blocking and must run outside an async reactor. No network
//! calls, telemetry activation, plaintext secret persistence or automatic repair.
mod anchor;
mod native;
mod record;
#[cfg(test)]
mod tests;

use crate::{EnrollmentClaim, EnrollmentCode, EnrollmentIdentity, EnrollmentKey, PlatformOrigin};
use anchor::Anchor;
use mitigate_secrets::{Secret, SecretRef};
use native::NativeVault;
use record::{Phase, Record};
use std::{fmt, path::Path};

/// Fixed lifecycle failures, without input, filesystem or OS-provider details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An anchor already exists; inspect/recover it rather than replacing identity.
    Exists,
    /// Missing, nonprivate, unsupported or invalid anchor path.
    Path,
    /// Another process owns the same enrollment operation.
    Busy,
    /// Anchor or native record is malformed, inconsistent or unsupported.
    Integrity,
    /// The operator's selected Platform differs from the stored binding.
    Origin,
    /// The native enrollment was removed or initial persistence never completed.
    Missing,
    /// Native storage or a required durable operation failed or is uncertain.
    Storage,
    /// Key/reference generation failed before any request could be sent.
    Randomness,
    /// This enrollment already has a confirmed receipt; bootstrap is unavailable.
    Confirmed,
    /// Receipt does not confirm the current pending identity.
    Receipt,
    /// Event signing requires a durably confirmed enrollment receipt.
    Pending,
    /// The outbox lease belongs to a different Runtime or enrollment.
    Scope,
}
impl Error {
    /// Stable local diagnostic category; no path, credential or provider details.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Exists => "enrollment_exists",
            Self::Path => "enrollment_path",
            Self::Busy => "enrollment_busy",
            Self::Integrity => "enrollment_integrity",
            Self::Origin => "enrollment_origin",
            Self::Missing => "enrollment_missing",
            Self::Storage => "enrollment_storage",
            Self::Randomness => "enrollment_randomness",
            Self::Confirmed => "enrollment_confirmed",
            Self::Receipt => "enrollment_receipt",
            Self::Pending => "enrollment_pending",
            Self::Scope => "enrollment_scope",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Exists => "Enrollment state already exists. Check its status or retry the pending enrollment.",
            Self::Path => "Use an enrollment file in your private local state directory.",
            Self::Busy => "Another enrollment operation is running. Wait for it to finish, then retry.",
            Self::Integrity => "Enrollment state is invalid. Restore the matching local state and native credential.",
            Self::Origin => "The selected Platform does not match this enrollment. Use its original Platform.",
            Self::Missing => "The native enrollment is missing. Local MCP protection is unaffected.",
            Self::Storage => "Enrollment storage could not be confirmed. Unlock the native store and check enrollment status before retrying.",
            Self::Randomness => "Secure enrollment identity generation is unavailable.",
            Self::Confirmed => "This Runtime is already enrolled. Check its status instead of sending another code.",
            Self::Receipt => "Platform enrollment was not confirmed. Retry using the same pending enrollment.",
            Self::Pending => "Enrollment is still pending. Retry it before enabling sync.",
            Self::Scope => "The queued event belongs to another enrollment. Pause sync and check its configuration.",
        })
    }
}
impl std::error::Error for Error {}

/// Local receipt state only; neither ongoing remote authorization nor sync consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Secure pending material is available for the identical bootstrap retry.
    Pending,
    /// A matching receipt was durably read back from native storage.
    Confirmed {
        /// Informational server timestamp, not local clock authority.
        enrolled_at_ms: u64,
    },
}

/// One exclusively locked enrollment, with secrets in the OS-native broker.
/// No Clone/Debug/Serialize. Keep this owner alive through bootstrap transmission
/// and confirmation. Dropping it releases the lock, never deletes pending state.
pub struct EnrollmentStore(Session<NativeVault>);
impl EnrollmentStore {
    /// Create a new private anchor and native pending record before a claim can
    /// be obtained. Existing files are never overwritten, including damaged ones.
    pub fn create(
        path: &Path,
        origin: PlatformOrigin,
        code: EnrollmentCode,
    ) -> Result<Self, Error> {
        native::check_thread()?;
        Session::create(path, origin, code, NativeVault).map(Self)
    }
    /// Lock and restore the exact existing enrollment. Never regenerate a missing
    /// credential or silently switch its origin. Parent directory must be trusted.
    pub fn open(path: &Path, expected_origin: &PlatformOrigin) -> Result<Self, Error> {
        native::check_thread()?;
        Session::open(path, expected_origin, NativeVault).map(Self)
    }
    /// Locally persisted state, without secret material or invented online status.
    pub fn status(&self) -> Status {
        self.0.status()
    }
    /// Pinned destination restored from the immutable anchor/native record pair.
    pub fn origin(&self) -> &PlatformOrigin {
        &self.0.anchor.origin
    }
    /// Opaque references for this one enrollment, never machine/content identifiers.
    pub fn identity(&self) -> &EnrollmentIdentity {
        &self.0.record.identity
    }
    /// Build an identical retry only from a successfully restored pending record.
    /// Keep this store locked until the request and receipt handling finish.
    pub fn claim(&self) -> Result<EnrollmentClaim, Error> {
        self.0.claim()
    }
    /// Sign a checked lease using only the confirmed native key, identity and
    /// pinned origin. Keep this store locked through delivery. Local confirmation
    /// does not establish current remote authority, consent or lease validity.
    /// No network, credential mutation or automatic sync activation occurs here.
    pub fn sign_event(
        &self,
        lease: &mitigate_egress::outbox::Lease,
    ) -> Result<crate::event::SignedEvent, Error> {
        self.0.sign_event(lease)
    }
    /// After authenticated HTTPS, consume a matching receipt, remove the bootstrap
    /// token and verify native read-back. Failure consumes this session: reopen
    /// to reconcile an uncertain write before performing another operation.
    pub fn confirm(self, receipt: &[u8]) -> Result<Self, Error> {
        native::check_thread()?;
        self.0.confirm(receipt).map(Self)
    }
    /// Explicitly forget only this enrollment's native record, under its lock.
    /// Missing is idempotent; malformed/mismatched records are never deleted.
    /// Leaves the immutable anchor to prevent concurrent reuse. Does not revoke
    /// remote access or remove an outbox; the caller must stop/purge sync first.
    pub fn forget(path: &Path, expected_origin: &PlatformOrigin) -> Result<(), Error> {
        native::check_thread()?;
        forget(path, expected_origin, NativeVault)
    }
}

// The synchronous adapter keeps the file lock owned until native writes finish.
// A detached blocking worker cannot release its lock while an OS prompt/write is
// still active. The private trait is only a fault-injection seam for lifecycle tests.
trait Vault {
    fn read(&self, reference: &SecretRef) -> Result<Secret, mitigate_secrets::Error>;
    fn put(&self, reference: &SecretRef, value: Secret) -> Result<(), mitigate_secrets::Error>;
    fn delete(&self, reference: &SecretRef) -> Result<(), mitigate_secrets::Error>;
}
struct Session<V: Vault> {
    anchor: Anchor,
    record: Record,
    vault: V,
}
impl<V: Vault> Session<V> {
    fn create(
        path: &Path,
        origin: PlatformOrigin,
        code: EnrollmentCode,
        vault: V,
    ) -> Result<Self, Error> {
        let record = Record {
            key: EnrollmentKey::generate().map_err(|_| Error::Randomness)?,
            identity: EnrollmentIdentity::fresh().map_err(|_| Error::Randomness)?,
            phase: Phase::Pending(code),
        };
        let reference = SecretRef::generate().map_err(|_| Error::Randomness)?;
        // Anchor is flushed before the first native mutation, so even an uncertain
        // write leaves the exact recovery reference. A collision is never replaced.
        let anchor = Anchor::create(path, origin, reference)?;
        match vault.read(&anchor.reference) {
            Err(mitigate_secrets::Error::Missing) => (),
            _ => return Err(Error::Storage),
        }
        persist(&anchor, &record, &vault)?;
        Ok(Self {
            anchor,
            record,
            vault,
        })
    }
    fn open(path: &Path, origin: &PlatformOrigin, vault: V) -> Result<Self, Error> {
        let anchor = Anchor::open(path, origin)?;
        let secret = vault.read(&anchor.reference).map_err(vault_error)?;
        let record = Record::decode(secret, &anchor)?;
        Ok(Self {
            anchor,
            record,
            vault,
        })
    }
    fn status(&self) -> Status {
        match self.record.phase {
            Phase::Pending(_) => Status::Pending,
            Phase::Confirmed(enrolled_at_ms) => Status::Confirmed { enrolled_at_ms },
        }
    }
    fn claim(&self) -> Result<EnrollmentClaim, Error> {
        let Phase::Pending(code) = &self.record.phase else {
            return Err(Error::Confirmed);
        };
        self.record
            .key
            .claim(&self.anchor.origin, code, &self.record.identity)
            .map_err(|_| Error::Integrity)
    }
    fn confirm(mut self, bytes: &[u8]) -> Result<Self, Error> {
        let receipt = self
            .claim()?
            .verify_receipt(bytes)
            .map_err(|_| Error::Receipt)?;
        // Replacing the phase drops/zeroizes the code. The active native record
        // contains only the key, opaque identity and verified receipt timestamp.
        self.record.phase = Phase::Confirmed(receipt.enrolled_at_ms());
        persist(&self.anchor, &self.record, &self.vault)?;
        Ok(self)
    }
    fn sign_event(
        &self,
        lease: &mitigate_egress::outbox::Lease,
    ) -> Result<crate::event::SignedEvent, Error> {
        if !matches!(self.record.phase, Phase::Confirmed(_)) {
            return Err(Error::Pending);
        }
        self.record
            .key
            .sign_event(&self.anchor.origin, &self.record.identity, lease)
            .map_err(|error| match error {
                crate::event::Error::Scope => Error::Scope,
                _ => Error::Integrity,
            })
    }
}
fn persist(anchor: &Anchor, record: &Record, vault: &impl Vault) -> Result<(), Error> {
    let expected = record.encode(anchor)?;
    // Never report success merely because a write returned: read back this exact
    // record. If a provider fails after writing, reopening reconciles actual state.
    let value = record.encode(anchor)?;
    vault.put(&anchor.reference, value).map_err(vault_error)?;
    let restored = vault.read(&anchor.reference).map_err(vault_error)?;
    if !expected.expose(|left| restored.expose(|right| left == right)) {
        return Err(Error::Integrity);
    }
    Ok(())
}
fn forget(path: &Path, origin: &PlatformOrigin, vault: impl Vault) -> Result<(), Error> {
    let anchor = Anchor::open(path, origin)?;
    match vault.read(&anchor.reference) {
        Err(mitigate_secrets::Error::Missing) => return Ok(()),
        Err(e) => return Err(vault_error(e)),
        Ok(value) => {
            drop(Record::decode(value, &anchor)?);
        }
    }
    vault.delete(&anchor.reference).map_err(vault_error)?;
    match vault.read(&anchor.reference) {
        Err(mitigate_secrets::Error::Missing) => Ok(()),
        _ => Err(Error::Storage),
    }
}
fn vault_error(error: mitigate_secrets::Error) -> Error {
    match error {
        mitigate_secrets::Error::Missing => Error::Missing,
        _ => Error::Storage,
    }
}
