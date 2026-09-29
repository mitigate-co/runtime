//! Customer-local correlation keys mapped to independent random wire references.
//! This store is never a telemetry source or consent/identity authority. Only its
//! random outputs may enter an independently checked event. Local keys stay here.
mod database;
#[cfg(test)]
mod tests;

use crate::{
    SyncRef,
    outbox::{self, Partition, db},
};
use rusqlite::{Connection, TransactionBehavior, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
};

/// Hard per-enrollment bound. Full stores refuse new mappings without eviction.
pub const MAX_REFERENCES: usize = 8192;
/// One atomic resolution batch; larger requests are rejected before storage I/O.
pub const MAX_BATCH: usize = 16;

/// Domain separation prevents an identical local digest linking unrelated facts.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Kind {
    /// Explicitly declared client profile.
    Client,
    /// Explicitly declared principal.
    Principal,
    /// Explicitly declared agent.
    Agent,
    /// Reviewed server launch identity.
    Server,
    /// Server-scoped tool identity.
    Tool,
    /// Reviewed tool schema revision.
    Schema,
    /// Verified policy identity; version is a separate event field.
    Policy,
}

/// A local-only fixed-size correlation key. No display, serialization or logging.
/// Never construct this from raw arguments/results or matched sensitive values.
/// Call, approval and event IDs are fresh per-invocation references, not entries
/// in this durable catalog.
///
/// ```compile_fail
/// fn export_key(key: &mitigate_egress::references::LocalKey) {
///     let _ = serde_json::to_vec(key);
/// }
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalKey {
    kind: Kind,
    digest: [u8; 32],
}
impl LocalKey {
    /// Bind a trusted local identity/schema fingerprint to its closed domain.
    /// The digest is only a lookup key; random outputs never derive from its bits.
    pub const fn new(kind: Kind, digest: [u8; 32]) -> Self {
        Self { kind, digest }
    }
}

/// Fixed failures never include a local digest, path, SQL text or provider error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid batch or enrollment partition.
    Input,
    /// No capacity for all missing keys; no partial mappings are committed.
    Full,
    /// Independent secure randomness could not produce a unique reference.
    Randomness,
    /// Private file, schema, integrity, lock or durable commit failure.
    Storage(outbox::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Input => "Check the reference batch and original enrollment scope.",
            Self::Full => "Local reference capacity reached. Existing mappings are retained.",
            Self::Randomness => "Secure reference generation is unavailable.",
            Self::Storage(_) => "Local references could not be verified or committed. Preserve the store and retry after checking access.",
        })
    }
}
impl std::error::Error for Error {}
impl From<outbox::Error> for Error {
    fn from(value: outbox::Error) -> Self {
        Self::Storage(value)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value.into())
    }
}

/// Private durable mapping for exactly one runtime/enrollment partition.
/// Synchronous: use only on a dedicated metadata worker, never tool authorization.
/// No Clone/Debug/Serialize, generic export, raw JSON import or network capability.
pub struct ReferenceMap {
    conn: Connection,
    partition: Partition,
}
impl ReferenceMap {
    /// Create a new store after explicit sync consent. Parent directories must
    /// be trusted/private. Never overwrite, adopt an existing database or rotate
    /// references on failure. An interrupted creation may leave a partial file.
    pub fn create(path: &Path, partition: Partition) -> Result<Self, Error> {
        validate_partition(&partition)?;
        db::create_file(path)?;
        let mut conn = db::connect(path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        database::initialize(&tx, &partition)?;
        tx.commit()?;
        Ok(Self { conn, partition })
    }
    /// Open only an existing private file whose closed schema and every mapping
    /// match the separately supplied enrollment scope. Performs no repairs.
    pub fn open(path: &Path, partition: Partition) -> Result<Self, Error> {
        validate_partition(&partition)?;
        let mut result = Self {
            conn: db::connect(path)?,
            partition,
        };
        result.len()?;
        Ok(result)
    }
    /// Inspect the verified mapping count. No keys or mapping pairs are exposed.
    pub fn len(&mut self) -> Result<usize, Error> {
        let deadline = db::budget(&self.conn)?;
        let tx = self.conn.transaction()?;
        let rows = database::load(&tx, &self.partition, deadline)?;
        tx.commit()?;
        Ok(rows.len())
    }
    /// Whether this verified store has no mappings.
    pub fn is_empty(&mut self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }
    /// Atomically resolve one bounded batch, preserving input order/duplicates.
    /// Existing keys retain their reference across processes and restarts. New
    /// keys use independent OS randomness. Results are returned only after commit;
    /// an uncertain commit requires reopening rather than replacing the store.
    /// A full catalog still resolves known keys and never evicts stable identities.
    pub fn resolve(&mut self, keys: &[LocalKey]) -> Result<Vec<SyncRef>, Error> {
        if keys.is_empty() || keys.len() > MAX_BATCH {
            return Err(Error::Input);
        }
        let deadline = db::budget(&self.conn)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut rows = database::load(&tx, &self.partition, deadline)?;
        let missing = keys
            .iter()
            .filter(|key| !rows.contains_key(*key))
            .collect::<BTreeSet<_>>();
        if rows.len() + missing.len() > MAX_REFERENCES {
            return Err(Error::Full);
        }
        let mut used = rows.values().cloned().collect::<BTreeSet<_>>();
        used.insert(self.partition.runtime_ref.clone());
        used.insert(self.partition.enrollment_ref.clone());
        for key in missing {
            database::within_budget(deadline)?;
            let reference = fresh(&used)?;
            tx.execute(
                "INSERT INTO mappings VALUES(?1,?2,?3)",
                params![key.kind as u8, key.digest.as_slice(), reference.as_str()],
            )?;
            used.insert(reference.clone());
            rows.insert(key.clone(), reference);
        }
        let result = keys
            .iter()
            .map(|key| rows.get(key).cloned().ok_or(Error::Input))
            .collect::<Result<Vec<_>, _>>()?;
        database::within_budget(deadline)?;
        tx.commit()?;
        Ok(result)
    }
}
fn validate_partition(partition: &Partition) -> Result<(), Error> {
    if partition.runtime_ref == partition.enrollment_ref {
        Err(Error::Input)
    } else {
        Ok(())
    }
}
fn fresh(used: &BTreeSet<SyncRef>) -> Result<SyncRef, Error> {
    for _ in 0..8 {
        let reference = SyncRef::fresh().map_err(|_| Error::Randomness)?;
        if !used.contains(&reference) {
            return Ok(reference);
        }
    }
    Err(Error::Randomness)
}

type Rows = BTreeMap<LocalKey, SyncRef>;
