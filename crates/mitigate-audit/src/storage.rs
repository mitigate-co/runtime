use crate::{CallContext, Error, Event, EventDetails};
use mitigate_fingerprint::canonicalize;
use rusqlite::{
    Connection, OpenFlags, TransactionBehavior, config::DbConfig, limits::Limit, params,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_EVENT: usize = 4096;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RECORDS: &str = "CREATE TABLE records (sequence INTEGER PRIMARY KEY, time_ms INTEGER NOT NULL, bytes INTEGER NOT NULL, payload TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL) STRICT";
const STATE: &str = "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), anchor_sequence INTEGER NOT NULL, anchor_hash TEXT NOT NULL, head_sequence INTEGER NOT NULL, head_hash TEXT NOT NULL, last_time_ms INTEGER NOT NULL, max_records INTEGER NOT NULL, max_age_seconds INTEGER NOT NULL, max_payload_bytes INTEGER NOT NULL, payload_bytes INTEGER NOT NULL) STRICT";

/// Persistent retention policy. Oldest records rotate as a contiguous prefix.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    /// Retained record limit, 1 through 100,000.
    pub max_records: u32,
    /// Maximum record age, 1 second through 365 days.
    pub max_age_seconds: u64,
    /// Encoded payload budget, 4 KiB through 64 MiB.
    pub max_payload_bytes: u64,
}
impl Default for Retention {
    fn default() -> Self {
        Self {
            max_records: 10_000,
            max_age_seconds: 30 * 86_400,
            max_payload_bytes: 16 * 1024 * 1024,
        }
    }
}
impl Retention {
    fn validate(self) -> Result<(), Error> {
        if !(1..=100_000).contains(&self.max_records)
            || !(1..=365 * 86_400).contains(&self.max_age_seconds)
            || !(4096..=64 * 1024 * 1024).contains(&self.max_payload_bytes)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Chain-bound record. This is a local export, not a Platform telemetry event.
#[derive(Clone, Serialize)]
pub struct Record {
    /// Monotonically increasing sequence; never reused after retention.
    pub sequence: u64,
    /// Digest of the preceding record or retention anchor.
    pub previous_hash: String,
    /// Domain-separated digest of sequence, previous hash and canonical event.
    pub hash: String,
    /// Closed local event.
    pub event: Event,
}
/// Verified bounded export. Pages reflect this read transaction's retained data.
#[derive(Serialize)]
pub struct Page {
    /// Export format version.
    pub schema_version: u32,
    /// Current prefix retention anchor; indicates records deliberately removed.
    pub anchor_sequence: u64,
    /// Digest at the retention anchor.
    pub anchor_hash: String,
    /// Current tail sequence, including rotated records.
    pub head_sequence: u64,
    /// Exported records, at most 250.
    pub records: Vec<Record>,
    /// Pass as `after` for the next page, if more records were observed.
    pub next_after: Option<u64>,
}
/// Result of a full retained-chain verification.
#[derive(Debug, Serialize)]
pub struct Verification {
    /// Report format version.
    pub schema_version: u32,
    /// Number of retained records.
    pub records: u64,
    /// Canonical encoded payload bytes currently retained.
    pub payload_bytes: u64,
    /// Last pruned sequence (zero for an unrotated database).
    pub anchor_sequence: u64,
    /// Digest of the last pruned record, or the genesis digest.
    pub anchor_hash: String,
    /// Tail sequence, even if all records have expired.
    pub head_sequence: u64,
    /// Digest of the last appended record, or the genesis digest.
    pub head_hash: String,
    /// Persisted retention policy.
    pub retention: Retention,
}
struct State {
    anchor: u64,
    anchor_hash: String,
    head: u64,
    head_hash: String,
    time: u64,
    retention: Retention,
    bytes: u64,
}
impl State {
    fn load(conn: &Connection) -> Result<Self, Error> {
        let state = conn.query_row("SELECT anchor_sequence,anchor_hash,head_sequence,head_hash,last_time_ms,max_records,max_age_seconds,max_payload_bytes,payload_bytes FROM state WHERE id=1", [], |r| {
            Ok(Self {
                anchor:read_u64(r,0)?,
                anchor_hash:r.get(1)?,
                head:read_u64(r,2)?,
                head_hash:r.get(3)?,
                time:read_u64(r,4)?,
                retention:Retention {
                    max_records:r.get(5)?,
                    max_age_seconds:read_u64(r,6)?,
                    max_payload_bytes:read_u64(r,7)?
                },
                bytes:read_u64(r,8)?,
            })
        }).map_err(read_error)?;
        state.retention.validate().map_err(|_| Error::Integrity)?;
        if state.anchor > state.head
            || state.head > 9_007_199_254_740_991
            || state.time > 9_007_199_254_740_991
            || state.bytes > state.retention.max_payload_bytes
            || !valid_hash(&state.anchor_hash)
            || !valid_hash(&state.head_hash)
            || (state.anchor == 0 && state.anchor_hash != GENESIS)
            || (state.head == 0 && state.head_hash != GENESIS)
        {
            return Err(Error::Integrity);
        }
        Ok(state)
    }
    fn save(&self, conn: &Connection) -> Result<(), Error> {
        if conn.execute("UPDATE state SET anchor_sequence=?1,anchor_hash=?2,head_sequence=?3,head_hash=?4,last_time_ms=?5,payload_bytes=?6 WHERE id=1",
            params![self.anchor as i64,self.anchor_hash,self.head as i64,self.head_hash,self.time as i64,self.bytes as i64])? != 1 { return Err(Error::Integrity); }
        Ok(())
    }
}

/// Synchronous bounded local storage. Async compositions should use a blocking
/// worker; never hold this across upstream awaits. No SQL connection is exposed.
pub struct AuditStore {
    conn: Connection,
    data_version: i64,
}
impl AuditStore {
    /// Create exclusively. A pre-existing path is never erased or repurposed.
    pub fn create(path: &Path, retention: Retention) -> Result<Self, Error> {
        retention.validate()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| Error::Path)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        drop(file);
        // Leave any failed initialization intact for explicit operator recovery.
        let mut conn = connect(path)?;
        conn.execute_batch("PRAGMA page_size=4096; PRAGMA auto_vacuum=FULL;")?;
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(RECORDS)?;
        transaction.execute_batch(STATE)?;
        transaction.execute(
            "INSERT INTO state VALUES (1,0,?1,0,?1,0,?2,?3,?4,0)",
            params![
                GENESIS,
                retention.max_records,
                retention.max_age_seconds as i64,
                retention.max_payload_bytes as i64
            ],
        )?;
        transaction.execute_batch("PRAGMA user_version=1;")?;
        transaction.commit()?;
        let mut store = Self {
            conn,
            data_version: 0,
        };
        store.verify()?;
        Ok(store)
    }
    /// Open an existing private database and verify its schema and entire chain.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let conn = connect(path)?;
        let mut store = Self {
            conn,
            data_version: 0,
        };
        store.verify()?;
        Ok(store)
    }
    /// Verify under a consistent read transaction; never silently repairs data.
    pub fn verify(&mut self) -> Result<Verification, Error> {
        budget(&self.conn)?;
        let tx = self.conn.transaction()?;
        let result = verify(&tx)?;
        let version = data_version(&tx)?;
        tx.commit()?;
        self.data_version = version;
        Ok(result)
    }
    /// Durably append and rotate in one immediate transaction. On error no event
    /// ID is returned; do not treat an uncertain I/O outcome as permission to act.
    pub fn append(&mut self, detail: EventDetails) -> Result<Record, Error> {
        self.append_at(detail, now()?)
    }
    /// Append version-two governed-call metadata in the existing verified chain.
    /// A dispatch record is evidence of authorization, never proof of effects.
    /// Failure returns no durable receipt and gives no permission to invoke.
    pub fn append_call(
        &mut self,
        detail: EventDetails,
        call: CallContext,
    ) -> Result<Record, Error> {
        self.append_event_at(detail, Some(call), now()?)
    }
    pub(crate) fn append_at(&mut self, detail: EventDetails, time: u64) -> Result<Record, Error> {
        self.append_event_at(detail, None, time)
    }
    pub(crate) fn append_event_at(
        &mut self,
        detail: EventDetails,
        call: Option<CallContext>,
        time: u64,
    ) -> Result<Record, Error> {
        detail.validate()?;
        if let Some(context) = &call {
            context.validate(&detail)?;
        }
        budget(&self.conn)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        schema(&tx)?;
        let version = data_version(&tx)?;
        // A second legitimate writer is supported, but its changes must be
        // verified before this handle extends or rotates their chain.
        if version != self.data_version {
            verify(&tx)?;
        }
        let mut state = State::load(&tx)?;
        let time = time.max(state.time);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Error::Unavailable)?;
        let event = Event {
            schema_version: if call.is_some() { 2 } else { 1 },
            event_id: random.iter().map(|b| format!("{b:02x}")).collect(),
            time_ms: time,
            detail,
            call,
        };
        event.validate()?;
        let payload = canonicalize(&serde_json::to_value(&event).map_err(|_| Error::InvalidInput)?)
            .map_err(|_| Error::InvalidInput)?;
        if payload.len() > MAX_EVENT {
            return Err(Error::InvalidInput);
        }
        let sequence = state
            .head
            .checked_add(1)
            .filter(|v| *v <= 9_007_199_254_740_991)
            .ok_or(Error::Unavailable)?;
        let hash = digest(sequence, &state.head_hash, &payload);
        let record = Record {
            sequence,
            previous_hash: state.head_hash.clone(),
            hash: hash.clone(),
            event,
        };
        let payload = std::str::from_utf8(&payload).map_err(|_| Error::InvalidInput)?;
        tx.execute(
            "INSERT INTO records VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                sequence as i64,
                time as i64,
                payload.len() as i64,
                payload,
                record.previous_hash,
                hash
            ],
        )?;
        state.head = sequence;
        state.head_hash = hash;
        state.time = time;
        state.bytes += payload.len() as u64;
        rotate(&tx, &mut state)?;
        state.save(&tx)?;
        tx.commit()?;
        self.data_version = version;
        Ok(record)
    }
    /// Apply stored age/count/byte retention now. This is an explicit deletion
    /// operation and cannot be undone; returns the count of removed records.
    pub fn prune(&mut self) -> Result<u64, Error> {
        self.prune_at(now()?)
    }
    pub(crate) fn prune_at(&mut self, time: u64) -> Result<u64, Error> {
        budget(&self.conn)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify(&tx)?;
        let mut state = State::load(&tx)?;
        state.time = time.max(state.time);
        if state.time > 9_007_199_254_740_991 {
            return Err(Error::InvalidInput);
        }
        let old = state.anchor;
        rotate(&tx, &mut state)?;
        state.save(&tx)?;
        let removed = state.anchor - old;
        let version = data_version(&tx)?;
        tx.commit()?;
        self.data_version = version;
        Ok(removed)
    }
    /// Verify then return up to 250 records after a sequence. A reader can see
    /// retention advance between pages; anchor_sequence makes that gap explicit.
    pub fn page(&mut self, after: u64, limit: u32) -> Result<Page, Error> {
        if after > 9_007_199_254_740_991 || !(1..=250).contains(&limit) {
            return Err(Error::InvalidInput);
        }
        budget(&self.conn)?;
        let tx = self.conn.transaction()?;
        let verified = verify(&tx)?;
        let mut records = Vec::new();
        {
            let mut statement=tx.prepare("SELECT sequence,time_ms,bytes,payload,previous_hash,hash FROM records WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?;
            let mut rows = statement.query(params![after as i64, limit + 1])?;
            while let Some(row) = rows.next()? {
                records.push(decode(row)?.0);
            }
        }
        let next_after = if records.len() > limit as usize {
            records.pop();
            records.last().map(|r| r.sequence)
        } else {
            None
        };
        tx.commit()?;
        Ok(Page {
            schema_version: 1,
            anchor_sequence: verified.anchor_sequence,
            anchor_hash: verified.anchor_hash,
            head_sequence: verified.head_sequence,
            records,
            next_after,
        })
    }
}
fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Unavailable)
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(sequence: u64, previous: &str, payload: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"mitigate-local-audit-chain-v1\0");
    hash.update(sequence.to_be_bytes());
    hash.update(previous.as_bytes());
    hash.update([0]);
    hash.update(payload);
    format!("{:x}", hash.finalize())
}
fn data_version(conn: &Connection) -> Result<i64, Error> {
    Ok(conn.query_row("PRAGMA data_version", [], |r| r.get(0))?)
}
fn budget(conn: &Connection) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(5);
    conn.progress_handler(1000, Some(move || Instant::now() >= deadline))?;
    Ok(())
}
fn connect(path: &Path) -> Result<Connection, Error> {
    // Native build environment overrides must not silently select an older
    // system library lacking the reviewed journal/corruption fixes.
    if rusqlite::version_number() < 3_053_004 {
        return Err(Error::Unavailable);
    }
    let metadata = path.symlink_metadata().map_err(|_| Error::Path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_FILE {
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
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Path);
        }
    }
    // An absolute filesystem path also prevents SQLite's special ":memory:"
    // filename from silently replacing durable storage with a transient database.
    let absolute = path.canonicalize().map_err(|_| Error::Path)?;
    let conn = Connection::open_with_flags(
        absolute,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| Error::Path)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, 16_384),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 16_384),
        (Limit::SQLITE_LIMIT_COLUMN, 32),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 32),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VDBE_OP, 100_000),
    ] {
        conn.set_limit(limit, value)?;
    }
    conn.busy_timeout(Duration::from_millis(250))?;
    budget(&conn)?;
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048;")?;
    let page_size: u64 = conn.query_row("PRAGMA page_size", [], |r| read_u64(r, 0))?;
    if !(512..=65_536).contains(&page_size) {
        return Err(Error::Integrity);
    }
    let maximum: u64 = conn.query_row(
        &format!("PRAGMA max_page_count={}", MAX_FILE / page_size),
        [],
        |r| read_u64(r, 0),
    )?;
    if maximum > MAX_FILE / page_size {
        return Err(Error::Integrity);
    }
    Ok(conn)
}
fn schema(conn: &Connection) -> Result<(), Error> {
    let vacuum: u32 = conn
        .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .map_err(read_error)?;
    if vacuum != 1 {
        return Err(Error::Integrity);
    }
    let version: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(read_error)?;
    if version != 1 {
        return Err(Error::Integrity);
    }
    let mut statement = conn
        .prepare("SELECT name,sql FROM sqlite_schema ORDER BY name")
        .map_err(read_error)?;
    let mut rows = statement.query([]).map_err(read_error)?;
    for (name, sql) in [("records", RECORDS), ("state", STATE)] {
        let row = rows.next().map_err(read_error)?.ok_or(Error::Integrity)?;
        if row.get::<_, String>(0).map_err(read_error)? != name
            || row.get::<_, String>(1).map_err(read_error)? != sql
        {
            return Err(Error::Integrity);
        }
    }
    if rows.next().map_err(read_error)?.is_some() {
        return Err(Error::Integrity);
    }
    let count: u64 = conn
        .query_row("SELECT count(*) FROM state", [], |r| read_u64(r, 0))
        .map_err(read_error)?;
    if count != 1 {
        return Err(Error::Integrity);
    }
    Ok(())
}
fn decode(row: &rusqlite::Row<'_>) -> Result<(Record, usize), Error> {
    let sequence: u64 = read_u64(row, 0).map_err(|_| Error::Integrity)?;
    let time: u64 = read_u64(row, 1).map_err(|_| Error::Integrity)?;
    let size: usize = read_u64(row, 2)
        .map_err(|_| Error::Integrity)?
        .try_into()
        .map_err(|_| Error::Integrity)?;
    let payload: String = row.get(3).map_err(|_| Error::Integrity)?;
    let previous_hash: String = row.get(4).map_err(|_| Error::Integrity)?;
    let hash: String = row.get(5).map_err(|_| Error::Integrity)?;
    if payload.len() > MAX_EVENT
        || size != payload.len()
        || !valid_hash(&previous_hash)
        || !valid_hash(&hash)
    {
        return Err(Error::Integrity);
    }
    let value = mitigate_json::parse(payload.as_bytes()).map_err(|_| Error::Integrity)?;
    if canonicalize(&value).map_err(|_| Error::Integrity)? != payload.as_bytes() {
        return Err(Error::Integrity);
    }
    let event: Event = serde_json::from_value(value).map_err(|_| Error::Integrity)?;
    event.validate().map_err(|_| Error::Integrity)?;
    if event.time_ms != time || digest(sequence, &previous_hash, payload.as_bytes()) != hash {
        return Err(Error::Integrity);
    }
    Ok((
        Record {
            sequence,
            previous_hash,
            hash,
            event,
        },
        size,
    ))
}
fn verify(conn: &Connection) -> Result<Verification, Error> {
    schema(conn)?;
    let state = State::load(conn)?;
    let mut last = state.anchor;
    let mut hash = state.anchor_hash.clone();
    let mut count = 0u64;
    let mut bytes = 0u64;
    let mut time = 0u64;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut statement=conn.prepare("SELECT sequence,time_ms,bytes,payload,previous_hash,hash FROM records ORDER BY sequence").map_err(read_error)?;
    let mut rows = statement.query([]).map_err(read_error)?;
    while let Some(row) = rows.next().map_err(read_error)? {
        let (record, size) = decode(row)?;
        count += 1;
        bytes += size as u64;
        if count > u64::from(state.retention.max_records)
            || bytes > state.retention.max_payload_bytes
            || record.sequence != last + 1
            || record.previous_hash != hash
            || record.event.time_ms < time
            || record.event.time_ms > state.time
        {
            return Err(Error::Integrity);
        }
        if Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        last = record.sequence;
        hash = record.hash;
        time = record.event.time_ms;
    }
    if last != state.head || hash != state.head_hash || bytes != state.bytes {
        return Err(Error::Integrity);
    }
    Ok(Verification {
        schema_version: 1,
        records: count,
        payload_bytes: bytes,
        anchor_sequence: state.anchor,
        anchor_hash: state.anchor_hash,
        head_sequence: state.head,
        head_hash: state.head_hash,
        retention: state.retention,
    })
}
fn rotate(conn: &Connection, state: &mut State) -> Result<(), Error> {
    // Contiguous verified sequences and a transactional byte counter avoid
    // scanning every retained payload on each append. Full verification checks
    // both counters against actual rows before this handle trusts other writers.
    let mut count = state.head - state.anchor;
    let mut bytes = state.bytes;
    let cutoff = state
        .time
        .saturating_sub(state.retention.max_age_seconds * 1000);
    {
        let mut statement =
            conn.prepare("SELECT sequence,time_ms,bytes,hash FROM records ORDER BY sequence")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let time = read_u64(row, 1)?;
            if count <= u64::from(state.retention.max_records)
                && bytes <= state.retention.max_payload_bytes
                && time >= cutoff
            {
                break;
            }
            let size = read_u64(row, 2)?;
            state.anchor = read_u64(row, 0)?;
            state.anchor_hash = row.get(3)?;
            count = count.checked_sub(1).ok_or(Error::Integrity)?;
            bytes = bytes.checked_sub(size).ok_or(Error::Integrity)?;
        }
    }
    conn.execute(
        "DELETE FROM records WHERE sequence<=?1",
        [state.anchor as i64],
    )?;
    state.bytes = bytes;
    Ok(())
}
fn read_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn read_error(error: rusqlite::Error) -> Error {
    use rusqlite::ErrorCode;
    // A timeout or I/O failure is not evidence that the retained chain is corrupt.
    match error.sqlite_error_code() {
        Some(
            ErrorCode::DatabaseBusy
            | ErrorCode::DatabaseLocked
            | ErrorCode::OperationInterrupted
            | ErrorCode::SystemIoFailure
            | ErrorCode::OutOfMemory
            | ErrorCode::CannotOpen
            | ErrorCode::PermissionDenied
            | ErrorCode::DiskFull
            | ErrorCode::ReadOnly,
        ) => Error::Unavailable,
        _ => Error::Integrity,
    }
}

#[cfg(test)]
mod disk_tests {
    use super::*;
    use crate::Operation;
    use mitigate_fingerprint::{Domain, fingerprint};
    use mitigate_gateway::CallerIdentity;

    #[test]
    fn full_database_rolls_back_append_and_preserves_verifiable_history() {
        assert_eq!(rusqlite::version_number(), 3_053_004);
        let path =
            std::env::temp_dir().join(format!("mitigate-audit-full-{}.sqlite", std::process::id()));
        let mut store = AuditStore::create(&path, Retention::default()).unwrap();
        let pages: i64 = store
            .conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        store
            .conn
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        let detail = EventDetails::new(
            &CallerIdentity::default(),
            fingerprint(Domain::ServerIdentity, &serde_json::json!("fixture")).unwrap(),
            Operation::Inventory,
        );
        let mut written = 0;
        loop {
            match store.append(detail.clone()) {
                Ok(_) => {
                    written += 1;
                    assert!(written < 100, "page limit must be enforced");
                }
                Err(error) => {
                    assert_eq!(error, Error::Unavailable);
                    break;
                }
            }
        }
        assert_eq!(store.verify().unwrap().records, written);
        drop(store);
        let mut reopened = AuditStore::open(&path).unwrap();
        assert_eq!(reopened.verify().unwrap().records, written);
        assert_eq!(reopened.append(detail).unwrap().sequence, written + 1);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
}
