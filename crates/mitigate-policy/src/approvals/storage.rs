//! Bounded SQLite mailbox shared by the local gateway and operator CLI.
use super::*;
use crate::Clock;
use crate::files::{safe_file, write_new};
use rusqlite::{
    Connection, OpenFlags, TransactionBehavior, config::DbConfig, limits::Limit, params,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

const ROWS: usize = 256;
const RETENTION_MS: u64 = 86_400_000;
const APPROVALS: &str = "CREATE TABLE approvals (reference TEXT PRIMARY KEY, record BLOB NOT NULL) STRICT, WITHOUT ROWID";
const CLOCK: &str =
    "CREATE TABLE clock (id INTEGER PRIMARY KEY CHECK(id=1), last_time INTEGER NOT NULL) STRICT";
type Records = BTreeMap<Fingerprint, Record>;

/// Private local approval storage. Use a blocking worker from asynchronous code.
/// Atomic transitions and a persistent nondecreasing clock prevent ordinary
/// replay/races. A privileged attacker replacing the whole DB is out of scope.
pub struct ApprovalStore {
    conn: Connection,
}
impl ApprovalStore {
    /// Exclusively create a store; never overwrite or repair an existing file.
    pub fn create(path: &Path) -> Result<Self, Error> {
        write_new(path, &[]).map_err(|_| Error::Path)?;
        let mut conn = connect(path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(APPROVALS)?;
        tx.execute_batch(CLOCK)?;
        tx.execute_batch("INSERT INTO clock VALUES(1,0); PRAGMA user_version=1;")?;
        tx.commit()?;
        Ok(Self { conn })
    }
    /// Open and verify existing state. Missing/corrupt files are never recreated.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut conn = connect(path)?;
        let tx = conn.transaction()?;
        read(&tx)?;
        tx.commit()?;
        Ok(Self { conn })
    }
    /// Create a request valid for 100–300,000 milliseconds. The gateway must use
    /// fresh session/call references, hold arguments in memory and bound its wait.
    pub fn request(
        &mut self,
        binding: Binding,
        clock: impl Clock,
        ttl_ms: u64,
    ) -> Result<Record, Error> {
        let binding = binding.normalized()?;
        if !(100..=MAX_TTL).contains(&ttl_ms) {
            return Err(Error::Input);
        }
        let reference = fresh_reference()?;
        self.update(clock, |records, now| {
            let expires_at_ms = now
                .checked_add(ttl_ms)
                .filter(|t| *t <= MAX_TIME)
                .ok_or(Error::Input)?;
            if records.contains_key(&reference)
                || records.values().any(|r| {
                    r.binding.session_ref == binding.session_ref
                        && r.binding.call_ref == binding.call_ref
                })
            {
                return Err(Error::Input);
            }
            if records.len() >= ROWS {
                let oldest = records
                    .iter()
                    .filter(|(_, r)| !r.state.active())
                    .min_by_key(|(key, r)| (r.updated_at_ms, (*key).clone()))
                    .map(|(key, _)| key.clone())
                    .ok_or(Error::Capacity)?;
                records.remove(&oldest);
            }
            let record = Record {
                schema_version: 1,
                approval_ref: reference.clone(),
                binding,
                state: State::Requested,
                created_at_ms: now,
                expires_at_ms,
                updated_at_ms: now,
                decisions: Vec::new(),
                cancellation: None,
            };
            records.insert(reference, record.clone());
            Ok(record)
        })
    }
    /// List the bounded store after applying expiry/retention. No raw tool data.
    pub fn list(&mut self, clock: impl Clock) -> Result<Vec<Record>, Error> {
        self.update(clock, |records, _| Ok(records.values().cloned().collect()))
    }
    /// Inspect one request after applying expiry; never consume it.
    pub fn get(&mut self, reference: &Fingerprint, clock: impl Clock) -> Result<Record, Error> {
        self.update(clock, |records, _| {
            records.get(reference).cloned().ok_or(Error::Missing)
        })
    }
    /// Approve only a requested call, or deny/revoke a requested/approved call.
    /// Explicit operator attribution is declared, not authenticated by this API.
    pub fn decide(
        &mut self,
        reference: &Fingerprint,
        choice: Choice,
        operator: Fingerprint,
        clock: impl Clock,
    ) -> Result<Record, Error> {
        self.update(clock, |records, now| {
            let record = records.get_mut(reference).ok_or(Error::Missing)?;
            if record.state != State::Requested
                && !(choice == Choice::Deny && record.state == State::Approved)
            {
                return Err(Error::State);
            }
            record.decisions.push(LocalDecision {
                operator_ref: operator,
                source: OperatorSource::DeclaredLocal,
                choice,
                time_ms: now,
            });
            record.state = match choice {
                Choice::Approve => State::Approved,
                Choice::Deny => State::Denied,
            };
            record.updated_at_ms = now;
            Ok(record.clone())
        })
    }
    /// Cancel on caller withdrawal or context/session change. Terminal requests
    /// stay terminal. Cancellation never resurrects or consumes an approval.
    pub fn cancel(
        &mut self,
        reference: &Fingerprint,
        reason: Cancellation,
        clock: impl Clock,
    ) -> Result<Record, Error> {
        self.update(clock, |records, now| {
            let record = records.get_mut(reference).ok_or(Error::Missing)?;
            cancel(record, reason, now);
            Ok(record.clone())
        })
    }
    /// Recheck all binding facts, expiry and state, then commit one consumption
    /// before returning a permit. Failure/uncertain commit yields no permit.
    /// Never retry a call automatically after consumption, even after a crash.
    pub fn consume(
        &mut self,
        reference: &Fingerprint,
        current: &Binding,
        clock: impl Clock,
    ) -> Result<Consumption, Error> {
        let current = current.clone().normalized()?;
        self.update(clock, |records, now| {
            let record = records.get_mut(reference).ok_or(Error::Missing)?;
            if record.binding != current {
                cancel(record, Cancellation::ContextChanged, now);
            }
            match record.state {
                State::Requested => Ok(Consumption::Pending),
                State::Approved => {
                    let operator = record
                        .decisions
                        .last()
                        .ok_or(Error::Storage)?
                        .operator_ref
                        .clone();
                    record.state = State::Consumed;
                    record.updated_at_ms = now;
                    Ok(Consumption::Ready(Permit {
                        reference: reference.clone(),
                        operator,
                    }))
                }
                state => Ok(Consumption::Unavailable(state)),
            }
        })
    }
    fn update<T>(
        &mut self,
        clock: impl Clock,
        operation: impl FnOnce(&mut Records, u64) -> Result<T, Error>,
    ) -> Result<T, Error> {
        budget(&self.conn)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (last_time, original) = read(&tx)?;
        let now = clock
            .now_ms()
            .filter(|t| *t <= MAX_TIME)
            .ok_or(Error::Clock)?;
        if now < last_time {
            return Err(Error::Clock);
        }
        let mut records = original.clone();
        for record in records.values_mut() {
            if record.state.active() && now >= record.expires_at_ms {
                record.state = State::Expired;
                record.updated_at_ms = now;
            }
        }
        records
            .retain(|_, r| r.state.active() || now.saturating_sub(r.updated_at_ms) < RETENTION_MS);
        // Persist observed expiry even when an operator attempts an invalid
        // transition. A later clock rollback cannot revive that observation.
        let result = operation(&mut records, now);
        for key in original.keys().filter(|k| !records.contains_key(*k)) {
            tx.execute("DELETE FROM approvals WHERE reference=?1", [key.as_str()])?;
        }
        for (key, record) in &records {
            if original.get(key) != Some(record) {
                record.validate().map_err(|_| Error::Storage)?;
                let bytes = serde_json::to_vec(record).map_err(|_| Error::Storage)?;
                if bytes.len() > MAX_RECORD {
                    return Err(Error::Storage);
                }
                tx.execute("INSERT INTO approvals VALUES(?1,?2) ON CONFLICT(reference) DO UPDATE SET record=excluded.record", params![key.as_str(),bytes])?;
            }
        }
        tx.execute("UPDATE clock SET last_time=?1 WHERE id=1", [now as i64])?;
        tx.commit()?;
        result
    }
}
fn cancel(record: &mut Record, reason: Cancellation, now: u64) {
    if record.state.active() {
        record.state = State::Cancelled;
        record.cancellation = Some(reason);
        record.updated_at_ms = now;
    }
}
fn connect(path: &Path) -> Result<Connection, Error> {
    safe_file(path, 2_097_152, true).map_err(|_| Error::Path)?;
    if rusqlite::version_number() < 3_053_004 {
        return Err(Error::Storage);
    }
    let conn = Connection::open_with_flags(
        path.canonicalize().map_err(|_| Error::Path)?,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(Duration::from_millis(250))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, 8192)?;
    conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 4096)?;
    conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 16)?;
    conn.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 16)?;
    conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
    conn.set_limit(Limit::SQLITE_LIMIT_VDBE_OP, 10_000)?;
    budget(&conn)?;
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-512; PRAGMA max_page_count=512;")?;
    if conn.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))? != 4096 {
        return Err(Error::Storage);
    }
    Ok(conn)
}
fn budget(conn: &Connection) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(2);
    conn.progress_handler(100, Some(move || Instant::now() >= deadline))?;
    Ok(())
}
fn read(conn: &Connection) -> Result<(u64, Records), Error> {
    budget(conn)?;
    if conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(Error::Storage);
    }
    let mut statement = conn.prepare("SELECT name,sql FROM sqlite_schema ORDER BY name")?;
    let mut schema = statement.query([])?;
    for (name, sql) in [("approvals", APPROVALS), ("clock", CLOCK)] {
        let row = schema.next()?.ok_or(Error::Storage)?;
        if row.get::<_, String>(0)? != name || row.get::<_, String>(1)? != sql {
            return Err(Error::Storage);
        }
    }
    if schema.next()?.is_some() {
        return Err(Error::Storage);
    }
    if conn.query_row("SELECT count(*) FROM clock", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(Error::Storage);
    }
    let clock: i64 = conn.query_row("SELECT last_time FROM clock WHERE id=1", [], |r| r.get(0))?;
    if clock < 0 || clock as u64 > MAX_TIME {
        return Err(Error::Storage);
    }
    let mut statement =
        conn.prepare("SELECT reference,record FROM approvals ORDER BY reference LIMIT 257")?;
    let mut rows = statement.query([])?;
    let mut records = Records::new();
    let mut calls = BTreeSet::new();
    while let Some(row) = rows.next()? {
        if records.len() >= ROWS {
            return Err(Error::Storage);
        }
        let reference: String = row.get(0)?;
        let bytes: Vec<u8> = row.get(1)?;
        if bytes.len() > MAX_RECORD {
            return Err(Error::Storage);
        }
        let value = mitigate_json::parse(&bytes).map_err(|_| Error::Storage)?;
        let object = value.as_object().ok_or(Error::Storage)?;
        if !object.contains_key("cancellation") {
            return Err(Error::Storage);
        }
        let binding = value.get("binding").ok_or(Error::Storage)?;
        if !["principal", "agent", "environment"]
            .iter()
            .all(|k| binding.get(*k).is_some())
        {
            return Err(Error::Storage);
        }
        let record: Record = serde_json::from_value(value).map_err(|_| Error::Storage)?;
        record.validate().map_err(|_| Error::Storage)?;
        if record.approval_ref.as_str() != reference || record.updated_at_ms > clock as u64 {
            return Err(Error::Storage);
        }
        if !calls.insert((
            record.binding.session_ref.clone(),
            record.binding.call_ref.clone(),
        )) {
            return Err(Error::Storage);
        }
        records.insert(record.approval_ref.clone(), record);
    }
    Ok((clock as u64, records))
}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        // Retain only reviewed categories, never backend text, SQL or paths.
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy
            }
            Some(rusqlite::ErrorCode::OperationInterrupted) => Self::Interrupted,
            _ => Self::Storage,
        }
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    #[test]
    fn sqlite_categories_discard_all_backend_diagnostics() {
        for (code, expected) in [
            (rusqlite::ffi::SQLITE_BUSY, Error::Busy),
            (rusqlite::ffi::SQLITE_LOCKED, Error::Busy),
            (rusqlite::ffi::SQLITE_INTERRUPT, Error::Interrupted),
            (rusqlite::ffi::SQLITE_IOERR, Error::Storage),
            (rusqlite::ffi::SQLITE_CORRUPT, Error::Storage),
            (rusqlite::ffi::SQLITE_FULL, Error::Storage),
        ] {
            let failure = Error::from(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                Some("private-sql-and-path-canary".into()),
            ));
            assert_eq!(failure, expected);
            assert!(!format!("{failure} {failure:?} {}", failure.code()).contains("canary"));
        }
    }
    fn binding() -> Binding {
        Binding::from_bytes(include_bytes!(
            "../../../../examples/approvals/context.json"
        ))
        .unwrap()
    }
    #[test]
    fn failed_commit_never_releases_a_permit() {
        let dir = std::env::temp_dir().join(format!(
            "mitigate-approval-commit-{}",
            fresh_reference().unwrap().as_str()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("approvals.db");
        let mut store = ApprovalStore::create(&path).unwrap();
        let request = store.request(binding(), 1000, 1000).unwrap();
        store
            .decide(
                &request.approval_ref,
                Choice::Approve,
                fresh_reference().unwrap(),
                1000,
            )
            .unwrap();
        store.conn.commit_hook(Some(|| true)).unwrap();
        assert!(matches!(
            store.consume(&request.approval_ref, &binding(), 1001),
            Err(Error::Storage)
        ));
        store.conn.commit_hook(None::<fn() -> bool>).unwrap();
        assert_eq!(
            store.get(&request.approval_ref, 1001).unwrap().state,
            State::Approved
        );
        drop(store);
        let mut reopened = ApprovalStore::open(&path).unwrap();
        assert_eq!(
            reopened.get(&request.approval_ref, 1001).unwrap().state,
            State::Approved
        );
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn full_database_rolls_back_new_requests() {
        let dir = std::env::temp_dir().join(format!(
            "mitigate-approval-full-{}",
            fresh_reference().unwrap().as_str()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("approvals.db");
        let mut store = ApprovalStore::create(&path).unwrap();
        store.conn.execute_batch("PRAGMA max_page_count=3").unwrap();
        let mut accepted = 0;
        let mut failed = false;
        for _ in 0..20 {
            let mut b = binding();
            b.call_ref = fresh_reference().unwrap();
            let call = b.call_ref.clone();
            match store.request(b, 1000, 1000) {
                Ok(_) => accepted += 1,
                Err(Error::Storage) => {
                    let records = store.list(1000).unwrap();
                    assert_eq!(records.len(), accepted);
                    assert!(records.iter().all(|r| r.binding.call_ref != call));
                    failed = true;
                    break;
                }
                Err(other) => panic!("unexpected fixed error: {other}"),
            }
        }
        assert!(failed);
        drop(store);
        assert_eq!(
            ApprovalStore::open(&path)
                .unwrap()
                .list(1000)
                .unwrap()
                .len(),
            accepted
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
