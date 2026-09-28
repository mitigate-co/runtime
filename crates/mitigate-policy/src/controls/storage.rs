//! One transactional local control plane; no quota reset on process restart.
use super::*;
use crate::files::{safe_file, write_new};
use rusqlite::{
    Connection, OpenFlags, TransactionBehavior, config::DbConfig, limits::Limit as SqlLimit, params,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

const STATE_SQL: &str = "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, last_time INTEGER NOT NULL, stopped INTEGER NOT NULL) STRICT";
const DISABLED_SQL: &str = "CREATE TABLE disabled (target TEXT PRIMARY KEY) STRICT, WITHOUT ROWID";
const BUCKETS_SQL: &str = "CREATE TABLE buckets (target TEXT PRIMARY KEY, capacity INTEGER NOT NULL, refill_tokens INTEGER NOT NULL, period_ms INTEGER NOT NULL, units INTEGER NOT NULL, updated_at INTEGER NOT NULL) STRICT, WITHOUT ROWID";
const HISTORY_SQL: &str =
    "CREATE TABLE history (revision INTEGER PRIMARY KEY, record BLOB NOT NULL) STRICT";

#[derive(Clone, Copy, PartialEq, Eq)]
struct Bucket {
    rate: Rate,
    units: u64,
    updated_at: u64,
}
impl Bucket {
    fn refill(&mut self, now: u64) {
        // One whole token is period_ms units. Intermediate products use u128
        // even though the validated input bounds fit comfortably in u64.
        self.units = (u128::from(self.units)
            + u128::from(now - self.updated_at) * u128::from(self.rate.refill_tokens))
        .min(u128::from(self.rate.maximum())) as u64;
        self.updated_at = now;
    }
}
#[derive(Clone)]
struct State {
    revision: u64,
    last_time: u64,
    stopped: bool,
    disabled: BTreeSet<Target>,
    buckets: BTreeMap<Target, Bucket>,
}
impl State {
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            schema_version: 1,
            revision: self.revision,
            emergency_stop: self.stopped,
            disabled: self.disabled.iter().cloned().collect(),
            limits: self
                .buckets
                .iter()
                .map(|(target, b)| Limit {
                    target: target.clone(),
                    rate: b.rate,
                })
                .collect(),
        }
    }
    fn check_clock(&self, now: u64) -> Result<(), Error> {
        if now > MAX_TIME || now < self.last_time {
            return Err(Error::Clock);
        }
        Ok(())
    }
    fn change(&mut self, change: &Change, now: u64) -> Result<bool, Error> {
        match change {
            Change::Stop {} | Change::Resume {} => {
                let stopped = matches!(change, Change::Stop {});
                let changed = self.stopped != stopped;
                self.stopped = stopped;
                Ok(changed)
            }
            Change::Disable { target } => {
                if self.disabled.contains(target) {
                    return Ok(false);
                }
                if self.disabled.len() >= MAX_DISABLED {
                    return Err(Error::Capacity);
                }
                self.disabled.insert(target.clone());
                Ok(true)
            }
            Change::Enable { target } => Ok(self.disabled.remove(target)),
            Change::RemoveLimit { target } => Ok(self.buckets.remove(target).is_some()),
            Change::SetLimit { target, rate } => {
                if let Some(bucket) = self.buckets.get_mut(target) {
                    if &bucket.rate == rate {
                        return Ok(false);
                    }
                    bucket.refill(now);
                    // Preserve earned tokens, round down fractional units and
                    // clamp to the new burst. A config edit is not a refill.
                    bucket.units = (u128::from(bucket.units) * u128::from(rate.period_ms)
                        / u128::from(bucket.rate.period_ms))
                    .min(u128::from(rate.maximum())) as u64;
                    bucket.rate = *rate;
                } else {
                    if self.buckets.len() >= MAX_LIMITS {
                        return Err(Error::Capacity);
                    }
                    self.buckets.insert(
                        target.clone(),
                        Bucket {
                            rate: *rate,
                            units: rate.maximum(),
                            updated_at: now,
                        },
                    );
                }
                Ok(true)
            }
        }
    }
    fn admit(&mut self, context: &Context, now: u64) -> Admission {
        let disabled: Vec<_> = self
            .disabled
            .iter()
            .filter(|t| t.matches(context))
            .cloned()
            .collect();
        if self.stopped || !disabled.is_empty() {
            return Admission::Disabled {
                revision: self.revision,
                emergency_stop: self.stopped,
                targets: disabled,
            };
        }
        let mut depleted = Vec::new();
        let mut retry_after_ms = 0;
        for (target, bucket) in self.buckets.iter_mut().filter(|(t, _)| t.matches(context)) {
            bucket.refill(now);
            let cost = u64::from(bucket.rate.period_ms);
            if bucket.units < cost {
                depleted.push(target.clone());
                retry_after_ms = retry_after_ms
                    .max((cost - bucket.units).div_ceil(u64::from(bucket.rate.refill_tokens)));
            }
        }
        if !depleted.is_empty() {
            return Admission::RateLimited {
                revision: self.revision,
                retry_after_ms,
                targets: depleted,
            };
        }
        for (_, bucket) in self.buckets.iter_mut().filter(|(t, _)| t.matches(context)) {
            bucket.units -= u64::from(bucket.rate.period_ms);
        }
        Admission::Allowed {
            revision: self.revision,
        }
    }
}

/// Private, bounded local controls shared by gateways and operator commands.
/// Use a blocking worker in asynchronous code. Failed/uncertain commits release
/// no allowance. Same-user replacement of the entire database is out of scope.
pub struct ControlStore {
    conn: Connection,
}
impl ControlStore {
    /// Exclusively create a store with no disables/limits. Never overwrite.
    /// Other governance checks must still deny calls without authorization.
    pub fn create(path: &Path) -> Result<Self, Error> {
        write_new(path, &[]).map_err(|_| Error::Path)?;
        let mut conn = connect(path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for sql in [STATE_SQL, DISABLED_SQL, BUCKETS_SQL, HISTORY_SQL] {
            tx.execute_batch(sql)?;
        }
        tx.execute_batch("INSERT INTO state VALUES(1,0,0,0); PRAGMA user_version=1;")?;
        tx.commit()?;
        Ok(Self { conn })
    }
    /// Verify an existing store. Missing/corrupt state is never recreated.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut conn = connect(path)?;
        let tx = conn.transaction()?;
        read(&tx)?;
        tx.commit()?;
        Ok(Self { conn })
    }
    /// Inspect current configuration without changing clocks or quota balances.
    pub fn status(&mut self) -> Result<Snapshot, Error> {
        budget(&self.conn)?;
        let tx = self.conn.transaction()?;
        let (state, _) = read(&tx)?;
        tx.commit()?;
        Ok(state.snapshot())
    }
    /// Read the last 256 administrator changes in ascending revision order.
    /// The first revision explicitly reveals when older history was pruned.
    pub fn history(&mut self) -> Result<Vec<HistoryEntry>, Error> {
        budget(&self.conn)?;
        let tx = self.conn.transaction()?;
        let (_, history) = read(&tx)?;
        tx.commit()?;
        Ok(history)
    }
    /// Commit a validated administrator change and its history atomically.
    /// Reapplying an identical configuration does not reset buckets or revision.
    pub fn apply(
        &mut self,
        change: Change,
        operator: Fingerprint,
        now: u64,
    ) -> Result<Snapshot, Error> {
        change.validate()?;
        budget(&self.conn)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (original, _) = read(&tx)?;
        original.check_clock(now)?;
        let mut state = original.clone();
        if state.change(&change, now)? {
            state.revision = state
                .revision
                .checked_add(1)
                .filter(|r| *r <= MAX_TIME)
                .ok_or(Error::Capacity)?;
            let entry = HistoryEntry {
                schema_version: 1,
                revision: state.revision,
                time_ms: now,
                operator_ref: operator,
                source: OperatorSource::DeclaredLocal,
                change,
            };
            let bytes = serde_json::to_vec(&entry).map_err(|_| Error::Storage)?;
            tx.execute(
                "INSERT INTO history VALUES(?1,?2)",
                params![state.revision as i64, bytes],
            )?;
            tx.execute(
                "DELETE FROM history WHERE revision<=?1",
                [state.revision.saturating_sub(MAX_CHANGES as u64) as i64],
            )?;
        }
        state.last_time = now;
        write(&tx, &original, &state)?;
        tx.commit()?;
        Ok(state.snapshot())
    }
    /// Diagnose an action without consuming quota or changing any stored state.
    /// The result can race with live calls/changes and must never authorize one.
    pub fn preview(&mut self, context: &Context, now: u64) -> Result<Admission, Error> {
        context.validate()?;
        budget(&self.conn)?;
        let tx = self.conn.transaction()?;
        let (mut state, _) = read(&tx)?;
        state.check_clock(now)?;
        let result = state.admit(context, now);
        tx.commit()?;
        Ok(result)
    }
    /// Check emergency/target disables, then charge all matching quotas in one
    /// transaction. Caller supplies trusted time and rechecks before dispatch.
    /// A committed admission remains charged if later checks/calls fail.
    pub fn admit(&mut self, context: &Context, now: u64) -> Result<Admission, Error> {
        context.validate()?;
        budget(&self.conn)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (original, _) = read(&tx)?;
        original.check_clock(now)?;
        let mut state = original.clone();
        let result = state.admit(context, now);
        state.last_time = now;
        write(&tx, &original, &state)?;
        tx.commit()?;
        Ok(result)
    }
}

fn target_key(target: &Target) -> Result<String, Error> {
    serde_json::to_string(target).map_err(|_| Error::Storage)
}
fn stored_target(key: &str) -> Result<Target, Error> {
    if key.len() > 256 {
        return Err(Error::Storage);
    }
    let value = mitigate_json::parse(key.as_bytes()).map_err(|_| Error::Storage)?;
    let target: Target = serde_json::from_value(value).map_err(|_| Error::Storage)?;
    if target_key(&target)? != key {
        return Err(Error::Storage);
    }
    Ok(target)
}
fn write(conn: &Connection, before: &State, after: &State) -> Result<(), Error> {
    for target in before.disabled.difference(&after.disabled) {
        conn.execute(
            "DELETE FROM disabled WHERE target=?1",
            [target_key(target)?],
        )?;
    }
    for target in after.disabled.difference(&before.disabled) {
        conn.execute("INSERT INTO disabled VALUES(?1)", [target_key(target)?])?;
    }
    for target in before
        .buckets
        .keys()
        .filter(|t| !after.buckets.contains_key(*t))
    {
        conn.execute("DELETE FROM buckets WHERE target=?1", [target_key(target)?])?;
    }
    for (target, b) in &after.buckets {
        if before.buckets.get(target) != Some(b) {
            conn.execute("INSERT INTO buckets VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(target) DO UPDATE SET capacity=excluded.capacity,refill_tokens=excluded.refill_tokens,period_ms=excluded.period_ms,units=excluded.units,updated_at=excluded.updated_at",
                params![target_key(target)?, b.rate.capacity, b.rate.refill_tokens, b.rate.period_ms, b.units as i64, b.updated_at as i64])?;
        }
    }
    conn.execute(
        "UPDATE state SET revision=?1,last_time=?2,stopped=?3 WHERE id=1",
        params![after.revision as i64, after.last_time as i64, after.stopped],
    )?;
    Ok(())
}
fn read(conn: &Connection) -> Result<(State, Vec<HistoryEntry>), Error> {
    budget(conn)?;
    if conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(Error::Storage);
    }
    let mut stmt = conn.prepare("SELECT name,sql FROM sqlite_schema ORDER BY name")?;
    let mut rows = stmt.query([])?;
    for (name, sql) in [
        ("buckets", BUCKETS_SQL),
        ("disabled", DISABLED_SQL),
        ("history", HISTORY_SQL),
        ("state", STATE_SQL),
    ] {
        let row = rows.next()?.ok_or(Error::Storage)?;
        if row.get::<_, String>(0)? != name || row.get::<_, String>(1)? != sql {
            return Err(Error::Storage);
        }
    }
    if rows.next()?.is_some() {
        return Err(Error::Storage);
    }
    if conn.query_row("SELECT count(*) FROM state", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(Error::Storage);
    }
    let (revision, last_time, stopped): (i64, i64, u32) = conn.query_row(
        "SELECT revision,last_time,stopped FROM state WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let revision = u64::try_from(revision).map_err(|_| Error::Storage)?;
    let last_time = u64::try_from(last_time).map_err(|_| Error::Storage)?;
    if revision > MAX_TIME || last_time > MAX_TIME || stopped > 1 {
        return Err(Error::Storage);
    }
    let mut state = State {
        revision,
        last_time,
        stopped: stopped == 1,
        disabled: BTreeSet::new(),
        buckets: BTreeMap::new(),
    };
    let mut stmt = conn.prepare("SELECT target FROM disabled LIMIT 257")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let target = stored_target(&row.get::<_, String>(0)?)?;
        if matches!(target, Target::Global {})
            || state.disabled.len() >= MAX_DISABLED
            || !state.disabled.insert(target)
        {
            return Err(Error::Storage);
        }
    }
    let mut stmt = conn.prepare(
        "SELECT target,capacity,refill_tokens,period_ms,units,updated_at FROM buckets LIMIT 129",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let target = stored_target(&row.get::<_, String>(0)?)?;
        let rate = Rate {
            capacity: row.get(1)?,
            refill_tokens: row.get(2)?,
            period_ms: row.get(3)?,
        };
        rate.validate().map_err(|_| Error::Storage)?;
        let b = Bucket {
            rate,
            units: u64::try_from(row.get::<_, i64>(4)?).map_err(|_| Error::Storage)?,
            updated_at: u64::try_from(row.get::<_, i64>(5)?).map_err(|_| Error::Storage)?,
        };
        if b.units > rate.maximum()
            || b.updated_at > last_time
            || state.buckets.len() >= MAX_LIMITS
            || state.buckets.insert(target, b).is_some()
        {
            return Err(Error::Storage);
        }
    }
    let mut stmt =
        conn.prepare("SELECT revision,record FROM history ORDER BY revision LIMIT 257")?;
    let mut rows = stmt.query([])?;
    let mut history = Vec::new();
    let mut next = revision
        .saturating_sub(MAX_CHANGES as u64)
        .saturating_add(1);
    let mut previous_time = 0;
    while let Some(row) = rows.next()? {
        let key = u64::try_from(row.get::<_, i64>(0)?).map_err(|_| Error::Storage)?;
        let bytes: Vec<u8> = row.get(1)?;
        if bytes.len() > 2048 {
            return Err(Error::Storage);
        }
        let entry: HistoryEntry =
            serde_json::from_value(mitigate_json::parse(&bytes).map_err(|_| Error::Storage)?)
                .map_err(|_| Error::Storage)?;
        entry.change.validate().map_err(|_| Error::Storage)?;
        if history.len() >= MAX_CHANGES
            || key != next
            || entry.revision != key
            || entry.schema_version != 1
            || entry.time_ms > last_time
            || entry.time_ms < previous_time
        {
            return Err(Error::Storage);
        }
        previous_time = entry.time_ms;
        next += 1;
        history.push(entry);
    }
    if next != revision + 1 {
        return Err(Error::Storage);
    }
    if revision == 0 && (state.stopped || !state.disabled.is_empty() || !state.buckets.is_empty()) {
        return Err(Error::Storage);
    }
    Ok((state, history))
}
fn connect(path: &Path) -> Result<Connection, Error> {
    safe_file(path, 4_194_304, true).map_err(|_| Error::Path)?;
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
    conn.set_limit(SqlLimit::SQLITE_LIMIT_LENGTH, 4096)?;
    conn.set_limit(SqlLimit::SQLITE_LIMIT_SQL_LENGTH, 4096)?;
    conn.set_limit(SqlLimit::SQLITE_LIMIT_COLUMN, 16)?;
    conn.set_limit(SqlLimit::SQLITE_LIMIT_EXPR_DEPTH, 16)?;
    conn.set_limit(SqlLimit::SQLITE_LIMIT_ATTACHED, 0)?;
    conn.set_limit(SqlLimit::SQLITE_LIMIT_VDBE_OP, 10_000)?;
    budget(&conn)?;
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-512; PRAGMA max_page_count=1024;")?;
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
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use crate::controls::tests::{Directory, context, reference};

    #[test]
    fn read_operations_replace_expired_budgets_before_beginning_transactions() {
        let dir = Directory::new();
        let mut store = ControlStore::create(&dir.db()).unwrap();
        // A deterministic expired-budget stand-in, without sleeping.
        store.conn.progress_handler(1, Some(|| true)).unwrap();
        assert_eq!(store.status().unwrap().revision, 0);
        store.conn.progress_handler(1, Some(|| true)).unwrap();
        assert!(store.history().unwrap().is_empty());
        store.conn.progress_handler(1, Some(|| true)).unwrap();
        assert!(matches!(
            store.preview(&context(), 0),
            Ok(Admission::Allowed { .. })
        ));
    }

    #[test]
    fn failed_commits_release_no_admission_or_partial_change() {
        let dir = Directory::new();
        let mut store = ControlStore::create(&dir.db()).unwrap();
        store
            .apply(
                Change::SetLimit {
                    target: Target::Global {},
                    rate: Rate {
                        capacity: 1,
                        refill_tokens: 1,
                        period_ms: 1000,
                    },
                },
                reference(99),
                0,
            )
            .unwrap();
        store.conn.commit_hook(Some(|| true)).unwrap();
        assert!(matches!(store.admit(&context(), 0), Err(Error::Storage)));
        assert!(matches!(
            store.apply(Change::Stop {}, reference(99), 0),
            Err(Error::Storage)
        ));
        store.conn.commit_hook(None::<fn() -> bool>).unwrap();
        drop(store);
        let mut store = ControlStore::open(&dir.db()).unwrap();
        assert!(!store.status().unwrap().emergency_stop);
        assert_eq!(store.history().unwrap().len(), 1);
        assert!(matches!(
            store.admit(&context(), 0),
            Ok(Admission::Allowed { .. })
        ));
        assert!(matches!(
            store.admit(&context(), 0),
            Ok(Admission::RateLimited { .. })
        ));
    }
    #[test]
    fn malformed_stored_counters_and_history_never_allow() {
        for sql in [
            "UPDATE buckets SET units=-1",
            "UPDATE buckets SET units=1001",
            "UPDATE buckets SET updated_at=1",
            "UPDATE buckets SET period_ms=0",
            "UPDATE state SET last_time=-1",
            "UPDATE state SET stopped=2",
            "DELETE FROM history",
            "UPDATE history SET record=X'7b7d'",
        ] {
            let dir = Directory::new();
            let mut store = ControlStore::create(&dir.db()).unwrap();
            store
                .apply(
                    Change::SetLimit {
                        target: Target::Global {},
                        rate: Rate {
                            capacity: 1,
                            refill_tokens: 1,
                            period_ms: 1000,
                        },
                    },
                    reference(99),
                    0,
                )
                .unwrap();
            store.conn.execute_batch(sql).unwrap();
            assert!(matches!(store.admit(&context(), 0), Err(Error::Storage)));
            drop(store);
            assert!(matches!(ControlStore::open(&dir.db()), Err(Error::Storage)));
        }
    }
    #[test]
    fn full_database_keeps_existing_stop_and_atomic_history() {
        let dir = Directory::new();
        let mut store = ControlStore::create(&dir.db()).unwrap();
        store.apply(Change::Stop {}, reference(99), 0).unwrap();
        store.conn.execute_batch("PRAGMA max_page_count=5").unwrap();
        let mut full = false;
        for n in 0..100 {
            let before = store.status().unwrap().revision;
            match store.apply(
                Change::Disable {
                    target: Target::Server {
                        reference: reference(n),
                    },
                },
                reference(99),
                0,
            ) {
                Ok(_) => (),
                Err(Error::Storage) => {
                    full = true;
                    assert_eq!(store.status().unwrap().revision, before);
                    assert_eq!(store.history().unwrap().last().unwrap().revision, before);
                    assert!(matches!(
                        store.admit(&context(), 0),
                        Ok(Admission::Disabled {
                            emergency_stop: true,
                            ..
                        })
                    ));
                    break;
                }
                Err(e) => panic!("unexpected fixed error: {e}"),
            }
        }
        assert!(full);
    }
}
