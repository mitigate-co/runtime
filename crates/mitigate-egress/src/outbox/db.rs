use super::{
    Error, MAX_TIME,
    state::{Receipt, Receipts, Record, Rows, State},
};
use rusqlite::{Connection, OpenFlags, config::DbConfig, limits::Limit, params};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

const STATE: &str =
    "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), record BLOB NOT NULL) STRICT";
const EVENTS: &str =
    "CREATE TABLE events (id TEXT PRIMARY KEY, record BLOB NOT NULL) STRICT, WITHOUT ROWID";
const RECEIPTS: &str =
    "CREATE TABLE receipts (id TEXT PRIMARY KEY, record BLOB NOT NULL) STRICT, WITHOUT ROWID";
const MAX_FILE: u64 = 16 * 1024 * 1024;

pub(super) fn create_file(path: &Path) -> Result<(), Error> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| Error::Path)?
        .sync_all()
        .map_err(|_| Error::Storage)
}
pub(super) fn connect(path: &Path) -> Result<Connection, Error> {
    open(path, false)
}
pub(super) fn readonly(path: &Path) -> Result<Connection, Error> {
    open(path, true)
}
fn open(path: &Path, readonly: bool) -> Result<Connection, Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_FILE {
        return Err(Error::Path);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Path);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(Error::Path);
        }
    }
    if rusqlite::version_number() < 3_053_004 {
        return Err(Error::Storage);
    }
    let conn = Connection::open_with_flags(
        path.canonicalize().map_err(|_| Error::Path)?,
        (if readonly {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        }) | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(Duration::from_millis(250))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, 65_536),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 4096),
        (Limit::SQLITE_LIMIT_COLUMN, 16),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 16),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VDBE_OP, 100_000),
    ] {
        conn.set_limit(limit, value)?;
    }
    budget(&conn)?;
    if readonly {
        conn.execute_batch(
            "PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048;",
        )?;
        if conn.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))? != "delete" {
            return Err(Error::Integrity);
        }
    } else {
        conn.execute_batch("PRAGMA page_size=4096; PRAGMA auto_vacuum=FULL; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048; PRAGMA max_page_count=4096;")?;
    }
    if conn.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))? != 4096
        || conn.query_row("PRAGMA auto_vacuum", [], |r| r.get::<_, i64>(0))? != 1
    {
        return Err(Error::Integrity);
    }
    Ok(conn)
}
pub(super) fn budget(conn: &Connection) -> Result<Instant, Error> {
    let deadline = Instant::now() + Duration::from_secs(2);
    conn.progress_handler(100, Some(move || Instant::now() >= deadline))?;
    Ok(deadline)
}
pub(super) fn initialize(conn: &Connection, state: &State) -> Result<(), Error> {
    conn.execute_batch(STATE)?;
    conn.execute_batch(EVENTS)?;
    conn.execute_batch(RECEIPTS)?;
    conn.execute("INSERT INTO state VALUES(1,?1)", [encode(state)?])?;
    conn.execute_batch("PRAGMA user_version=1")?;
    Ok(())
}
fn decode<T: DeserializeOwned>(bytes: &[u8], max: usize) -> Result<T, Error> {
    if bytes.len() > max {
        return Err(Error::Integrity);
    }
    serde_json::from_value(mitigate_json::parse(bytes).map_err(|_| Error::Integrity)?)
        .map_err(|_| Error::Integrity)
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| Error::Integrity)
}
fn schema(conn: &Connection) -> Result<(), Error> {
    if conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(Error::Integrity);
    }
    let mut stmt = conn.prepare("SELECT name,sql FROM sqlite_schema ORDER BY name")?;
    let mut rows = stmt.query([])?;
    for (name, sql) in [("events", EVENTS), ("receipts", RECEIPTS), ("state", STATE)] {
        let row = rows.next()?.ok_or(Error::Integrity)?;
        if row.get::<_, String>(0)? != name || row.get::<_, String>(1)? != sql {
            return Err(Error::Integrity);
        }
    }
    if rows.next()?.is_some() {
        return Err(Error::Integrity);
    }
    Ok(())
}
pub(super) fn load(conn: &Connection, deadline: Instant) -> Result<(State, Rows, Receipts), Error> {
    schema(conn)?;
    if conn.query_row("SELECT count(*) FROM state", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(Error::Integrity);
    }
    let bytes: Vec<u8> = conn.query_row("SELECT record FROM state WHERE id=1", [], |r| r.get(0))?;
    let state: State = decode(&bytes, 65_536)?;
    state.validate()?;
    let mut events = Rows::new();
    let mut stmt = conn.prepare("SELECT id,record FROM events ORDER BY id")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if Instant::now() >= deadline {
            return Err(Error::Budget);
        }
        if events.len() >= state.limits.max_events as usize {
            return Err(Error::Integrity);
        }
        let id: String = row.get(0)?;
        let record: Record = decode(&row.get::<_, Vec<u8>>(1)?, 8192)?;
        record.checked(&id, &state)?;
        events.insert(id, record);
    }
    let mut receipts = Receipts::new();
    let mut stmt = conn.prepare("SELECT id,record FROM receipts ORDER BY id")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if Instant::now() >= deadline {
            return Err(Error::Budget);
        }
        if receipts.len() >= state.limits.max_events as usize {
            return Err(Error::Integrity);
        }
        let id: String = row.get(0)?;
        let receipt: Receipt = decode(&row.get::<_, Vec<u8>>(1)?, 256)?;
        if !crate::reference::valid(&id)
            || events.contains_key(&id)
            || receipt.finished_ms > state.last_time
            || receipt.finished_ms > MAX_TIME
            || receipt.digest.len() != 64
            || !receipt
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Integrity);
        }
        receipts.insert(id, receipt);
    }
    Ok((state, events, receipts))
}
pub(super) fn save(
    conn: &Connection,
    state: &State,
    events: &Rows,
    receipts: &Receipts,
    old_events: &[String],
    old_receipts: &[String],
    deadline: Instant,
) -> Result<(), Error> {
    state.validate()?;
    if events.len() > state.limits.max_events as usize
        || receipts.len() > state.limits.max_events as usize
    {
        return Err(Error::Integrity);
    }
    for id in old_events.iter().filter(|id| !events.contains_key(*id)) {
        conn.execute("DELETE FROM events WHERE id=?1", [id])?;
    }
    for id in old_receipts.iter().filter(|id| !receipts.contains_key(*id)) {
        conn.execute("DELETE FROM receipts WHERE id=?1", [id])?;
    }
    let mut stmt = conn.prepare("INSERT INTO events VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record WHERE events.record<>excluded.record")?;
    for (id, record) in events {
        if Instant::now() >= deadline {
            return Err(Error::Budget);
        }
        let bytes = encode(record)?;
        if bytes.len() > 8192 {
            return Err(Error::Integrity);
        }
        stmt.execute(params![id, bytes])?;
    }
    let mut stmt = conn.prepare("INSERT INTO receipts VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record WHERE receipts.record<>excluded.record")?;
    for (id, record) in receipts {
        if Instant::now() >= deadline {
            return Err(Error::Budget);
        }
        stmt.execute(params![id, encode(record)?])?;
    }
    conn.execute("UPDATE state SET record=?1 WHERE id=1", [encode(state)?])?;
    Ok(())
}
