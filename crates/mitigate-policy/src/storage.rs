use crate::{
    ActivePolicy, Authority, Error, SignedBundle,
    bundle::MAX_BUNDLE,
    files::{safe_file, write_new},
};
use rusqlite::{
    Connection, OpenFlags, TransactionBehavior, config::DbConfig, limits::Limit, params,
};
use std::{
    path::Path,
    time::{Duration, Instant},
};

const SCHEMA: &str = "CREATE TABLE policy (id INTEGER PRIMARY KEY CHECK(id=1), authority TEXT NOT NULL, version INTEGER NOT NULL, bundle BLOB) STRICT";
const MAX_FILE: u64 = 1_048_576;

/// One pinned policy with atomic replacement and persistent version checks.
/// Synchronous; asynchronous gateways should own it on a blocking worker.
pub struct PolicyStore {
    conn: Connection,
    authority: Authority,
}
impl PolicyStore {
    /// Create a new empty store. The separate trust document pins the authority.
    pub fn create(path: &Path, authority: Authority) -> Result<Self, Error> {
        authority.key()?;
        write_new(path, &[])?;
        let mut conn = connect(path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO policy VALUES(1,?1,0,NULL)",
            [authority_text(&authority)?],
        )?;
        tx.execute_batch("PRAGMA user_version=1;")?;
        tx.commit()?;
        Ok(Self { conn, authority })
    }
    /// Open an existing store only. Never recreate corrupt/missing state.
    /// Reverify the signed active bundle against independently supplied trust.
    pub fn open(path: &Path, authority: Authority) -> Result<Self, Error> {
        authority.key()?;
        let conn = connect(path)?;
        read(&conn, &authority)?;
        Ok(Self { conn, authority })
    }
    /// Load and compile the last committed verified bundle. No network lookup.
    pub fn load(&self) -> Result<ActivePolicy, Error> {
        read(&self.conn, &self.authority)?
            .ok_or(Error::NoPolicy)?
            .verify(&self.authority)
    }
    /// Verify/compile the candidate before changing disk. Inside a write
    /// transaction, check current trusted state and monotonically increase the
    /// version. Busy/corrupt/full-disk failures leave the previous commit intact.
    /// A failed commit can have uncertain durability; reopen to inspect it.
    pub fn activate(&mut self, bundle: &SignedBundle) -> Result<ActivePolicy, Error> {
        let candidate = bundle.verify(&self.authority)?;
        let bytes = bundle.to_bytes()?;
        budget(&self.conn)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = read(&tx, &self.authority)?;
        if previous.is_some_and(|p| p.version() >= bundle.version()) {
            return Err(Error::Rollback);
        }
        if tx.execute(
            "UPDATE policy SET version=?1,bundle=?2 WHERE id=1",
            params![bundle.version() as i64, bytes],
        )? != 1
        {
            return Err(Error::Storage);
        }
        tx.commit()?;
        Ok(candidate)
    }
}
fn authority_text(authority: &Authority) -> Result<String, Error> {
    serde_json::to_string(authority).map_err(|_| Error::Signature)
}
fn connect(path: &Path) -> Result<Connection, Error> {
    safe_file(path, MAX_FILE, true)?;
    if rusqlite::version_number() < 3_053_004 {
        return Err(Error::Storage);
    }
    let path = path.canonicalize().map_err(|_| Error::Path)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(Duration::from_millis(250))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, 65_536)?;
    conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 4096)?;
    conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 16)?;
    conn.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 16)?;
    conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
    conn.set_limit(Limit::SQLITE_LIMIT_VDBE_OP, 10_000)?;
    // Reset the bounded operation timer before each public read/write below.
    budget(&conn)?;
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-256; PRAGMA max_page_count=256;")?;
    let page_size: u64 = conn.query_row("PRAGMA page_size", [], |r| {
        r.get::<_, i64>(0).map(|n| n as u64)
    })?;
    if page_size != 4096 {
        return Err(Error::Storage);
    }
    Ok(conn)
}
fn budget(conn: &Connection) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(2);
    conn.progress_handler(100, Some(move || Instant::now() >= deadline))?;
    Ok(())
}
fn read(conn: &Connection, authority: &Authority) -> Result<Option<SignedBundle>, Error> {
    budget(conn)?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != 1 {
        return Err(Error::Storage);
    }
    let mut statement = conn.prepare("SELECT name,sql FROM sqlite_schema ORDER BY name")?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.ok_or(Error::Storage)?;
    if row.get::<_, String>(0)? != "policy"
        || row.get::<_, String>(1)? != SCHEMA
        || rows.next()?.is_some()
    {
        return Err(Error::Storage);
    }
    let count: i64 = conn.query_row("SELECT count(*) FROM policy", [], |r| r.get(0))?;
    if count != 1 {
        return Err(Error::Storage);
    }
    let (stored_authority, version, bytes): (String, i64, Option<Vec<u8>>) = conn.query_row(
        "SELECT authority,version,bundle FROM policy WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if stored_authority != authority_text(authority)? {
        return Err(Error::Signature);
    }
    match bytes {
        None if version == 0 => Ok(None),
        Some(bytes) if version > 0 && bytes.len() <= MAX_BUNDLE => {
            let bundle = SignedBundle::from_bytes(&bytes)?;
            bundle.verify_signature(authority)?;
            if bundle.version() != version as u64 {
                return Err(Error::Storage);
            }
            Ok(Some(bundle))
        }
        _ => Err(Error::Storage),
    }
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_failure_rolls_back_replacement() {
        let dir =
            std::env::temp_dir().join(format!("mitigate-policy-capacity-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("policy.db");
        let authority = Authority {
            schema_version: 1,
            policy_ref: serde_json::from_value(serde_json::json!("a".repeat(64))).unwrap(),
            public_key: crate::public_key(&[9; 32]),
        };
        let mut store = PolicyStore::create(&path, authority.clone()).unwrap();
        let source = "package mitigate.mcp\ndefault decision := \"deny\"";
        let bundle =
            SignedBundle::sign(authority.policy_ref.clone(), 1, source.into(), &[9; 32]).unwrap();
        let mut active = store.activate(&bundle).unwrap();
        store.conn.execute_batch("PRAGMA max_page_count=2").unwrap();
        let bigger = format!(
            "{source}\n{}",
            format!("# {}\n", "x".repeat(64)).repeat(180)
        );
        let replacement =
            SignedBundle::sign(authority.policy_ref.clone(), 2, bigger, &[9; 32]).unwrap();
        assert_eq!(
            active.refresh(&mut store, &replacement),
            Err(Error::Storage)
        );
        assert_eq!(active.receipt().version, 1);
        assert_eq!(store.load().unwrap().receipt().version, 1);
        drop(store);
        assert_eq!(
            PolicyStore::open(&path, authority)
                .unwrap()
                .load()
                .unwrap()
                .receipt()
                .version,
            1
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
