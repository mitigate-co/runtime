use super::*;
use std::time::Instant;

const SCOPE: &str = "CREATE TABLE scope (id INTEGER PRIMARY KEY CHECK(id=1), runtime_ref TEXT NOT NULL, enrollment_ref TEXT NOT NULL) STRICT";
const MAPPINGS: &str = "CREATE TABLE mappings (kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 6), digest BLOB NOT NULL CHECK(length(digest)=32), reference TEXT NOT NULL CHECK(length(reference)=36), PRIMARY KEY(kind,digest)) STRICT, WITHOUT ROWID";
const UNIQUE: &str = "CREATE UNIQUE INDEX reference_values ON mappings(reference)";

pub(super) fn within_budget(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(outbox::Error::Budget.into())
    } else {
        Ok(())
    }
}
pub(super) fn initialize(conn: &Connection, partition: &Partition) -> Result<(), Error> {
    for sql in [SCOPE, MAPPINGS, UNIQUE] {
        conn.execute_batch(sql)?;
    }
    conn.execute(
        "INSERT INTO scope VALUES(1,?1,?2)",
        params![
            partition.runtime_ref.as_str(),
            partition.enrollment_ref.as_str()
        ],
    )?;
    conn.execute_batch("PRAGMA user_version=1")?;
    Ok(())
}
pub(super) fn load(
    conn: &Connection,
    partition: &Partition,
    deadline: Instant,
) -> Result<Rows, Error> {
    let integrity = || Error::Storage(outbox::Error::Integrity);
    if conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(integrity());
    }
    let mut stmt = conn.prepare("SELECT name,sql FROM sqlite_schema ORDER BY name")?;
    let mut records = stmt.query([])?;
    for (name, sql) in [
        ("mappings", MAPPINGS),
        ("reference_values", UNIQUE),
        ("scope", SCOPE),
    ] {
        let row = records.next()?.ok_or_else(integrity)?;
        if row.get::<_, String>(0)? != name || row.get::<_, String>(1)? != sql {
            return Err(integrity());
        }
    }
    if records.next()?.is_some()
        || conn.query_row("SELECT count(*) FROM scope", [], |r| r.get::<_, i64>(0))? != 1
    {
        return Err(integrity());
    }
    let scope = conn.query_row(
        "SELECT runtime_ref,enrollment_ref FROM scope WHERE id=1",
        [],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )?;
    if scope.0 != partition.runtime_ref.as_str() || scope.1 != partition.enrollment_ref.as_str() {
        return Err(outbox::Error::Partition.into());
    }
    let mut rows = Rows::new();
    let mut used = BTreeSet::from([
        partition.runtime_ref.clone(),
        partition.enrollment_ref.clone(),
    ]);
    let mut stmt =
        conn.prepare("SELECT kind,digest,reference FROM mappings ORDER BY kind,digest")?;
    let mut records = stmt.query([])?;
    while let Some(row) = records.next()? {
        within_budget(deadline)?;
        if rows.len() >= MAX_REFERENCES {
            return Err(integrity());
        }
        let kind = match row.get::<_, u8>(0)? {
            0 => Kind::Client,
            1 => Kind::Principal,
            2 => Kind::Agent,
            3 => Kind::Server,
            4 => Kind::Tool,
            5 => Kind::Schema,
            6 => Kind::Policy,
            _ => return Err(integrity()),
        };
        let digest: [u8; 32] = row
            .get::<_, Vec<u8>>(1)?
            .try_into()
            .map_err(|_| integrity())?;
        let reference: SyncRef = serde_json::from_value(serde_json::Value::String(row.get(2)?))
            .map_err(|_| integrity())?;
        if !used.insert(reference.clone()) {
            return Err(integrity());
        }
        rows.insert(LocalKey::new(kind, digest), reference);
    }
    within_budget(deadline)?;
    Ok(rows)
}
