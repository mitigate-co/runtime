use super::*;
use serde_json::json;
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};

pub(super) fn reference(n: u64) -> Fingerprint {
    serde_json::from_value(json!(format!("{n:064x}"))).unwrap()
}
pub(super) fn context() -> Context {
    Context {
        schema_version: 1,
        client: Some(reference(1)),
        principal: Some(reference(2)),
        agent: Some(reference(3)),
        server: reference(4),
        tool: reference(5),
    }
}
pub(super) struct Directory(PathBuf);
impl Directory {
    pub(super) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-controls-{}",
            crate::approvals::fresh_reference().unwrap().as_str()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub(super) fn db(&self) -> PathBuf {
        self.0.join("controls.db")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn rate(capacity: u32, refill_tokens: u32, period_ms: u32) -> Rate {
    Rate {
        capacity,
        refill_tokens,
        period_ms,
    }
}
fn set(store: &mut ControlStore, target: Target, rate: Rate, now: u64) {
    store
        .apply(Change::SetLimit { target, rate }, reference(99), now)
        .unwrap();
}
fn allowed(result: Result<Admission, Error>) -> bool {
    matches!(result, Ok(Admission::Allowed { .. }))
}
fn retry(result: Result<Admission, Error>) -> u64 {
    match result.unwrap() {
        Admission::RateLimited { retry_after_ms, .. } => retry_after_ms,
        _ => panic!("expected rate limit"),
    }
}

#[test]
fn exact_disables_unknown_identity_and_emergency_precedence() {
    let dir = Directory::new();
    let mut store = ControlStore::create(&dir.db()).unwrap();
    let ctx = context();
    let targets = [
        Target::Client {
            reference: reference(1),
        },
        Target::Principal {
            reference: reference(2),
        },
        Target::Agent {
            reference: reference(3),
        },
        Target::Server {
            reference: reference(4),
        },
        Target::Tool {
            server: reference(4),
            tool: reference(5),
        },
    ];
    for target in targets {
        store
            .apply(
                Change::Disable {
                    target: target.clone(),
                },
                reference(99),
                1,
            )
            .unwrap();
        assert!(
            matches!(store.admit(&ctx, 1).unwrap(), Admission::Disabled { emergency_stop: false, targets, .. } if targets == vec![target.clone()])
        );
        let mut other = context();
        other.client = None;
        other.principal = None;
        other.agent = None;
        other.server = reference(6);
        assert!(allowed(store.admit(&other, 1)));
        store
            .apply(Change::Enable { target }, reference(99), 1)
            .unwrap();
    }
    set(&mut store, Target::Global {}, rate(1, 1, 1000), 1);
    assert!(allowed(store.admit(&ctx, 1)));
    store.apply(Change::Stop {}, reference(99), 1).unwrap();
    assert!(matches!(
        store.admit(&ctx, 1).unwrap(),
        Admission::Disabled {
            emergency_stop: true,
            ..
        }
    ));
    store.apply(Change::Resume {}, reference(99), 1).unwrap();
    assert_eq!(retry(store.admit(&ctx, 1)), 1000);
    let target = Target::Server {
        reference: reference(4),
    };
    store
        .apply(Change::Disable { target }, reference(99), 1)
        .unwrap();
    store.apply(Change::Stop {}, reference(99), 1).unwrap();
    store.apply(Change::Resume {}, reference(99), 1).unwrap();
    assert!(matches!(
        store.admit(&ctx, 5000).unwrap(),
        Admission::Disabled {
            emergency_stop: false,
            ..
        }
    ));
}

#[test]
fn exact_fractional_refill_boundaries_and_long_idle_cap() {
    let dir = Directory::new();
    let mut store = ControlStore::create(&dir.db()).unwrap();
    set(&mut store, Target::Global {}, rate(2, 3, 1000), 0);
    assert!(allowed(store.admit(&context(), 0)));
    assert!(allowed(store.admit(&context(), 0)));
    assert_eq!(retry(store.admit(&context(), 0)), 334);
    assert_eq!(retry(store.admit(&context(), 333)), 1);
    assert!(allowed(store.admit(&context(), 334)));
    assert_eq!(retry(store.admit(&context(), 666)), 1);
    assert!(allowed(store.admit(&context(), 667)));
    assert!(allowed(store.admit(&context(), 1000)));
    assert!(allowed(store.admit(&context(), MAX_TIME)));
    assert!(allowed(store.admit(&context(), MAX_TIME)));
    assert_eq!(retry(store.admit(&context(), MAX_TIME)), 334);
}

#[test]
fn overlapping_limits_are_atomic_and_tool_scope_includes_server() {
    let dir = Directory::new();
    let mut store = ControlStore::create(&dir.db()).unwrap();
    let tool = Target::Tool {
        server: reference(4),
        tool: reference(5),
    };
    set(&mut store, Target::Global {}, rate(2, 1, 1000), 0);
    set(&mut store, tool, rate(1, 1, 10000), 0);
    assert!(allowed(store.admit(&context(), 0)));
    assert_eq!(retry(store.admit(&context(), 0)), 10000);
    let mut other = context();
    other.server = reference(6);
    assert!(
        allowed(store.admit(&other, 0)),
        "rejected call must not debit the global bucket"
    );
    assert_eq!(retry(store.admit(&other, 0)), 1000);
    assert_eq!(retry(store.admit(&context(), 1)), 9999);
}

#[test]
fn restart_noop_edits_and_rate_changes_cannot_replenish_quota() {
    let dir = Directory::new();
    let mut store = ControlStore::create(&dir.db()).unwrap();
    set(&mut store, Target::Global {}, rate(1, 1, 1000), 0);
    assert!(allowed(store.admit(&context(), 0)));
    set(&mut store, Target::Global {}, rate(1, 1, 1000), 250);
    assert_eq!(store.status().unwrap().revision, 1);
    drop(store);
    let mut store = ControlStore::open(&dir.db()).unwrap();
    assert_eq!(retry(store.admit(&context(), 250)), 750);
    set(&mut store, Target::Global {}, rate(10, 1, 2000), 500);
    assert_eq!(retry(store.admit(&context(), 500)), 1000);
    assert!(allowed(store.admit(&context(), 1500)));
    assert_eq!(retry(store.admit(&context(), 1500)), 2000);
    // An explicit, recorded remove/re-add intentionally creates a new bucket.
    store
        .apply(
            Change::RemoveLimit {
                target: Target::Global {},
            },
            reference(99),
            1500,
        )
        .unwrap();
    set(&mut store, Target::Global {}, rate(1, 1, 1000), 1500);
    assert!(allowed(store.admit(&context(), 1500)));
    assert_eq!(store.history().unwrap().len(), 4);
}

#[test]
fn preview_is_read_only_and_denials_persist_clock_high_water() {
    let dir = Directory::new();
    let mut store = ControlStore::create(&dir.db()).unwrap();
    set(&mut store, Target::Global {}, rate(1, 1, 1000), 1000);
    assert!(allowed(store.preview(&context(), 5000)));
    assert!(allowed(store.preview(&context(), 1000)));
    assert!(allowed(store.admit(&context(), 1000)));
    assert_eq!(retry(store.admit(&context(), 1100)), 900);
    drop(store);
    let mut store = ControlStore::open(&dir.db()).unwrap();
    assert!(matches!(store.admit(&context(), 1099), Err(Error::Clock)));
    assert!(matches!(
        store.preview(&context(), MAX_TIME + 1),
        Err(Error::Clock)
    ));
    store.apply(Change::Stop {}, reference(99), 1200).unwrap();
    assert!(matches!(
        store.admit(&context(), 1300),
        Ok(Admission::Disabled { .. })
    ));
    assert!(matches!(
        store.apply(Change::Resume {}, reference(99), 1299),
        Err(Error::Clock)
    ));
    assert!(store.status().unwrap().emergency_stop);
}

#[test]
fn independent_connections_cannot_overspend_shared_quota() {
    let dir = Directory::new();
    let mut store = ControlStore::create(&dir.db()).unwrap();
    set(&mut store, Target::Global {}, rate(1, 1, 1000), 0);
    let gate = Arc::new(Barrier::new(5));
    let mut threads = Vec::new();
    for _ in 0..5 {
        let mut connection = ControlStore::open(&dir.db()).unwrap();
        let gate = gate.clone();
        threads.push(std::thread::spawn(move || {
            gate.wait();
            allowed(connection.admit(&context(), 0))
        }));
    }
    assert_eq!(
        threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(retry(store.admit(&context(), 0)), 1000);
}

#[test]
fn closed_inputs_reject_missing_identity_and_payloads() {
    let valid = json!({"schema_version":1,"client":null,"principal":null,"agent":null,"server":"a".repeat(64),"tool":"b".repeat(64)});
    assert!(Context::from_bytes(&serde_json::to_vec(&valid).unwrap()).is_ok());
    for field in [
        "client",
        "principal",
        "agent",
        "schema_version",
        "server",
        "tool",
    ] {
        let mut v = valid.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(Context::from_bytes(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    for field in ["arguments", "result", "metadata", "token"] {
        let mut v = valid.clone();
        v[field] = json!("secret-canary");
        assert!(Context::from_bytes(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    for change in [
        r#"{"action":"stop","metadata":"canary"}"#,
        r#"{"action":"stop","action":"resume"}"#,
        r#"{"action":"disable","target":{"kind":"global"}}"#,
        r#"{"action":"set_limit","target":{"kind":"global","metadata":"canary"},"rate":{"capacity":1,"refill_tokens":1,"period_ms":1}}"#,
        r#"{"action":"set_limit","target":{"kind":"global"},"rate":{"capacity":0,"refill_tokens":1,"period_ms":1}}"#,
        r#"{"action":"set_limit","target":{"kind":"global"},"rate":{"capacity":1,"refill_tokens":1,"period_ms":86400001}}"#,
    ] {
        assert!(
            Change::from_bytes(change.as_bytes()).is_err(),
            "invalid change accepted"
        );
    }
    assert!(Change::from_bytes(&vec![b' '; 4097]).is_err());
    let dir = Directory::new();
    let mut store = ControlStore::create(&dir.db()).unwrap();
    let mut invalid = context();
    invalid.schema_version = 2;
    assert!(matches!(store.admit(&invalid, 0), Err(Error::Input)));
    assert!(matches!(
        store.apply(
            Change::SetLimit {
                target: Target::Global {},
                rate: rate(1, 0, 1)
            },
            reference(99),
            0
        ),
        Err(Error::Input)
    ));
}

#[test]
fn configuration_and_history_stay_bounded_without_losing_active_controls() {
    let dir = Directory::new();
    let mut store = ControlStore::create(&dir.db()).unwrap();
    for n in 0..256 {
        store
            .apply(
                Change::Disable {
                    target: Target::Agent {
                        reference: reference(n),
                    },
                },
                reference(99),
                1000,
            )
            .unwrap();
    }
    assert!(matches!(
        store.apply(
            Change::Disable {
                target: Target::Agent {
                    reference: reference(999)
                }
            },
            reference(99),
            1000
        ),
        Err(Error::Capacity)
    ));
    for n in 0..128 {
        set(
            &mut store,
            Target::Principal {
                reference: reference(n),
            },
            rate(1, 1, 1000),
            1000,
        );
    }
    assert!(matches!(
        store.apply(
            Change::SetLimit {
                target: Target::Global {},
                rate: rate(1, 1, 1)
            },
            reference(99),
            1000
        ),
        Err(Error::Capacity)
    ));
    let snapshot = store.status().unwrap();
    assert_eq!(
        (
            snapshot.revision,
            snapshot.disabled.len(),
            snapshot.limits.len()
        ),
        (384, 256, 128)
    );
    let history = store.history().unwrap();
    assert_eq!(history.len(), 256);
    assert_eq!(history[0].revision, 129);
    assert_eq!(history.last().unwrap().revision, 384);
    assert!(history.iter().all(|h| h.operator_ref == reference(99)));
    drop(store);
    assert_eq!(
        ControlStore::open(&dir.db())
            .unwrap()
            .status()
            .unwrap()
            .disabled
            .len(),
        256
    );
    assert!(std::fs::metadata(dir.db()).unwrap().len() < 4_194_304);
}

#[test]
fn missing_busy_corrupt_or_unexpected_schema_fails_closed() {
    let dir = Directory::new();
    assert!(matches!(ControlStore::open(&dir.db()), Err(Error::Path)));
    let mut store = ControlStore::create(&dir.db()).unwrap();
    assert!(matches!(ControlStore::create(&dir.db()), Err(Error::Path)));
    let connection = rusqlite::Connection::open(dir.db()).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    assert!(matches!(store.admit(&context(), 1000), Err(Error::Storage)));
    connection
        .execute_batch("ROLLBACK; CREATE TABLE unrelated(value TEXT);")
        .unwrap();
    assert!(matches!(store.admit(&context(), 1000), Err(Error::Storage)));
    drop(store);
    drop(connection);
    std::fs::write(dir.db(), b"malformed database").unwrap();
    assert!(ControlStore::open(&dir.db()).is_err());
}

#[cfg(unix)]
#[test]
fn storage_is_private_and_symlinks_are_rejected() {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    let dir = Directory::new();
    drop(ControlStore::create(&dir.db()).unwrap());
    assert_eq!(
        std::fs::metadata(dir.db()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let link = dir.0.join("link.db");
    symlink(dir.db(), &link).unwrap();
    assert!(matches!(ControlStore::open(&link), Err(Error::Path)));
    std::fs::set_permissions(dir.db(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(ControlStore::open(&dir.db()), Err(Error::Path)));
}
