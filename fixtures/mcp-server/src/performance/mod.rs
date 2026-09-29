//! Explicit synthetic measurements, never customer discovery or telemetry.
mod relay;
mod stats;
use mitigate_audit::{AuditStore, EventDetails, Operation, Retention};
use mitigate_fingerprint::{Domain, canonicalize, fingerprint};
use mitigate_policy::{Decision, Policy, PolicyInput};
use serde_json::{Value, json};
use stats::Case;
use std::{fs, hint::black_box, path::PathBuf, time::Instant};

type Result<T> = std::result::Result<T, ()>;
struct Workspace(PathBuf, bool);
impl Workspace {
    fn create() -> Result<Self> {
        let suffix = mitigate_egress::SyncRef::fresh().map_err(|_| ())?;
        let path = std::env::temp_dir().join(format!("mitigate-benchmark-{}", suffix.as_str()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|_| ())?;
        Ok(Self(path, false))
    }
    fn remove(&mut self) -> Result<()> {
        fs::remove_dir_all(&self.0).map_err(|_| ())?;
        self.1 = true;
        Ok(())
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        if !self.1 {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn options(args: &[String]) -> Result<(usize, usize)> {
    if args.is_empty() {
        return Ok((100, 10));
    }
    if args.len() != 4 || args[0] != "--samples" || args[2] != "--warmup" {
        return Err(());
    }
    let parse = |value: &str| {
        if value.is_empty() || value.len() > 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(());
        }
        value.parse::<usize>().map_err(|_| ())
    };
    let count = parse(&args[1])?;
    let warmup = parse(&args[3])?;
    if !(5..=500).contains(&count) || warmup > 50 {
        return Err(());
    }
    Ok((count, warmup))
}
fn measure(
    name: &'static str,
    count: usize,
    warmup: usize,
    mut operation: impl FnMut() -> Result<()>,
) -> Value {
    let mut case = Case::new(name, count, warmup);
    while case.next() {
        let start = Instant::now();
        let ok = operation().is_ok();
        case.record(start.elapsed(), ok);
    }
    case.finish()
}
fn cpu_and_storage(
    root: &Workspace,
    count: usize,
    warmup: usize,
    output: &mut Vec<Value>,
) -> Result<()> {
    let schema = json!({"type":"object","properties":(0..32).map(|i|(format!("field_{i}"),json!({"type":"string","maxLength":256}))).collect::<serde_json::Map<_,_>>(),"additionalProperties":false});
    output.push(measure("canonicalize_32_fields", count, warmup, || {
        black_box(canonicalize(black_box(&schema)).map_err(|_| ())?);
        Ok(())
    }));
    output.push(measure("fingerprint_32_fields", count, warmup, || {
        black_box(fingerprint(Domain::InputSchema, black_box(&schema)).map_err(|_| ())?);
        Ok(())
    }));
    for (name, servers) in [
        ("scan_1_server", 1usize),
        ("scan_32_servers", 32),
        ("scan_128_servers", 128),
    ] {
        let project = root.0.join(name);
        fs::create_dir(&project).map_err(|_| ())?;
        fs::create_dir(project.join(".cursor")).map_err(|_| ())?;
        for (file, size) in [
            (".mcp.json", servers.div_ceil(2)),
            (".cursor/mcp.json", servers / 2),
        ] {
            let declarations = (0..size)
                .map(|i| {
                    (
                        format!("fixture_{i}"),
                        json!({"command":"synthetic-not-executed","args":["fixed"]}),
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            fs::write(
                project.join(file),
                serde_json::to_vec(&json!({"mcpServers":declarations})).map_err(|_| ())?,
            )
            .map_err(|_| ())?;
        }
        output.push(measure(name, count, warmup, || {
            let report =
                mitigate_mcp_scan::scan_project(&project, &mitigate_config::ScanLimits::default())
                    .map_err(|_| ())?;
            if black_box(report).servers.len() != servers {
                return Err(());
            }
            Ok(())
        }));
    }
    let source = include_str!("../../../../examples/policies/read-and-review.rego");
    output.push(measure("policy_compile", count, warmup, || {
        black_box(Policy::compile(black_box(source)).map_err(|_| ())?);
        Ok(())
    }));
    let mut policy = Policy::compile(source).map_err(|_| ())?;
    let input = PolicyInput::from_bytes(&serde_json::to_vec(&json!({"schema_version":1,"client":null,"principal":"a".repeat(64),"agent":null,"server":"b".repeat(64),"tool":"c".repeat(64),"schema_fingerprint":"d".repeat(64),"capabilities":["read_data"],"schema_changed":false,"grant":"explicit","offline":true})).map_err(|_| ())?).map_err(|_| ())?;
    output.push(measure("policy_evaluate", count, warmup, || {
        if policy.evaluate(black_box(&input)).map_err(|_| ())? != Decision::Allow {
            return Err(());
        }
        Ok(())
    }));
    let event = include_bytes!("../../../../examples/egress/decision.json");
    output.push(measure("egress_validate_decision", count, warmup, || {
        black_box(mitigate_egress::CheckedEvent::from_bytes(black_box(event)).map_err(|_| ())?);
        Ok(())
    }));
    let mut audit =
        AuditStore::create(&root.0.join("audit.sqlite"), Retention::default()).map_err(|_| ())?;
    let identity =
        fingerprint(Domain::ServerIdentity, &json!("synthetic-server")).map_err(|_| ())?;
    output.push(measure(
        "audit_append_growing_history",
        count,
        warmup,
        || {
            let detail =
                EventDetails::new(&Default::default(), identity.clone(), Operation::ToolCall);
            black_box(audit.append(detail).map_err(|_| ())?);
            Ok(())
        },
    ));
    let verification = audit.verify().map_err(|_| ())?;
    if output.last().is_some_and(|v| v["status"] == "ok")
        && verification.records != (count + warmup) as u64
    {
        return Err(());
    }
    Ok(())
}

pub(super) fn run(args: &[String]) -> i32 {
    let Ok((count, warmup)) = options(args) else {
        println!("{{\"schema_version\":1,\"error\":\"benchmark_arguments\"}}");
        return 2;
    };
    let mut results = Vec::new();
    let outcome = (|| {
        let mut root = Workspace::create()?;
        cpu_and_storage(&root, count, warmup, &mut results)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ())?;
        runtime.block_on(relay::measure(&root.0, count, warmup, &mut results))?;
        root.remove()?;
        Ok::<_, ()>(())
    })();
    let ok = outcome.is_ok() && results.iter().all(|v| v["status"] == "ok");
    println!(
        "{}",
        json!({"schema_version":1,"fixture":"runtime-synthetic-v1","runtime_version":env!("CARGO_PKG_VERSION"),"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"build":if cfg!(debug_assertions){"debug"}else{"release"},"status":if ok{"ok"}else{"failed"},"harness_failed":outcome.is_err(),"cases":results})
    );
    if ok { 0 } else { 2 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn options_bound_work_and_cannot_select_customer_paths_or_commands() {
        assert_eq!(options(&[]), Ok((100, 10)));
        for args in [
            vec!["--samples", "501", "--warmup", "1"],
            vec!["--samples", "5", "--warmup", "51"],
            vec!["--samples", "0", "--warmup", "0"],
            vec!["--samples", "+5", "--warmup", "0"],
            vec!["--root", "private"],
        ] {
            assert!(options(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
        }
    }
}
