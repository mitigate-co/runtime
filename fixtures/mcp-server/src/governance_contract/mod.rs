//! Real CLI governance against our own synthetic child and isolated local stores.
mod cases;
mod changes;
mod offline;
use mitigate_audit::{AuditStore, Retention};
use mitigate_fingerprint::Fingerprint;
use mitigate_mcp::{LaunchConfig, LaunchReview, Snapshot, StdioServer};
use mitigate_policy::{
    Authority, PolicyStore, SignedBundle, SystemClock,
    approvals::{ApprovalStore, Choice, Record, State},
    controls::{Change, ControlStore},
    public_key,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout},
    time::timeout,
};

fn reference(ch: char) -> Fingerprint {
    serde_json::from_value(json!(ch.to_string().repeat(64))).unwrap()
}
fn write(path: &Path, value: Value) {
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}
struct Project(PathBuf);
impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Project {
    async fn new(root: &Path, label: &str, mode: &str, decision: &str, ttl: u64) -> Self {
        eprintln!("Governance contract: {label}");
        let project = Self(root.join(label));
        fs::create_dir(&project.0).unwrap();
        let config = LaunchConfig::from_bytes(&serde_json::to_vec(&json!({
            "schema_version":1,"executable_path":std::env::current_exe().unwrap(),"working_directory":project.0,
            "argv":[mode,project.path("child-address"),project.path("call-marker")],"timeout_ms":30000
        })).unwrap()).unwrap();
        // LaunchConfig has no Serialize because it can contain sensitive facts.
        write(
            &project.path("launch.json"),
            json!({"schema_version":1,
            "executable_path":std::env::current_exe().unwrap(),"working_directory":project.0,
            "argv":[mode,project.path("child-address"),project.path("call-marker")],"timeout_ms":30000}),
        );
        LaunchReview::create(&config)
            .await
            .unwrap()
            .write_new(&project.path("review.json"))
            .unwrap();
        let mut upstream = StdioServer::connect(&config).await.unwrap();
        Snapshot::from_inventory(upstream.inventory())
            .unwrap()
            .write_new(&project.path("snapshot.json"))
            .unwrap();
        upstream.close().await.unwrap();
        let authority = project.authority();
        write(
            &project.path("trust.json"),
            serde_json::to_value(&authority).unwrap(),
        );
        drop(PolicyStore::create(&project.path("policy.sqlite"), authority).unwrap());
        project.policy(1, decision);
        project.grants(true);
        drop(ApprovalStore::create(&project.path("approvals.sqlite")).unwrap());
        drop(ControlStore::create(&project.path("controls.sqlite")).unwrap());
        drop(AuditStore::create(&project.path("audit.sqlite"), Retention::default()).unwrap());
        write(
            &project.path("profile.json"),
            json!({"schema_version":1,"client_ref":"governance-client-canary","principal_ref":"governance-principal-canary"}),
        );
        write(
            &project.path("governance.json"),
            json!({"schema_version":1,"policy_db":project.path("policy.sqlite"),
            "policy_authority":project.path("trust.json"),"grants":project.path("grants.json"),
            "approvals_db":project.path("approvals.sqlite"),"controls_db":project.path("controls.sqlite"),
            "audit_db":project.path("audit.sqlite"),"tool_snapshot":project.path("snapshot.json"),
            "classification_overrides":null,"environment":null,"approval_timeout_ms":ttl}),
        );
        project
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn authority(&self) -> Authority {
        Authority {
            schema_version: 1,
            policy_ref: reference('a'),
            public_key: public_key(&[7; 32]),
        }
    }
    fn policy(&self, version: u64, decision: &str) {
        let source = if decision == "deny" {
            "package mitigate.mcp\ndefault decision := \"deny\"".to_owned()
        } else {
            format!(
                "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"{decision}\" if {{ input.grant == \"explicit\" }}"
            )
        };
        let bundle = SignedBundle::sign(reference('a'), version, source, &[7; 32]).unwrap();
        PolicyStore::open(&self.path("policy.sqlite"), self.authority())
            .unwrap()
            .activate(&bundle)
            .unwrap();
    }
    fn grants(&self, allow: bool) {
        write(
            &self.path("grants.json"),
            json!({"schema_version":1,"grants":[{"grant_ref":"f".repeat(64),
            "effect":if allow {"allow"} else {"deny"},"scope":{"client":null,"principal":null,"agent":null,
            "server":null,"tool":null,"capabilities":null,"environment":null,"not_before_ms":null,"expires_at_ms":null}}]}),
        );
    }
    fn control(&self, change: Change) {
        ControlStore::open(&self.path("controls.sqlite"))
            .unwrap()
            .apply(change, reference('2'), SystemClock)
            .unwrap();
    }
    async fn pending(&self) -> Record {
        timeout(Duration::from_secs(15), async {
            loop {
                let records = ApprovalStore::open(&self.path("approvals.sqlite"))
                    .unwrap()
                    .list(SystemClock)
                    .unwrap();
                if let Some(record) = records.into_iter().find(|r| r.state == State::Requested) {
                    return record;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("pending approval timed out in {}", self.0.display()))
    }
    fn decide(&self, record: &Record, choice: Choice) {
        ApprovalStore::open(&self.path("approvals.sqlite"))
            .unwrap()
            .decide(&record.approval_ref, choice, reference('3'), SystemClock)
            .unwrap();
    }
    fn events(&self) -> Vec<Value> {
        AuditStore::open(&self.path("audit.sqlite"))
            .unwrap()
            .page(0, 100)
            .unwrap()
            .records
            .into_iter()
            .map(|r| serde_json::to_value(r.event).unwrap())
            .collect()
    }
    fn private(&self) {
        for file in [
            "audit.sqlite",
            "approvals.sqlite",
            "controls.sqlite",
            "policy.sqlite",
        ] {
            let bytes = fs::read(self.path(file)).unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains("canary"),
                "local stores must exclude workload/identity text"
            );
        }
    }
}
struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}
impl Client {
    fn start(binary: &Path, project: &Project, known: bool) -> Self {
        let mut command = tokio::process::Command::new(binary);
        command
            .args(["mcp", "serve", "--allow-exec", "--launch-config"])
            .arg(project.path("launch.json"))
            .arg("--launch-review")
            .arg(project.path("review.json"))
            .arg("--enforce")
            .arg(project.path("governance.json"));
        if known {
            command.arg("--profile").arg(project.path("profile.json"));
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Self {
            input: child.stdin.take(),
            output: BufReader::new(child.stdout.take().unwrap()),
            child,
        }
    }
    async fn send(&mut self, message: Value) {
        timeout(
            Duration::from_secs(5),
            self.input
                .as_mut()
                .unwrap()
                .write_all(format!("{message}\n").as_bytes()),
        )
        .await
        .unwrap()
        .unwrap();
    }
    async fn read(&mut self) -> Value {
        let mut line = String::new();
        let count = timeout(Duration::from_secs(45), self.output.read_line(&mut line))
            .await
            .expect("bounded CLI response")
            .unwrap();
        assert!(count > 0 && count <= 1_048_576, "MCP response required");
        serde_json::from_str(&line).unwrap()
    }
    async fn initialize(&mut self) {
        self.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"untrusted-client","version":"1"}}})).await;
        assert_eq!(
            self.read().await["result"]["serverInfo"]["name"],
            "mitigate"
        );
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
    }
    async fn call(&mut self, id: u32, args: Value) {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"read_status","arguments":args,
            "_meta":{"progressToken":"downstream-token","principal_ref":"forged-admin-canary"}}})).await;
    }
    async fn result(&mut self, id: u32) -> (Value, usize) {
        let mut updates = 0;
        loop {
            let message = self.read().await;
            if message.get("method").is_some() {
                assert_eq!(message["method"], "notifications/progress");
                assert_eq!(message["params"]["progressToken"], "downstream-token");
                assert!(!message.to_string().contains("canary"));
                updates += 1;
            } else {
                assert_eq!(message["id"], id);
                return (message, updates);
            }
        }
    }
    async fn finish(&mut self, code: i32) {
        self.input.take();
        let status = timeout(Duration::from_secs(20), self.child.wait())
            .await
            .expect("bounded CLI cleanup")
            .unwrap();
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .await
            .unwrap();
        assert!(!stderr.contains("canary"));
        assert_eq!(status.code(), Some(code), "{stderr}");
    }
}
pub(super) fn verify(binary: &Path) {
    let root = Project(std::env::temp_dir().join(format!(
        "mitigate-governance-contract-{}",
        std::process::id()
    )));
    fs::create_dir(&root.0).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(cases::run(binary, &root.0));
    println!(
        "Governance verified: reviewed CLI calls, policy/grants, one-call approvals, controls, progress, failure cleanup and private audit."
    );
}

pub(super) fn verify_offline(binary: &Path) {
    let root = Project(
        std::env::temp_dir().join(format!("mitigate-offline-contract-{}", std::process::id())),
    );
    fs::create_dir(&root.0).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(offline::run(binary, &root.0));
    println!(
        "Offline authority verified: cached decisions, rejected refreshes, restart and local approval failure/recovery."
    );
}

// Called only by our synthetic child during its second inventory response.
// This makes the final-gate race deterministic without timing assumptions.
pub(super) fn change_during_refresh(mode: &str, directory: &Path) {
    if mode == "relay-governance-stop" {
        ControlStore::open(&directory.join("controls.sqlite"))
            .unwrap()
            .apply(Change::Stop {}, reference('2'), SystemClock)
            .unwrap();
    } else {
        assert_eq!(mode, "relay-governance-revoke");
        let mut approvals = ApprovalStore::open(&directory.join("approvals.sqlite")).unwrap();
        let record = approvals
            .list(SystemClock)
            .unwrap()
            .into_iter()
            .find(|r| r.state == State::Approved)
            .unwrap();
        approvals
            .decide(
                &record.approval_ref,
                Choice::Deny,
                reference('4'),
                SystemClock,
            )
            .unwrap();
    }
}
