//! Actual executable/client/upstream contract. No customer configs or tool calls.
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

struct Project(PathBuf);
impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}
impl Client {
    fn start(binary: &Path, launch: &Path) -> Self {
        Self::start_audited(binary, launch, None)
    }
    fn start_audited(binary: &Path, launch: &Path, audit: Option<&Path>) -> Self {
        let mut command = tokio::process::Command::new(binary);
        command
            .args(["mcp", "serve", "--launch-config"])
            .arg(launch)
            .args(["--allow-exec", "--inventory-only"]);
        if let Some(db) = audit {
            command.arg("--audit-db").arg(db);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start local CLI fixture");
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
        let count = timeout(Duration::from_secs(5), self.output.read_line(&mut line))
            .await
            .expect("bounded CLI response")
            .unwrap();
        assert!(count > 0, "CLI protocol response required");
        assert!(count <= 1_048_576, "bounded MCP output frame");
        serde_json::from_str(&line).expect("MCP only on stdout")
    }
    async fn initialize(&mut self) {
        self.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})).await;
        assert_eq!(
            self.read().await["result"]["serverInfo"]["name"],
            "mitigate"
        );
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
    }
    async fn finish(&mut self, code: i32) {
        let status = timeout(Duration::from_secs(13), self.child.wait())
            .await
            .expect("CLI must exit without another stdin byte")
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .await
            .unwrap();
        assert!(
            !stderr.contains("canary"),
            "operational errors exclude content"
        );
        if code == 0 {
            assert!(stderr.is_empty());
        }
    }
}

pub(super) fn verify(binary: &Path) {
    let directory =
        std::env::temp_dir().join(format!("mitigate-gateway-contract-{}", std::process::id()));
    fs::create_dir(&directory).expect("exclusive synthetic fixture directory");
    let project = Project(directory);
    let launch = project.0.join("launch.json");
    let marker = project.0.join("must-not-call");
    fs::write(&launch, serde_json::to_vec(&json!({"schema_version":1,"executable_path":std::env::current_exe().unwrap(),"working_directory":project.0,"argv":["relay","unused",marker],"timeout_ms":5000})).unwrap()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut client = Client::start(binary, &launch);
        client.initialize().await;
        client.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
        assert_eq!(client.read().await["result"]["tools"][0]["name"], "read_status");
        client.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_status","arguments":{"value":"call-secret-canary"}}})).await;
        let disabled = client.read().await;
        assert_eq!(disabled["error"]["code"], -32006);
        assert!(!disabled.to_string().contains("canary"));
        assert!(!marker.exists(), "inventory mode must never invoke the upstream tool");
        // Drop the OS pipe handle to deliver EOF on every platform; AsyncWrite
        // shutdown alone does not close a Windows anonymous pipe.
        client.input.take();
        client.finish(0).await;

        verify_audit(binary,&launch,&project.0,&marker).await;

        for (mode, count) in [("relay-many",40), ("relay-large",20)] {
            fs::write(&launch, serde_json::to_vec(&json!({"schema_version":1,"executable_path":std::env::current_exe().unwrap(),"working_directory":project.0,"argv":[mode],"timeout_ms":5000})).unwrap()).unwrap();
            let mut client = Client::start(binary, &launch);
            client.initialize().await;
            let mut params = json!({});
            let mut found = Vec::new();
            for id in 2..34 {
                client.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":params})).await;
                let result = client.read().await["result"].clone();
                for tool in result["tools"].as_array().expect("tool page") { found.push(tool["name"].as_str().unwrap().to_owned()); }
                if let Some(cursor) = result.get("nextCursor") { params = json!({"cursor":cursor}); } else { break; }
            }
            assert_eq!(found.len(), count);
            found.sort(); found.dedup(); assert_eq!(found.len(), count);
            client.input.take();
            client.finish(0).await;
        }

        let mut client = Client::start(binary, &launch);
        client.initialize().await;
        client.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
        // The large page fills the OS stdout pipe. Leave it unread and require
        // the output deadline to end the CLI with both pipe workers blocked.
        client.finish(2).await;

        let mut client = Client::start(binary, &launch);
        client.initialize().await;
        client.input.as_mut().unwrap().write_all(b"{\"secret\":\"partial-canary").await.unwrap();
        // Keep stdin open. The partial-frame deadline must end the CLI even though
        // the OS stdin worker is still blocked waiting for additional bytes.
        client.finish(2).await;
    });
    println!(
        "Gateway CLI verified: inventory, denied calls, native audit, fail-closed audit errors, EOF and bounded shutdown."
    );
}

async fn audit_command(binary: &Path, args: &[&str]) -> std::process::Output {
    let output = timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(binary)
            .args(["mcp", "audit"])
            .args(args)
            .arg("--json")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains("canary"));
    }
    output
}
async fn verify_audit(binary: &Path, launch: &Path, root: &Path, marker: &Path) {
    let db = root.join("audit.sqlite");
    let db_arg = db.to_str().unwrap();
    assert!(
        audit_command(binary, &["init", "--db", db_arg])
            .await
            .status
            .success()
    );
    let mut client = Client::start_audited(binary, launch, Some(&db));
    client.initialize().await;
    client
        .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
        .await;
    assert!(client.read().await["result"]["tools"].is_array());
    client.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_status","arguments":{"value":"audit-argument-canary"},"_meta":{"canary":"audit-metadata-canary"}}})).await;
    assert_eq!(client.read().await["error"]["code"], -32006);
    // A competing writer must prevent a success response without a committed
    // event. No tool invocation occurs in this inventory-only endpoint.
    let blocker = rusqlite::Connection::open(&db).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    client
        .send(json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}))
        .await;
    assert_eq!(client.read().await["error"]["code"], -32007);
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    client.input.take();
    client.finish(0).await;
    assert!(!marker.exists());
    let output = audit_command(binary, &["list", "--db", db_arg, "--limit", "1"]).await;
    assert!(output.status.success());
    let first: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(first["next_after"], 1);
    assert_eq!(
        first["records"][0]["event"]["detail"]["operation"],
        "inventory"
    );
    let output = audit_command(binary, &["list", "--db", db_arg, "--after", "1"]).await;
    let second: Value = serde_json::from_slice(&output.stdout).unwrap();
    let detail = &second["records"][0]["event"]["detail"];
    assert_eq!(second["records"].as_array().unwrap().len(), 1);
    assert_eq!(detail["decision"], "deny");
    assert_eq!(detail["result_class"], "not_invoked");
    assert_eq!(detail["attribution"], "unknown");
    assert!(detail["client_ref"].is_null());
    assert!(detail["schema_fingerprint"].is_string());
    assert!(
        detail["capability_classes"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );
    let bytes = fs::read(&db).unwrap();
    assert!(!bytes.windows(b"canary".len()).any(|w| w == b"canary"));
    assert!(
        audit_command(binary, &["verify", "--db", db_arg])
            .await
            .status
            .success()
    );
    assert_eq!(
        audit_command(binary, &["prune", "--db", db_arg])
            .await
            .status
            .code(),
        Some(2)
    );
    assert!(
        audit_command(binary, &["prune", "--db", db_arg, "--confirm"])
            .await
            .status
            .success()
    );
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute("DELETE FROM records WHERE sequence=2", [])
        .unwrap();
    let failed = audit_command(binary, &["verify", "--db", db_arg]).await;
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&failed.stderr).unwrap()["error"],
        "audit_integrity_failed"
    );
    // A corrupt database must reject startup before executing the configured child.
    let blocked_launch = root.join("audit-blocked-launch.json");
    fs::write(&blocked_launch,serde_json::to_vec(&json!({"schema_version":1,"executable_path":std::env::current_exe().unwrap(),"working_directory":root,"argv":["credential",marker],"timeout_ms":5000})).unwrap()).unwrap();
    let mut blocked = Client::start_audited(binary, &blocked_launch, Some(&db));
    blocked.finish(2).await;
    assert!(!marker.exists());
}
