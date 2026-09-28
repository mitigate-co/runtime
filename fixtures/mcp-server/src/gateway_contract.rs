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
        let mut child = tokio::process::Command::new(binary)
            .args(["mcp", "serve", "--launch-config"])
            .arg(launch)
            .args(["--allow-exec", "--inventory-only"])
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
        "Gateway CLI verified: real upstream inventory, disabled calls, clean EOF and bounded shutdown with stdin held open."
    );
}
