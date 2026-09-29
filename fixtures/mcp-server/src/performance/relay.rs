use super::{Case, Result};
use mitigate_gateway::{CallerIdentity, Fault, ToolRequest, ToolService, serve};
use mitigate_mcp::{LaunchConfig, StdioServer};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    time::timeout,
};

async fn exchange(
    read: &mut (impl AsyncBufRead + Unpin),
    write: &mut (impl AsyncWrite + Unpin),
    message: Value,
) -> Result<Value> {
    timeout(Duration::from_secs(5), async {
        write
            .write_all(format!("{message}\n").as_bytes())
            .await
            .map_err(|_| ())?;
        write.flush().await.map_err(|_| ())?;
        if message.get("id").is_none() {
            return Ok(Value::Null);
        }
        let mut bytes = Vec::new();
        loop {
            let chunk = read.fill_buf().await.map_err(|_| ())?;
            if chunk.is_empty() {
                return Err(());
            }
            let end = chunk.iter().position(|b| *b == b'\n').map(|i| i + 1);
            let count = end.unwrap_or(chunk.len());
            if bytes.len() + count > 4096 {
                return Err(());
            }
            bytes.extend_from_slice(&chunk[..count]);
            read.consume(count);
            if end.is_some() {
                break;
            }
        }
        let response: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
        if response["id"] != message["id"] || response.get("error").is_some() {
            return Err(());
        }
        Ok(response)
    })
    .await
    .map_err(|_| ())?
}
async fn initialize(
    read: &mut (impl AsyncBufRead + Unpin),
    write: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
    let response = exchange(read,write,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"synthetic-benchmark","version":"1"}}})).await?;
    if response["result"]["protocolVersion"] != "2025-11-25" {
        return Err(());
    }
    exchange(
        read,
        write,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await?;
    Ok(())
}
async fn sample_pipe(
    name: &'static str,
    count: usize,
    warmup: usize,
    read: &mut (impl AsyncBufRead + Unpin),
    write: &mut (impl AsyncWrite + Unpin),
) -> Value {
    let mut case = Case::new(name, count, warmup);
    let mut id = 2;
    while case.next() {
        let start = Instant::now();
        let response = exchange(read,write,json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"read_status","arguments":{"value":1}}})).await;
        let ok = response.is_ok_and(|v| v["result"]["structuredContent"]["ok"] == true);
        case.record(start.elapsed(), ok);
        id += 1;
    }
    case.finish()
}

// This test-only service authorizes only the fixed local synthetic call. It is
// not exported from Runtime and is never selectable by the customer CLI.
struct Relay(StdioServer);
impl ToolService for Relay {
    fn tools_supported(&self) -> bool {
        true
    }
    async fn request(
        &mut self,
        _: &CallerIdentity,
        request: ToolRequest,
        _: Option<mitigate_gateway::ProgressSink>,
    ) -> std::result::Result<Value, Fault> {
        match request {
            ToolRequest::Call {
                name,
                arguments,
                meta,
            } if name == "read_status" && arguments == json!({"value":1}) && meta.is_none() => self
                .0
                .call_with_gate(&name, arguments, None, || async { Ok::<(), ()>(()) })
                .await
                .map_err(|_| Fault::Upstream),
            _ => Err(Fault::Denied),
        }
    }
}

pub(super) async fn measure(
    root: &Path,
    count: usize,
    warmup: usize,
    output: &mut Vec<Value>,
) -> Result<()> {
    let executable = std::env::current_exe().map_err(|_| ())?;
    let mut command = tokio::process::Command::new(&executable);
    command
        .arg("relay-schema")
        .current_dir(root)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for key in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|_| ())?;
    let mut read = BufReader::new(child.stdout.take().ok_or(())?);
    let mut write = child.stdin.take().ok_or(())?;
    initialize(&mut read, &mut write).await?;
    output.push(
        sample_pipe(
            "direct_stdio_roundtrip",
            count,
            warmup,
            &mut read,
            &mut write,
        )
        .await,
    );
    drop(write);
    if !timeout(Duration::from_secs(5), child.wait())
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?
        .success()
    {
        return Err(());
    }

    let config = LaunchConfig::from_bytes(&serde_json::to_vec(&json!({"schema_version":1,"executable_path":executable,"working_directory":root,"argv":["relay-schema"],"timeout_ms":5000})).map_err(|_| ())?).map_err(|_| ())?;
    let mut server = StdioServer::connect(&config).await.map_err(|_| ())?;
    output.push(super::measure("classify_one_tool", count, warmup, || {
        std::hint::black_box(
            server
                .inventory()
                .classify(&Default::default())
                .map_err(|_| ())?,
        );
        Ok(())
    }));
    let mut case = Case::new("managed_stdio_roundtrip", count, warmup);
    while case.next() {
        let started = Instant::now();
        let result = server
            .call_with_gate("read_status", json!({"value":1}), None, || async {
                Ok::<(), ()>(())
            })
            .await;
        case.record(
            started.elapsed(),
            result.is_ok_and(|v| v["structuredContent"]["ok"] == true),
        );
    }
    output.push(case.finish());
    server.close().await.map_err(|_| ())?;

    let mut relay = Relay(StdioServer::connect(&config).await.map_err(|_| ())?);
    let (server, client) = tokio::io::duplex(8192);
    let (read, write) = tokio::io::split(server);
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut client_read = BufReader::new(client_read);
    let (served, measured) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut relay,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async move {
            // A split write-half drop alone does not close a duplex stream while
            // its read half remains owned. Shut down and drop both on all paths.
            let result = async {
                initialize(&mut client_read, &mut client_write).await?;
                Ok::<_, ()>(
                    sample_pipe(
                        "listener_managed_stdio_roundtrip",
                        count,
                        warmup,
                        &mut client_read,
                        &mut client_write,
                    )
                    .await,
                )
            }
            .await;
            let shutdown = client_write.shutdown().await.map_err(|_| ());
            drop(client_write);
            drop(client_read);
            shutdown?;
            result
        }
    );
    relay.0.close().await.map_err(|_| ())?;
    output.push(measured?);
    served.map_err(|_| ())?;
    Ok(())
}
