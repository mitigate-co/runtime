//! Repeatable listener demonstration. Synthetic content stays in local pipes.
use mitigate_gateway::{CallerIdentity, Fault, ToolRequest, ToolService, serve};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

struct Fixture;
impl ToolService for Fixture {
    fn tools_supported(&self) -> bool {
        true
    }
    async fn request(
        &mut self,
        caller: &CallerIdentity,
        request: ToolRequest,
        _progress: Option<mitigate_gateway::ProgressSink>,
    ) -> Result<Value, Fault> {
        assert_eq!(caller.client_ref(), Some("cli_fixture"));
        assert!(caller.principal_ref().is_none());
        match request {
            ToolRequest::List { .. } => Ok(json!({"tools":[super::tool("read_status")]})),
            ToolRequest::Call { .. } => Err(Fault::Denied),
        }
    }
}
pub(super) fn verify() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (server, client) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let mut client = BufReader::new(client);
        let profile = CallerIdentity::from_profile(br#"{"schema_version":1,"client_ref":"cli_fixture"}"#).unwrap();
        let mut service = Fixture;
        let (result, ()) = tokio::join!(
            serve(BufReader::new(read), write, &mut service, profile, std::future::pending()),
            async {
                for message in [
                    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"untrusted_fixture","version":"1"}}}),
                    json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                    json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
                    json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_status","arguments":{"secret":"listener-canary"}}}),
                ] {
                    client.write_all(format!("{message}\n").as_bytes()).await.unwrap();
                    if let Some(id) = message.get("id") {
                        let mut line = String::new();
                        client.read_line(&mut line).await.unwrap();
                        let reply: Value = serde_json::from_str(&line).unwrap();
                        assert_eq!(&reply["id"], id);
                        match id.as_u64().unwrap() {
                            1 => assert_eq!(reply["result"]["capabilities"], json!({"tools":{}})),
                            2 => assert_eq!(reply["result"]["tools"][0]["name"], "read_status"),
                            3 => { assert_eq!(reply["error"]["code"], -32001); assert!(!line.contains("canary")); },
                            _ => unreachable!(),
                        }
                    }
                }
                client.shutdown().await.unwrap();
            }
        );
        assert_eq!(result, Ok(()));
    });
    println!(
        "Listener contract verified: initialization, explicit identity, tool listing and content-free denial. No tool executed."
    );
}
