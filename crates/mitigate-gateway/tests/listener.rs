//! Client-facing protocol, identity and cancellation tests over real async pipes.
use mitigate_gateway::{
    CallerIdentity, Error, Fault, IdentityConfidence, IdentitySource, ToolRequest, ToolService,
    serve,
};
use serde_json::{Value, json};
use std::{cell::Cell, rc::Rc};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

#[derive(Default)]
struct Service {
    calls: Vec<(Value, bool)>,
    pending: bool,
    delayed: bool,
    no_tools: bool,
    dropped: Rc<Cell<bool>>,
}
struct Cleanup(Rc<Cell<bool>>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        self.0.set(true);
    }
}
impl ToolService for Service {
    fn tools_supported(&self) -> bool {
        !self.no_tools
    }
    async fn request(
        &mut self,
        caller: &CallerIdentity,
        request: ToolRequest,
    ) -> Result<Value, Fault> {
        let _cleanup = Cleanup(self.dropped.clone());
        self.calls.push((
            serde_json::to_value(caller).unwrap(),
            matches!(request, ToolRequest::Call { .. }),
        ));
        if self.pending {
            std::future::pending::<()>().await;
        }
        if self.delayed {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        match request {
            ToolRequest::List { cursor } => {
                if cursor.is_some() {
                    Err(Fault::InvalidParams)
                } else {
                    Ok(json!({"tools":[]}))
                }
            }
            ToolRequest::Call {
                name,
                arguments,
                meta,
            } => {
                assert_eq!(name, "read_status");
                assert_eq!(arguments["secret"], "argument-canary");
                assert_eq!(meta.unwrap()["principal_ref"], "forged-admin");
                Err(Fault::Denied)
            }
        }
    }
}
type Client = BufReader<DuplexStream>;
async fn send(client: &mut Client, message: Value) {
    let mut bytes = serde_json::to_vec(&message).unwrap();
    bytes.push(b'\n');
    client.write_all(&bytes).await.unwrap();
}
async fn receive(client: &mut Client) -> Value {
    let mut line = String::new();
    assert!(client.read_line(&mut line).await.unwrap() > 0);
    serde_json::from_str(&line).unwrap()
}
fn request(id: Value, method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}
async fn initialize(client: &mut Client, version: &str) -> Value {
    send(client, request(json!(1), "initialize", json!({
        "protocolVersion":version,"capabilities":{"sampling":{},"elicitation":{},"tasks":{}},
        "clientInfo":{"name":"forged-admin","version":"client-version-canary"}
    }))).await;
    let result = receive(client).await;
    send(
        client,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    result
}

#[test]
fn profile_is_closed_bounded_and_never_claims_authentication() {
    let unknown = CallerIdentity::default();
    assert_eq!(unknown.source(), IdentitySource::Unknown);
    assert_eq!(unknown.confidence(), IdentityConfidence::Unknown);
    assert!(unknown.client_ref().is_none());
    assert!(unknown.principal_ref().is_none());
    let declared = CallerIdentity::from_profile(
        br#"{"schema_version":1,"client_ref":"cli_test","agent_ref":"agt_test"}"#,
    )
    .unwrap();
    assert_eq!(declared.source(), IdentitySource::GatewayProfile);
    assert_eq!(declared.confidence(), IdentityConfidence::Declared);
    assert_eq!(declared.client_ref(), Some("cli_test"));
    assert_eq!(declared.agent_ref(), Some("agt_test"));
    assert!(declared.principal_ref().is_none());
    for input in [
        r#"{"schema_version":2,"client_ref":"c"}"#,
        r#"{"schema_version":1,"client_ref":"c","client_ref":"forged"}"#,
        r#"{"schema_version":1,"client_ref":"c","confidence":"authenticated"}"#,
        r#"{"schema_version":1,"client_ref":""}"#,
        r#"{"schema_version":1,"client_ref":"c","principal_ref":"secret\ncanary"}"#,
        r#"{"schema_version":1,"client_ref":"c","secret":"profile-canary"}"#,
    ] {
        assert!(matches!(
            CallerIdentity::from_profile(input.as_bytes()),
            Err(Error::Profile)
        ));
    }
    assert!(matches!(
        CallerIdentity::from_profile(&vec![b' '; 4097]),
        Err(Error::Profile)
    ));
}

#[tokio::test(start_paused = true)]
async fn versions_identity_and_tool_relay_keep_content_out_of_faults() {
    for version in [
        "2025-11-25",
        "2025-06-18",
        "2025-03-26",
        "2024-11-05",
        "unsupported",
    ] {
        for configured in [false, true] {
            let (server, client) = tokio::io::duplex(4096);
            let (read, write) = tokio::io::split(server);
            let mut client = BufReader::new(client);
            let mut service = Service::default();
            let identity = if configured {
                CallerIdentity::from_profile(br#"{"schema_version":1,"client_ref":"cli_test"}"#)
                    .unwrap()
            } else {
                CallerIdentity::default()
            };
            let (outcome, ()) = tokio::join!(
                serve(
                    BufReader::new(read),
                    write,
                    &mut service,
                    identity,
                    std::future::pending()
                ),
                async {
                    let response = initialize(&mut client, version).await;
                    assert_eq!(
                        response["result"]["protocolVersion"],
                        if version == "unsupported" {
                            "2025-11-25"
                        } else {
                            version
                        }
                    );
                    assert_eq!(response["result"]["capabilities"], json!({"tools":{}}));
                    assert!(!response.to_string().contains("canary"));
                    send(&mut client, request(json!("list"), "tools/list", json!({}))).await;
                    assert_eq!(receive(&mut client).await["result"], json!({"tools":[]}));
                    send(&mut client, request(json!("call"), "tools/call", json!({"name":"read_status","arguments":{"secret":"argument-canary"},"_meta":{"principal_ref":"forged-admin"}}))).await;
                    let denied = receive(&mut client).await;
                    assert_eq!(denied["error"]["code"], -32001);
                    assert!(!denied.to_string().contains("canary"));
                    client.shutdown().await.unwrap();
                }
            );
            assert_eq!(outcome, Ok(()));
            assert_eq!(service.calls.len(), 2);
            for (caller, _) in service.calls {
                assert_eq!(caller["principal_ref"], Value::Null);
                assert_eq!(caller["agent_ref"], Value::Null);
                assert_eq!(
                    caller["client_ref"],
                    if configured {
                        json!("cli_test")
                    } else {
                        Value::Null
                    }
                );
                assert_eq!(
                    caller["identity_source"],
                    if configured {
                        "gateway_profile"
                    } else {
                        "unknown"
                    }
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn lifecycle_methods_and_bad_parameters_never_reach_service() {
    let (server, client) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(server);
    let mut client = BufReader::new(client);
    let mut service = Service::default();
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async {
            send(
                &mut client,
                request(json!("preinit"), "tools/list", json!({})),
            )
            .await;
            assert_eq!(receive(&mut client).await["error"]["code"], -32000);
            send(&mut client, request(json!("preping"), "ping", json!({}))).await;
            assert_eq!(receive(&mut client).await["result"], json!({}));
            initialize(&mut client, "2025-11-25").await;
            for (id, method, params, expected) in [
                (2, "sampling/createMessage", json!({}), -32601),
                (
                    3,
                    "tools/call",
                    json!({"name":"shell injected","arguments":{}}),
                    -32602,
                ),
                (
                    4,
                    "tools/call",
                    json!({"name":"read_status","arguments":[]}),
                    -32602,
                ),
                (
                    5,
                    "tools/call",
                    json!({"name":"read_status","task":{}}),
                    -32602,
                ),
                (6, "tools/list", json!({"cursor":42}), -32602),
                (7, "ping", json!({"secret":"canary"}), -32602),
            ] {
                send(&mut client, request(json!(id), method, params)).await;
                assert_eq!(receive(&mut client).await["error"]["code"], expected);
            }
            // Notifications have no response, even when they claim to call a tool.
            send(
                &mut client,
                json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_all"}}),
            )
            .await;
            send(&mut client, request(json!(8), "ping", json!({}))).await;
            assert_eq!(receive(&mut client).await["id"], 8);
            client.shutdown().await.unwrap();
        }
    );
    assert_eq!(outcome, Ok(()));
    assert!(service.calls.is_empty());
}

#[tokio::test(start_paused = true)]
async fn malformed_duplicate_and_reused_ids_fail_closed() {
    for bytes in [
        br#"{"jsonrpc":"2.0","id":2,"id":3,"method":"ping"}"#.as_slice(),
        br#"[{"jsonrpc":"2.0","id":2,"method":"ping"}]"#,
        br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":2.1,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":2,"method":"ping","result":{}}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}"#,
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        b"not-json-secret-canary",
        b"\xff",
    ] {
        let (server, client) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let mut client = BufReader::new(client);
        let mut service = Service::default();
        let (outcome, ()) = tokio::join!(
            serve(
                BufReader::new(read),
                write,
                &mut service,
                CallerIdentity::default(),
                std::future::pending()
            ),
            async {
                initialize(&mut client, "2025-11-25").await;
                client.write_all(bytes).await.unwrap();
                client.write_all(b"\n").await.unwrap();
                let error = receive(&mut client).await;
                assert!(error["error"].is_object());
                assert!(error["id"].is_null());
                assert!(!error.to_string().contains("canary"));
            }
        );
        assert_eq!(outcome, Err(Error::Protocol));
        assert!(service.calls.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_drops_work_while_ping_and_busy_responses_remain_available() {
    let (server, client) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(server);
    let mut client = BufReader::new(client);
    let mut service = Service {
        pending: true,
        ..Service::default()
    };
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async {
            initialize(&mut client, "2025-11-25").await;
            send(&mut client, request(json!(2), "tools/list", json!({}))).await;
            // Give the service future a chance to start; no wall-clock sleeping.
            tokio::task::yield_now().await;
            send(&mut client, request(json!(3), "ping", json!({}))).await;
            assert_eq!(receive(&mut client).await["id"], 3);
            send(&mut client, request(json!(4), "tools/list", json!({}))).await;
            assert_eq!(receive(&mut client).await["error"]["code"], -32005);
            send(&mut client, json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999,"reason":"cancel-canary"}})).await;
            send(&mut client, json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":"cancel-canary"}})).await;
            let mut remaining = String::new();
            assert_eq!(client.read_line(&mut remaining).await.unwrap(), 0);
        }
    );
    assert_eq!(outcome, Err(Error::Cancelled));
    assert_eq!(service.calls.len(), 1);
    assert!(service.dropped.get());
}

#[tokio::test(start_paused = true)]
async fn request_deadline_drops_inflight_work_and_returns_only_fixed_error() {
    let (server, client) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(server);
    let mut client = BufReader::new(client);
    let mut service = Service {
        pending: true,
        ..Service::default()
    };
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async {
            initialize(&mut client, "2025-11-25").await;
            send(&mut client, request(json!(2), "tools/list", json!({}))).await;
            let error = receive(&mut client).await;
            assert_eq!(error["id"], 2);
            assert_eq!(error["error"]["code"], -32002);
        }
    );
    assert_eq!(outcome, Err(Error::Timeout));
    assert!(service.dropped.get());
}

#[tokio::test(start_paused = true)]
async fn initialization_and_partial_frames_have_deadlines() {
    for partial in [false, true] {
        let (server, mut client) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let mut service = Service::default();
        if partial {
            client.write_all(b"{\"jsonrpc\":").await.unwrap();
        }
        let outcome = serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending(),
        )
        .await;
        assert_eq!(outcome, Err(Error::Timeout));
    }
}

#[tokio::test(start_paused = true)]
async fn oversized_and_incomplete_frames_never_reach_service() {
    for oversized in [true, false] {
        let (server, mut client) = tokio::io::duplex(2_097_152);
        let (read, write) = tokio::io::split(server);
        let mut service = Service::default();
        let bytes = if oversized {
            vec![b' '; 1_048_577]
        } else {
            b"{".to_vec()
        };
        client.write_all(&bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let result = serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending(),
        )
        .await;
        assert_eq!(
            result,
            Err(if oversized {
                Error::Limit
            } else {
                Error::Disconnected
            })
        );
        assert!(service.calls.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn partial_next_frame_survives_completion_of_current_request() {
    let (server, client) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(server);
    let mut client = BufReader::new(client);
    let mut service = Service {
        delayed: true,
        ..Service::default()
    };
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async {
            initialize(&mut client, "2025-11-25").await;
            send(&mut client, request(json!(2), "tools/list", json!({}))).await;
            client
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,")
                .await
                .unwrap();
            assert_eq!(receive(&mut client).await["id"], 2);
            client.write_all(b"\"method\":\"ping\"}\n").await.unwrap();
            assert_eq!(receive(&mut client).await["id"], 3);
            client.shutdown().await.unwrap();
        }
    );
    assert_eq!(outcome, Ok(()));
    assert_eq!(service.calls.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn unsupported_tools_are_not_advertised_or_relayed() {
    let (server, client) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(server);
    let mut client = BufReader::new(client);
    let mut service = Service {
        no_tools: true,
        ..Service::default()
    };
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async {
            assert_eq!(
                initialize(&mut client, "2025-11-25").await["result"]["capabilities"],
                json!({})
            );
            send(&mut client, request(json!(2), "tools/list", json!({}))).await;
            assert_eq!(receive(&mut client).await["error"]["code"], -32601);
            client.shutdown().await.unwrap();
        }
    );
    assert_eq!(outcome, Ok(()));
    assert!(service.calls.is_empty());
}

#[tokio::test(start_paused = true)]
async fn shutdown_drops_inflight_work_without_a_result() {
    let (server, client) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(server);
    let mut client = BufReader::new(client);
    let mut service = Service {
        pending: true,
        ..Service::default()
    };
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            tokio::time::sleep(std::time::Duration::from_secs(2))
        ),
        async {
            initialize(&mut client, "2025-11-25").await;
            send(&mut client, request(json!(2), "tools/list", json!({}))).await;
            let mut remaining = String::new();
            assert_eq!(client.read_line(&mut remaining).await.unwrap(), 0);
        }
    );
    assert_eq!(outcome, Ok(()));
    assert!(service.dropped.get());
}

#[tokio::test(start_paused = true)]
async fn blocked_output_is_bounded_even_when_client_stops_reading() {
    let (server, mut client) = tokio::io::duplex(128);
    let (read, write) = tokio::io::split(server);
    let mut service = Service::default();
    let init = request(
        json!(1),
        "initialize",
        json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}),
    );
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async {
            let bytes = format!("{init}\n");
            client.write_all(bytes.as_bytes()).await.unwrap();
        }
    );
    assert_eq!(outcome, Err(Error::Timeout));
    assert!(service.calls.is_empty());
}
