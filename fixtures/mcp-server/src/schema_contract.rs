//! Executable demonstration: all calls target this synthetic binary only.
use mitigate_mcp::{Error, LaunchConfig, StdioServer};
use serde_json::json;

pub(super) fn verify() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for (mode, expected) in [
            ("relay-schema", None),
            ("relay-schema-wrong", Some(Error::SchemaMismatch)),
            ("relay-schema-unsupported", Some(Error::Schema)),
        ] {
            let config = LaunchConfig::from_bytes(&serde_json::to_vec(&json!({
                "schema_version":1,"executable_path":std::env::current_exe().unwrap(),
                "working_directory":std::env::current_dir().unwrap(),"argv":[mode],"timeout_ms":5000
            })).unwrap()).unwrap();
            let mut server = StdioServer::connect(&config).await.unwrap();
            if mode == "relay-schema" {
                assert_eq!(
                    server
                        .call("read_status", json!({"value":"not-a-number"}), None)
                        .await
                        .err(),
                    Some(Error::SchemaMismatch)
                );
            }
            assert_eq!(
                server
                    .call("read_status", json!({"value":1}), None)
                    .await
                    .err(),
                expected
            );
            server.close().await.unwrap();
        }
    });
    println!(
        "Schema contract verified: invalid arguments blocked, valid call relayed, unsupported schemas refused and invalid results withheld."
    );
}
