//! Real-process relay demonstration, restricted to this synthetic executable.
use mitigate_mcp::{LaunchConfig, StdioServer};
use serde_json::json;

pub(super) fn verify() {
    let config = LaunchConfig::from_bytes(&serde_json::to_vec(&json!({
        "schema_version":1,"executable_path":std::env::current_exe().unwrap(),
        "working_directory":std::env::current_dir().unwrap(),"argv":["relay-progress"],"timeout_ms":5000
    })).unwrap()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut server = StdioServer::connect(&config).await.unwrap();
        let mut events = Vec::new();
        let result = server
            .call(
                "read_status",
                json!({"value":"synthetic-input"}),
                Some(&mut |p| events.push(p)),
            )
            .await
            .unwrap();
        assert_eq!(result["structuredContent"]["ok"], true);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].completed, 2.0);
        server.close().await.unwrap();
    });
    println!(
        "Upstream contract verified: real subprocess, fresh inventory, synthetic call, progress counters and confirmed cleanup."
    );
}
