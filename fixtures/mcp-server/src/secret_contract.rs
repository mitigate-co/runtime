//! Real native store + real CLI + real child, using only temporary synthetic data.
use mitigate_secrets::{NativeStore, SecretRef, SecretStore};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Output, Stdio},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, process::Command};

async fn cli(path: &Path, args: &[&str], input: Option<&[u8]>) -> Output {
    let mut command = Command::new(path);
    command
        .args(args)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.env("UNRELATED_CREDENTIAL_CANARY", "unrelated-credential-canary");
    // Must never be used when a native reference fails.
    command.env("BROKER_TOKEN", "ambient-fallback-canary");
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command.spawn().unwrap();
    let mut pipe = child.stdin.take().unwrap();
    if let Some(bytes) = input {
        pipe.write_all(bytes).await.unwrap();
    }
    drop(pipe);
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("CLI deadline")
        .unwrap();
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("broker-secret-canary"));
        assert!(!text.contains("ambient-fallback-canary"));
        assert!(!text.contains("unrelated-credential-canary"));
    }
    output
}

pub fn verify(path: &Path) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let reference = runtime.block_on(async {
        let imported = cli(
            path,
            &["secrets", "import", "--stdin"],
            Some(b"broker-secret-canary-v1\r\n"),
        )
        .await;
        assert!(
            imported.status.success(),
            "native store import failed (unlock the OS store)"
        );
        let report: Value = serde_json::from_slice(&imported.stdout).unwrap();
        SecretRef::parse(report["secret_ref"].as_str().unwrap()).unwrap()
    });
    // Clean up this exact fixture credential even if an assertion fails. Never
    // enumerate, bulk delete, or touch any pre-existing user's credentials.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            let value = NativeStore.read(&reference).await.unwrap();
            assert!(value.expose(|v| v == "broker-secret-canary-v1"));
            drop(value);
            assert!(cli(path,&["secrets","check","--reference",reference.as_str()],None).await.status.success());
            assert!(cli(path,&["secrets","replace","--reference",reference.as_str(),"--stdin"],Some(b"broker-secret-canary-v2")).await.status.success());
            let value = NativeStore.read(&reference).await.unwrap();
            assert!(value.expose(|v| v == "broker-secret-canary-v2"));
            drop(value);
            let root = std::env::temp_dir().join(format!("mitigate-secret-contract-{}", reference.as_str()));
            std::fs::create_dir(&root).unwrap();
            let marker = root.join("started");
            let launch = root.join("launch.json");
            let config = json!({"schema_version":1,"executable_path":std::env::current_exe().unwrap(),"working_directory":root,"argv":["credential",marker],"secret_references":[{"environment_key":"BROKER_TOKEN","secret_ref":reference.as_str()}],"timeout_ms":5000});
            std::fs::write(&launch,serde_json::to_vec(&config).unwrap()).unwrap();
            let inspected = cli(path,&["mcp","inspect","--launch-config",launch.to_str().unwrap(),"--allow-exec"],None).await;
            assert!(inspected.status.success(),"native credential injection failed");
            assert!(marker.is_file());
            std::fs::remove_file(&marker).unwrap();
            assert!(cli(path,&["secrets","delete","--reference",reference.as_str(),"--confirm"],None).await.status.success());
            assert_eq!(cli(path,&["secrets","check","--reference",reference.as_str()],None).await.status.code(),Some(2));
            let missing = cli(path,&["mcp","inspect","--launch-config",launch.to_str().unwrap(),"--allow-exec"],None).await;
            assert_eq!(missing.status.code(),Some(2));
            assert!(!marker.exists(),"missing credential launched a child");
            assert_eq!(cli(path,&["secrets","replace","--reference",reference.as_str(),"--stdin"],Some(b"broker-secret-canary-v2")).await.status.code(),Some(2));
            assert_eq!(cli(path,&["secrets","import","--stdin"],Some(&vec![b'x';2561])).await.status.code(),Some(2));
            std::fs::remove_file(launch).unwrap();
            std::fs::remove_dir(root).unwrap();
        });
    }));
    runtime.block_on(async {
        match NativeStore.delete(&reference).await {
            Ok(()) | Err(mitigate_secrets::Error::Missing) => (),
            Err(_) => panic!("fixture credential cleanup failed"),
        }
        assert_eq!(
            NativeStore.read(&reference).await.err(),
            Some(mitigate_secrets::Error::Missing)
        );
    });
    runtime.shutdown_timeout(Duration::from_millis(50));
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    println!(
        "Native credential contract passed: import, replace, injection, delete, no fallback or output leaks."
    );
}
