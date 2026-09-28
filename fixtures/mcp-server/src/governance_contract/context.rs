use super::*;

async fn inspect(
    binary: &Path,
    project: &Project,
    known: bool,
    machine: bool,
) -> std::process::Output {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["mcp", "context", "--allow-exec", "--launch-config"])
        .arg(project.path("launch.json"))
        .arg("--launch-review")
        .arg(project.path("review.json"))
        .arg("--tool-snapshot")
        .arg(project.path("snapshot.json"));
    if known {
        command.arg("--profile").arg(project.path("profile.json"));
    }
    if machine {
        command.arg("--json");
    }
    timeout(
        Duration::from_secs(45),
        command.stdin(Stdio::null()).kill_on_drop(true).output(),
    )
    .await
    .expect("bounded context inspection")
    .unwrap()
}

pub(super) async fn verify(binary: &Path, project: &Project) -> Value {
    let mut known_context = Value::Null;
    for known in [false, true] {
        let output = inspect(binary, project, known, true).await;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("canary"));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report.as_object().unwrap().len(), 7);
        assert_eq!(
            report["attribution"],
            if known { "declared_profile" } else { "unknown" }
        );
        assert_eq!(report["client_ref"].is_null(), !known);
        assert_eq!(report["principal_ref"].is_null(), !known);
        assert!(report["agent_ref"].is_null());
        assert_eq!(report["tools"][0]["name"], "read_status");
        assert_eq!(report["tools"][0].as_object().unwrap().len(), 5);
        assert!(!project.path("call-marker").exists());
        assert!(project.events().is_empty());
        if known {
            known_context = report;
        }
    }
    let human = inspect(binary, project, true, false).await;
    assert!(human.status.success());
    assert!(human.stderr.is_empty());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains(known_context["tools"][0]["tool_ref"].as_str().unwrap()));
    assert!(!text.contains("canary"));
    assert!(text.contains("No grants changed. No tools called."));

    // Use the command's exact references, rather than a wildcard fixture grant,
    // for the first actual governed call. Its audit must agree with this report.
    write(
        &project.path("grants.json"),
        json!({"schema_version":1,"grants":[{
            "grant_ref":"f".repeat(64),"effect":"allow","scope":{
                "client":known_context["client_ref"],"principal":known_context["principal_ref"],
                "agent":null,"server":known_context["server_ref"],"tool":known_context["tools"][0]["tool_ref"],
                "capabilities":known_context["tools"][0]["capability_classes"],"environment":null,
                "not_before_ms":null,"expires_at_ms":null}
        }]}),
    );
    known_context
}

pub(super) async fn stale(binary: &Path, project: &Project) {
    let output = inspect(binary, project, true, true).await;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("canary"));
    assert!(!project.path("call-marker").exists());
}
