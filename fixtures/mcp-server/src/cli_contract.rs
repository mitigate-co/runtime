//! End-to-end contract check against the actual CLI binary, invoked by CI after
//! building both programs. Uses this synthetic server, temporary files and no
//! customer config/account. Panics report expectations, never subprocess content.
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Project(PathBuf);
impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(binary: &Path, args: &[&str], expected: i32) -> Output {
    let output = Command::new(binary)
        .args(args)
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .env_remove("MITIGATE_TOKEN")
        .output()
        .expect("CLI must run");
    assert_eq!(output.status.code(), Some(expected), "CLI exit contract");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("canary"),
        "stdout must exclude fixture content"
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("canary"),
        "stderr must exclude fixture content"
    );
    output
}

pub(super) fn verify(binary: &Path) {
    let directory =
        std::env::temp_dir().join(format!("mitigate-cli-contract-{}", std::process::id()));
    fs::create_dir(&directory).expect("exclusive synthetic test directory");
    let project = Project(directory);
    let launch = project.0.join("launch.json");
    let snapshot = project.0.join("snapshot.json");
    let overrides = project.0.join("overrides.json");
    let launch_text = launch.to_str().unwrap();
    for (mode, exit, count) in [("ok", 3, 1), ("empty", 0, 0), ("no-tools", 0, 0)] {
        fs::write(&launch,serde_json::to_vec(&json!({"schema_version":1,"executable_path":std::env::current_exe().unwrap(),"working_directory":project.0,"argv":[mode],"timeout_ms":5000})).unwrap()).unwrap();
        let output = run(
            binary,
            &[
                "mcp",
                "inspect",
                "--launch-config",
                launch_text,
                "--allow-exec",
                "--json",
                "--fail-on-risk",
            ],
            exit,
        );
        assert!(output.stderr.is_empty());
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("single JSON success document");
        assert_eq!(report["schema_version"], 2);
        assert_eq!(report["tools_supported"], mode != "no-tools");
        assert_eq!(report["tools"].as_array().unwrap().len(), count);
        if count == 1 {
            let classification = &report["tools"][0]["classification"];
            assert_eq!(classification["classes"], json!(["read_data"]));
            assert_eq!(classification["sources"], json!(["deterministic"]));
            assert_eq!(classification["flags"], json!(["unknown_high_impact"]));
            for details in [false, true] {
                let mut args = vec![
                    "mcp",
                    "inspect",
                    "--launch-config",
                    launch_text,
                    "--allow-exec",
                ];
                if details {
                    args.push("--details");
                }
                let output = run(binary, &args, 0);
                let text = String::from_utf8(output.stdout).unwrap();
                assert!(text.contains("Read data"));
                assert!(text.contains("Unknown impact"));
            }
            run(
                binary,
                &[
                    "mcp",
                    "inspect",
                    "--launch-config",
                    launch_text,
                    "--allow-exec",
                    "--snapshot",
                    snapshot.to_str().unwrap(),
                    "--json",
                ],
                0,
            );
            let saved: Value = serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
            let mut tool = saved["tools"][0].clone();
            tool.as_object_mut().unwrap().remove("name");
            tool["classes"] = json!(["read_data"]);
            fs::write(&overrides,serde_json::to_vec(&json!({"schema_version":1,"fingerprint_profile":saved["fingerprint_profile"],"server_facts":saved["server_facts"],"tools":[tool]})).unwrap()).unwrap();
            let output = run(
                binary,
                &[
                    "mcp",
                    "inspect",
                    "--launch-config",
                    launch_text,
                    "--allow-exec",
                    "--classification-overrides",
                    overrides.to_str().unwrap(),
                    "--json",
                ],
                0,
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["tools"][0]["classification"]["overridden"], true);
            assert_eq!(
                report["tools"][0]["classification"]["flags"],
                json!(["unknown_high_impact"])
            );
            let output = run(
                binary,
                &[
                    "mcp",
                    "inspect",
                    "--launch-config",
                    launch_text,
                    "--allow-exec",
                    "--snapshot",
                    snapshot.to_str().unwrap(),
                    "--json",
                ],
                2,
            );
            assert!(output.stdout.is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"],
                "mcp_snapshot_invalid"
            );
        } else {
            let refused_snapshot = project.0.join("must-not-exist.json");
            let output = run(
                binary,
                &[
                    "mcp",
                    "inspect",
                    "--launch-config",
                    launch_text,
                    "--allow-exec",
                    "--classification-overrides",
                    overrides.to_str().unwrap(),
                    "--snapshot",
                    refused_snapshot.to_str().unwrap(),
                    "--json",
                ],
                2,
            );
            assert!(output.stdout.is_empty());
            assert!(!refused_snapshot.exists());
            assert_eq!(
                serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"],
                "mcp_classification_invalid"
            );
        }
    }
    println!(
        "CLI contract verified: reports, findings exits, empty/unsupported states, bound overrides and non-overwriting snapshots."
    );
}
