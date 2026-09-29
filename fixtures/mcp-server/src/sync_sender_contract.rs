//! Run only against the empty, consented synthetic profile supplied by the
//! native fixture. No accepted Platform enrollment or HTTP endpoint is needed.
use mitigate_enrollment::storage::sync::SyncProfile;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{Child, ChildStderr, ChildStdout, Command},
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(30);
struct Sender {
    child: Child,
    stdout: BufReader<ChildStdout>,
    stderr: ChildStderr,
}
fn command(binary: &Path, profile: &Path, action: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .args(["sync", action, "--profile"])
        .arg(profile)
        .arg("--json")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}
impl Sender {
    fn start(binary: &Path, profile: &Path) -> Self {
        let mut child = command(binary, profile, "run").spawn().unwrap();
        Self {
            stdout: BufReader::new(child.stdout.take().unwrap()),
            stderr: child.stderr.take().unwrap(),
            child,
        }
    }
    async fn status(&mut self, status: &str, reason: Option<&str>) {
        let mut line = String::new();
        let size = timeout(DEADLINE, self.stdout.read_line(&mut line))
            .await
            .expect("bounded sender status")
            .unwrap();
        assert!(size > 0 && size < 256);
        let report: Value = serde_json::from_str(&line).unwrap();
        let mut expected = json!({"schema_version":1,"status":status});
        if let Some(reason) = reason {
            expected["reason"] = json!(reason);
        }
        assert_eq!(report, expected, "closed progress contract");
    }
    async fn stopped(mut self, reason: &str) {
        self.status("stopped", Some(reason)).await;
        assert!(
            timeout(DEADLINE, self.child.wait())
                .await
                .expect("bounded sender exit")
                .unwrap()
                .success()
        );
        let mut remaining = Vec::new();
        self.stdout.read_to_end(&mut remaining).await.unwrap();
        self.stderr.read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.is_empty(), "unexpected extra sender output");
    }
    #[cfg(unix)]
    async fn interrupt(&mut self, signal: &str) {
        // This is the PID of our owned child, never a supplied process selector.
        let status = timeout(
            DEADLINE,
            Command::new("kill")
                .arg(signal)
                .arg(self.child.id().unwrap().to_string())
                .status(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(status.success());
        self.status("stopping", None).await;
    }
}

pub(crate) fn verify(binary: &Path, path: &Path) {
    let profile = SyncProfile::open(path).unwrap();
    assert!(!profile.inspect().unwrap().paused);
    assert_eq!(profile.inspect().unwrap().pending, 0);
    let config: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let queue = Path::new(config["outbox_file"].as_str().unwrap());
    let original = fs::read(queue).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // An unusable temp directory makes the real storage privacy probe
            // fail before readiness, native unlock or delivery. It is not a
            // bypass flag or a replacement/mock of the probe.
            let missing = path.parent().unwrap().join("missing-private-canary");
            assert!(!missing.exists());
            let failed = timeout(
                DEADLINE,
                command(binary, path, "run")
                    .env("TMPDIR", &missing)
                    .env("TMP", &missing)
                    .env("TEMP", &missing)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(failed.status.code(), Some(2));
            assert!(failed.stdout.is_empty());
            let error: Value = serde_json::from_slice(&failed.stderr).unwrap();
            assert_eq!(error["error"], "sync_privacy");
            assert!(!String::from_utf8_lossy(&failed.stderr).contains("canary"));
            assert!(!missing.exists());

            let mut first = Sender::start(binary, path);
            first.status("waiting", None).await;
            let mut second = Sender::start(binary, path);
            second.status("waiting", None).await;
            assert!(fs::read(queue).unwrap() == original, "idle rewrote queue");

            #[cfg(unix)]
            {
                first.interrupt("-INT").await;
                first.stopped("sync_interrupted").await;
                assert!(!profile.inspect().unwrap().paused);
                assert!(second.child.try_wait().unwrap().is_none());
                let mut third = Sender::start(binary, path);
                third.status("waiting", None).await;
                third.interrupt("-TERM").await;
                third.stopped("sync_interrupted").await;
                assert!(!profile.inspect().unwrap().paused);
            }

            let paused = timeout(DEADLINE, command(binary, path, "pause").output())
                .await
                .expect("bounded explicit pause")
                .unwrap();
            assert!(paused.status.success() && paused.stderr.is_empty());
            let report: Value = serde_json::from_slice(&paused.stdout).unwrap();
            assert_eq!(report["delivery_drained"], true);
            assert_eq!(report["status"], "paused");
            second.stopped("sync_paused").await;
            #[cfg(not(unix))]
            first.stopped("sync_paused").await;

            Sender::start(binary, path).stopped("sync_paused").await;
            let report = profile.inspect().unwrap();
            assert!(report.paused && report.pending == 0);
        });
}
