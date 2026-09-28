//! Explicit process lifecycle: bounded pipes, whole-session deadline, group cleanup.

use crate::{
    Error, Inventory, LaunchConfig, Result,
    protocol::{self, Transport},
};
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use serde_json::Value;
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{ChildStdin, ChildStdout},
};

pub(crate) struct Session {
    child: Box<dyn ChildWrapper>,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    received: usize,
    cleaned: bool,
}
impl Drop for Session {
    fn drop(&mut self) {
        // Covers cancellation/unwind. Always kill via the group/job wrapper.
        if !self.cleaned {
            let _ = self.child.start_kill();
        }
    }
}

impl Session {
    pub fn start(config: &LaunchConfig) -> Result<Self> {
        config.validate()?;
        let (executable, cwd) = config.paths()?;
        let environment = config.environment()?;
        let mut command = CommandWrap::with_new(executable, |command| {
            command
                .args(&config.argv)
                .current_dir(cwd)
                .env_clear()
                .envs(environment)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
        });
        command.wrap(KillOnDrop);
        #[cfg(windows)]
        {
            use process_wrap::tokio::{CreationFlags, JobObject};
            let mut flags = CreationFlags(Default::default());
            flags.0.0 = 0x08000000; // CREATE_NO_WINDOW; job assignment suspends/resumes safely.
            command.wrap(flags).wrap(JobObject);
        }
        #[cfg(unix)]
        command.wrap(process_wrap::tokio::ProcessGroup::leader());
        let mut child = command.spawn().map_err(|_| Error::Launch)?;
        let input = child.stdin().take();
        let output = child.stdout().take().ok_or(Error::Launch)?;
        Ok(Self {
            child,
            input,
            output: BufReader::new(output),
            received: 0,
            cleaned: false,
        })
    }
    pub fn interrupt(&mut self) {
        self.input.take();
        let _ = self.child.start_kill();
    }
    pub async fn close(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.interrupt();
        match tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await {
            Ok(Ok(_)) => {
                self.cleaned = true;
                Ok(())
            }
            _ => Err(Error::Cleanup),
        }
    }
    // Enumeration budgets apply per complete transaction, not per frame/page.
    pub fn begin_transaction(&mut self) {
        self.received = 0;
    }
}

/// Launch a caller-reviewed local server and enumerate its tools, without calls.
///
/// This is execution, not discovery: the server has the caller's OS privileges.
/// The caller must explicitly authorize its executable, argv, cwd and environment.
/// No shell interpolation, inherited credentials, stderr capture or Platform call.
pub async fn enumerate(config: &LaunchConfig) -> Result<Inventory> {
    enumerate_with_shutdown(config, std::future::pending()).await
}

/// Enumerate with caller-provided shutdown (for example Ctrl+C), then confirm
/// process cleanup before returning `Cancelled`. Dropping this future also kills
/// the job/group, but cannot await reaping; prefer this explicit shutdown path.
pub async fn enumerate_with_shutdown(
    config: &LaunchConfig,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<Inventory> {
    let mut session = Session::start(config)?;
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_millis(config.timeout_ms), protocol::inventory(&mut session)) => result.map_err(|_| Error::Timeout).and_then(|r|r),
        _ = shutdown => Err(Error::Cancelled),
    };
    // End the entire group before reaping its leader, including descendants that
    // retain pipes. Hard termination bounds cleanup of an uncooperative server.
    session.close().await?;
    result
}

impl Transport for Session {
    async fn send(&mut self, message: Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(&message).map_err(|_| Error::Protocol)?;
        if bytes.len() > 65_536 {
            return Err(Error::Limit);
        }
        bytes.push(b'\n');
        self.input
            .as_mut()
            .ok_or(Error::Disconnected)?
            .write_all(&bytes)
            .await
            .map_err(|_| Error::Disconnected)
    }
    async fn receive(&mut self) -> Result<Value> {
        let mut line = Vec::new();
        loop {
            let buffer = self
                .output
                .fill_buf()
                .await
                .map_err(|_| Error::Disconnected)?;
            if buffer.is_empty() {
                return Err(Error::Disconnected);
            }
            let end = buffer.iter().position(|b| *b == b'\n');
            let count = end.map_or(buffer.len(), |i| i + 1);
            self.received += count;
            if line.len() + count > 1_048_576 || self.received > 8_388_608 {
                return Err(Error::Limit);
            }
            line.extend_from_slice(&buffer[..count]);
            self.output.consume(count);
            if end.is_some() {
                return mitigate_json::parse(&line).map_err(|_| Error::Protocol);
            }
        }
    }
}
