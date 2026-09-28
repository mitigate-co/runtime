//! Review selected code/launch metadata locally; never start a process here.
use crate::{args::LaunchCommand, output};
use mitigate_mcp::{Error, LaunchConfig, LaunchReceipt, LaunchReview};
use std::{
    io::{self, Write},
    process::ExitCode,
    time::Duration,
};

async fn execute(command: LaunchCommand) -> Result<LaunchReceipt, Error> {
    match command {
        LaunchCommand::Review { launch_config, out } => {
            let config = LaunchConfig::from_file(&launch_config)?;
            let review = LaunchReview::create(&config).await?;
            review.write_new(&out)?;
            Ok(review.receipt())
        }
        LaunchCommand::Check {
            launch_config,
            review,
        } => {
            let config = LaunchConfig::from_file(&launch_config)?;
            LaunchReview::from_file(&review)?.check(&config).await
        }
    }
}
pub(crate) fn run(command: LaunchCommand, machine: bool) -> io::Result<ExitCode> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return super::mcp_error(Error::LaunchReview, machine),
    };
    let result = runtime.block_on(async {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => Err(Error::Cancelled),
            result = execute(command) => result,
        }
    });
    runtime.shutdown_timeout(Duration::from_millis(50));
    match result {
        Ok(receipt) => {
            if machine {
                output::json(&receipt, io::stdout().lock())?;
            } else {
                let mut out = io::stdout().lock();
                writeln!(out, "Launch reference: {}", receipt.launch_ref.as_str())?;
                writeln!(
                    out,
                    "Executable SHA-256: {}",
                    receipt.executable_sha256.as_str()
                )?;
                writeln!(
                    out,
                    "{} additional code artifacts. No server started.",
                    receipt.artifact_count
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => super::mcp_error(error, machine),
    }
}
