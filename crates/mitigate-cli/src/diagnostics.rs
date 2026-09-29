//! Explicit local support collection. Only checked, bounded fields may be exported.
//! No ambient configuration, authority store, log, enrollment or credential reads.
mod privacy;

use crate::output;
use mitigate_config::{CONFIG_SCHEMA_VERSION, RuntimeConfig};
use mitigate_egress::{outbox, self_test};
use serde::Serialize;
use std::{
    fs,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

#[derive(Serialize)]
struct Bundle {
    schema_version: u8,
    kind: &'static str,
    runtime_version: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    configuration_schema: u32,
    configuration: Configuration,
    storage_check: StorageCheck,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Configuration {
    NotRead,
    Valid {
        max_file_bytes: usize,
        max_servers: usize,
    },
    Unavailable {
        error: &'static str,
    },
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum StorageCheck {
    NotRun,
    Complete {
        passed: bool,
        attempted: u32,
        rejected: u32,
        positive_control: bool,
        queue_isolation: bool,
        persisted_canaries_absent: bool,
        network_requests: u32,
    },
    Unavailable {
        error: &'static str,
    },
}

fn collect(config: Option<&Path>, check_storage: bool, work_dir: Option<&Path>) -> Bundle {
    let configuration = match config.map(RuntimeConfig::from_file) {
        None => Configuration::NotRead,
        Some(Ok(config)) => Configuration::Valid {
            max_file_bytes: config.scan.max_file_bytes,
            max_servers: config.scan.max_servers,
        },
        Some(Err(error)) => Configuration::Unavailable {
            error: error.code(),
        },
    };
    let storage_check = if check_storage {
        let temporary = std::env::temp_dir();
        match self_test::run(work_dir.unwrap_or(&temporary)) {
            Ok(report) => StorageCheck::Complete {
                passed: report.passed,
                attempted: report
                    .checks
                    .iter()
                    .fold(0u32, |n, c| n.saturating_add(c.attempted)),
                rejected: report
                    .checks
                    .iter()
                    .fold(0u32, |n, c| n.saturating_add(c.rejected)),
                positive_control: report.positive_control,
                queue_isolation: report.queue_isolation,
                persisted_canaries_absent: report.persisted_canaries_absent,
                network_requests: report.network_requests,
            },
            Err(error) => StorageCheck::Unavailable {
                error: storage_code(error),
            },
        }
    } else {
        StorageCheck::NotRun
    };
    Bundle {
        schema_version: 1,
        kind: "mitigate_diagnostics",
        runtime_version: env!("CARGO_PKG_VERSION"),
        operating_system: match std::env::consts::OS {
            "windows" => "windows",
            "linux" => "linux",
            "macos" => "macos",
            _ => "other",
        },
        architecture: match std::env::consts::ARCH {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            _ => "other",
        },
        configuration_schema: CONFIG_SCHEMA_VERSION,
        configuration,
        storage_check,
    }
}

fn storage_code(error: self_test::Error) -> &'static str {
    match error {
        self_test::Error::Workspace => "workspace",
        self_test::Error::Setup => "setup",
        self_test::Error::Cleanup => "cleanup",
        self_test::Error::Storage(error) => match error {
            outbox::Error::Input => "storage_input",
            outbox::Error::Path => "storage_path",
            outbox::Error::Busy => "storage_busy",
            outbox::Error::Storage => "storage_unavailable",
            outbox::Error::Interrupted => "storage_interrupted",
            outbox::Error::Integrity => "storage_integrity",
            outbox::Error::Partition => "storage_partition",
            outbox::Error::Clock => "storage_clock",
            outbox::Error::StaleLease => "storage_stale_lease",
            outbox::Error::Budget => "storage_budget",
        },
    }
}

fn save_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Refuse alternate streams and portable device-name ambiguities before open.
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(io::ErrorKind::InvalidInput)?;
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if name.contains(':')
        || name.ends_with(['.', ' '])
        || matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

pub(crate) fn run(
    output_path: Option<&Path>,
    config: Option<&Path>,
    check_storage: bool,
    work_dir: Option<&Path>,
    machine: bool,
) -> io::Result<ExitCode> {
    let report = collect(config, check_storage, work_dir);
    let bytes = match serde_json::to_value(&report)
        .ok()
        .and_then(|value| privacy::encode(&value))
    {
        Some(bytes) => bytes,
        None => {
            output::error(
                "diagnostics_privacy_refused",
                "The support report failed its privacy check. Nothing was exported.",
                machine,
            )?;
            return Ok(ExitCode::from(2));
        }
    };
    if let Some(path) = output_path
        && save_new(path, &bytes).is_err()
    {
        output::error(
            "diagnostics_output_unavailable",
            "Cannot save the report. Choose a new file in a writable folder.",
            machine,
        )?;
        return Ok(ExitCode::from(2));
    }
    if machine {
        io::stdout().lock().write_all(&bytes)?;
    } else {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "Mitigate {} · {} {}",
            report.runtime_version, report.operating_system, report.architecture
        )?;
        let configuration = match report.configuration {
            Configuration::NotRead => "not checked",
            Configuration::Valid { .. } => "valid",
            Configuration::Unavailable { error } => error,
        };
        writeln!(out, "Configuration: {configuration}")?;
        let storage = match report.storage_check {
            StorageCheck::NotRun => "not checked",
            StorageCheck::Complete { passed: true, .. } => "passed",
            StorageCheck::Complete { .. } => "failed",
            StorageCheck::Unavailable { error } => error,
        };
        writeln!(out, "Synthetic storage check: {storage}")?;
        if output_path.is_some() {
            writeln!(out, "Support report saved.")?;
        }
    }
    // Report collection succeeded, not a health verdict. Unavailable/failed
    // checks are useful support evidence and remain explicit in the document.
    Ok(ExitCode::SUCCESS)
}
