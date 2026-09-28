//! Developer-only contract demonstration: bounded stdin, safe summary, no delivery.
use mitigate_egress::{CheckedEvent, EVENT_FIELDS, MAX_EVENT_BYTES};
use std::{
    io::{self, Read},
    process::ExitCode,
};

fn main() -> ExitCode {
    let mut bytes = Vec::new();
    if io::stdin()
        .take(MAX_EVENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        eprintln!("event input could not be read");
        return ExitCode::from(2);
    }
    match CheckedEvent::from_bytes(&bytes) {
        Ok(event) => {
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"event_type":"mcp_tool_decision",
                "bytes":event.as_bytes().len(),"fields":EVENT_FIELDS})
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
