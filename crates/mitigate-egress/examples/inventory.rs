//! Bounded candidate-protocol demonstration. Never admits or transmits a part.
use mitigate_egress::{MAX_EVENT_BYTES, inventory::CheckedPart};
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
        eprintln!("inventory candidate input could not be read");
        return ExitCode::from(2);
    }
    match CheckedPart::from_bytes(&bytes) {
        Ok(part) => {
            println!(
                "{}",
                serde_json::json!({
                    "schema_version": 2,
                    "event_type": "mcp_inventory_snapshot",
                    "canonical_bytes": part.as_bytes().len(),
                    "part_index": part.facts().part_index,
                    "required_parts": part.facts().part_count(),
                    "tool_count": part.facts().tool_count,
                    "outbox_admitted": false,
                    "network_requests": 0
                })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
