//! Closed synthetic-child failure projection. Never forward raw stderr or paths.

pub(crate) fn messages(stderr: &[u8]) -> Vec<String> {
    let bounded = String::from_utf8_lossy(&stderr[..stderr.len().min(8192)]);
    let mut result = Vec::new();
    for line in bounded.lines().take(64) {
        for category in [
            "assertion",
            "workspace",
            "setup",
            "cleanup",
            "storage_clock",
            "storage_budget",
            "storage",
        ] {
            let allowed = format!("Synthetic capture privacy category: {category}.");
            if line == allowed {
                result.push(allowed);
            }
        }
        for (label, states) in [
            ("pending", &["unobserved", "empty", "partial", "busy"][..]),
            ("worker", &["ready", "paused", "unavailable", "dropped"][..]),
        ] {
            for state in states {
                let allowed = format!("Synthetic capture {label} state: {state}.");
                if line == allowed {
                    result.push(allowed);
                }
            }
        }
        for stage in [
            "prepare",
            "first_start",
            "first_ready",
            "first_call",
            "first_commit",
            "restart",
            "second_ready",
            "second_call",
            "policy_denial",
            "inventory",
            "pause",
            "purge",
            "unavailable_profile",
            "complete",
        ] {
            let allowed = format!("Synthetic capture stage: {stage}.");
            if line == allowed {
                result.push(allowed);
            }
        }
        for category in [
            "outbox_input",
            "outbox_path",
            "outbox_busy",
            "outbox_storage",
            "outbox_interrupted",
            "outbox_integrity",
            "outbox_partition",
            "outbox_clock",
            "outbox_stale_lease",
            "outbox_budget",
            "unexpected_control",
        ] {
            let allowed = format!("Synthetic capture inspection category: {category}.");
            if line == allowed {
                result.push(allowed);
            }
        }
        let Some((_, location)) = line.split_once("panicked at ") else {
            continue;
        };
        let location = location.replace('\\', "/");
        for file in ["sync.rs", "mod.rs"] {
            let prefix = format!("fixtures/mcp-server/src/governance_contract/{file}:");
            let Some(position) = location
                .strip_prefix(&prefix)
                .and_then(|s| s.strip_suffix(':'))
            else {
                continue;
            };
            let Some((line, column)) = position.split_once(':') else {
                continue;
            };
            if line.is_empty()
                || column.is_empty()
                || !line
                    .bytes()
                    .chain(column.bytes())
                    .all(|b| b.is_ascii_digit())
            {
                continue;
            }
            if let (Ok(line), Ok(column)) = (line.parse::<u32>(), column.parse::<u32>())
                && line > 0
                && column > 0
            {
                result.push(format!(
                    "Synthetic capture assertion: {file}:{line}:{column}."
                ));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_and_posix_assertions_project_the_same_public_location() {
        for path in [
            "fixtures/mcp-server/src/governance_contract/sync.rs",
            "fixtures\\mcp-server\\src\\governance_contract\\sync.rs",
        ] {
            let input = format!(
                "Synthetic capture stage: first_ready.\nthread 'private-name-canary' (42) panicked at {path}:102:5:\nprivate-payload-canary\n"
            );
            assert_eq!(
                messages(input.as_bytes()),
                [
                    "Synthetic capture stage: first_ready.",
                    "Synthetic capture assertion: sync.rs:102:5.",
                ]
            );
        }
    }

    #[test]
    fn only_bounded_fixed_stages_categories_and_numeric_positions_escape() {
        assert_eq!(messages(b"Synthetic capture privacy category: storage_clock.\nSynthetic capture stage: inventory.\n"), [
            "Synthetic capture privacy category: storage_clock.", "Synthetic capture stage: inventory.",
        ]);
        for input in [
            "Synthetic capture pending state: private-canary.",
            "Synthetic capture worker state: dropped. private-canary",
            "Synthetic capture inspection category: private-canary.",
            "Synthetic capture inspection category: outbox_busy. private-canary",
            "Synthetic capture privacy category: private-canary.",
            "Synthetic capture stage: private-canary.",
            "Synthetic capture stage: inventory. private-canary",
            "thread 'x' panicked at C:/private/fixtures/mcp-server/src/governance_contract/sync.rs:2:3:",
            "thread 'x' panicked at fixtures/mcp-server/src/governance_contract/sync.rs:0:3:",
            "thread 'x' panicked at fixtures/mcp-server/src/governance_contract/sync.rs:+1:3:",
            "thread 'x' panicked at fixtures/mcp-server/src/governance_contract/sync.rs:1:3:private-canary",
            "thread 'x' panicked at fixtures/mcp-server/src/governance_contract/sync.rs:99999999999:3:",
        ] {
            assert!(messages(input.as_bytes()).is_empty());
        }
        let after_lines = "ignored\n".repeat(64) + "Synthetic capture stage: complete.";
        assert!(messages(after_lines.as_bytes()).is_empty());
        let after_bytes = "x".repeat(8192) + "\nSynthetic capture stage: complete.";
        assert!(messages(after_bytes.as_bytes()).is_empty());
        assert!(messages(&[0xff, 0xfe, 0]).is_empty());
    }

    #[test]
    fn closed_inspection_categories_survive_without_error_payloads() {
        for category in [
            "outbox_input",
            "outbox_path",
            "outbox_busy",
            "outbox_storage",
            "outbox_interrupted",
            "outbox_integrity",
            "outbox_partition",
            "outbox_clock",
            "outbox_stale_lease",
            "outbox_budget",
            "unexpected_control",
        ] {
            let allowed = format!("Synthetic capture inspection category: {category}.");
            let input = format!("private-path-canary\n{allowed}\nprivate-payload-canary\n");
            assert_eq!(messages(input.as_bytes()), [allowed]);
        }
    }

    #[test]
    fn timeout_state_projection_excludes_neighboring_private_payloads() {
        let input = b"private-path-canary\nSynthetic capture pending state: partial.\nSynthetic capture worker state: dropped.\nprivate-payload-canary\n";
        assert_eq!(
            messages(input),
            [
                "Synthetic capture pending state: partial.",
                "Synthetic capture worker state: dropped."
            ]
        );
    }
}
