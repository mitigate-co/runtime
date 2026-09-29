//! Independent export gate. Additions to collection do not silently widen sharing.
use serde_json::Value;

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn choice(value: &Value, allowed: &[&str]) -> bool {
    value.as_str().is_some_and(|text| allowed.contains(&text))
}

fn integer(value: &Value, min: u64, max: u64) -> bool {
    value
        .as_u64()
        .is_some_and(|number| (min..=max).contains(&number))
}

fn configuration(value: &Value) -> bool {
    match value["status"].as_str() {
        Some("not_read") => keys(value, &["status"]),
        Some("valid") => {
            keys(value, &["status", "max_file_bytes", "max_servers"])
                && integer(&value["max_file_bytes"], 1024, 1_048_576)
                && integer(&value["max_servers"], 1, 256)
        }
        Some("unavailable") => {
            keys(value, &["status", "error"])
                && choice(
                    &value["error"],
                    &[
                        "config_unavailable",
                        "config_not_regular_file",
                        "config_too_large",
                        "config_invalid_document",
                        "config_unsupported_version",
                        "config_invalid_limits",
                    ],
                )
        }
        _ => false,
    }
}

fn storage(value: &Value) -> bool {
    match value["status"].as_str() {
        Some("not_run") => keys(value, &["status"]),
        Some("unavailable") => {
            keys(value, &["status", "error"])
                && choice(
                    &value["error"],
                    &[
                        "workspace",
                        "setup",
                        "cleanup",
                        "storage_input",
                        "storage_path",
                        "storage_busy",
                        "storage_unavailable",
                        "storage_interrupted",
                        "storage_integrity",
                        "storage_partition",
                        "storage_clock",
                        "storage_stale_lease",
                        "storage_budget",
                    ],
                )
        }
        Some("complete") => {
            if !keys(
                value,
                &[
                    "status",
                    "passed",
                    "attempted",
                    "rejected",
                    "positive_control",
                    "queue_isolation",
                    "persisted_canaries_absent",
                    "network_requests",
                ],
            ) || ![
                "passed",
                "positive_control",
                "queue_isolation",
                "persisted_canaries_absent",
            ]
            .iter()
            .all(|key| value[*key].is_boolean())
                || !integer(&value["attempted"], 1, 4096)
                || !integer(
                    &value["rejected"],
                    0,
                    value["attempted"].as_u64().unwrap_or(0),
                )
                || !integer(&value["network_requests"], 0, 0)
            {
                return false;
            }
            value["passed"].as_bool()
                == Some(
                    value["positive_control"] == true
                        && value["queue_isolation"] == true
                        && value["persisted_canaries_absent"] == true
                        && value["attempted"] == value["rejected"],
                )
        }
        _ => false,
    }
}

/// Refuse unreviewed fields and values before producing either stdout or a file.
/// No user text, paths, identifiers, credentials or arbitrary error messages fit.
pub(super) fn encode(value: &Value) -> Option<Vec<u8>> {
    if !keys(
        value,
        &[
            "schema_version",
            "kind",
            "runtime_version",
            "operating_system",
            "architecture",
            "configuration_schema",
            "configuration",
            "storage_check",
        ],
    ) || !integer(&value["schema_version"], 1, 1)
        || value["kind"] != "mitigate_diagnostics"
        || value["runtime_version"] != env!("CARGO_PKG_VERSION")
        || !choice(
            &value["operating_system"],
            &["windows", "macos", "linux", "other"],
        )
        || !choice(&value["architecture"], &["x86_64", "aarch64", "other"])
        || !integer(&value["configuration_schema"], 1, 1)
        || !configuration(&value["configuration"])
        || !storage(&value["storage_check"])
    {
        return None;
    }
    let mut bytes = serde_json::to_vec(value).ok()?;
    bytes.push(b'\n');
    (bytes.len() <= 4096).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> Value {
        serde_json::to_value(super::super::collect(None, false, None)).unwrap()
    }

    fn complete() -> Value {
        json!({"status":"complete", "passed":true, "attempted":260, "rejected":260,
            "positive_control":true, "queue_isolation":true,
            "persisted_canaries_absent":true, "network_requests":0})
    }

    #[test]
    fn closed_success_and_failure_variants_remain_exportable() {
        let mut value = base();
        assert!(encode(&value).is_some());
        for configuration in [
            json!({"status":"valid","max_file_bytes":1024,"max_servers":1}),
            json!({"status":"valid","max_file_bytes":1048576,"max_servers":256}),
            json!({"status":"unavailable","error":"config_invalid_document"}),
        ] {
            value["configuration"] = configuration;
            assert!(encode(&value).is_some());
        }
        value["storage_check"] = complete();
        assert!(encode(&value).is_some());
        for control in [
            "positive_control",
            "queue_isolation",
            "persisted_canaries_absent",
        ] {
            value["storage_check"] = complete();
            value["storage_check"][control] = json!(false);
            value["storage_check"]["passed"] = json!(false);
            assert!(encode(&value).is_some());
        }
        value["storage_check"] = complete();
        value["storage_check"]["rejected"] = json!(259);
        value["storage_check"]["passed"] = json!(false);
        assert!(encode(&value).is_some());
        value["storage_check"] = json!({"status":"unavailable","error":"storage_clock"});
        assert!(encode(&value).is_some());
    }

    #[test]
    fn field_expansion_content_injection_and_type_confusion_fail_closed() {
        let mut original = base();
        original["configuration"] = json!({"status":"valid","max_file_bytes":1024,"max_servers":1});
        original["storage_check"] = complete();
        for pointer in ["", "/configuration", "/storage_check"] {
            let mut value = original.clone();
            value.pointer_mut(pointer).unwrap()["future"] = json!({"token":"private-canary"});
            assert!(encode(&value).is_none());
            let object = original.pointer(pointer).unwrap().as_object().unwrap();
            for key in object.keys() {
                for hostile in [
                    Value::Null,
                    json!(["private-canary"]),
                    json!({"content":"private-canary"}),
                    json!("private-canary".repeat(1024)),
                ] {
                    let mut value = original.clone();
                    value.pointer_mut(pointer).unwrap()[key] = hostile;
                    assert!(encode(&value).is_none(), "accepted {pointer}/{key}");
                }
                let mut value = original.clone();
                value
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
                assert!(encode(&value).is_none());
            }
        }
        for (pointer, hostile) in [
            ("/schema_version", json!(1.0)),
            ("/configuration_schema", json!(2)),
            ("/configuration/max_file_bytes", json!(1023)),
            ("/configuration/max_file_bytes", json!(1048577)),
            ("/configuration/max_servers", json!(257)),
            ("/configuration/max_servers", json!(-1)),
            ("/storage_check/attempted", json!(0)),
            ("/storage_check/attempted", json!(4097)),
            ("/storage_check/rejected", json!(261)),
            ("/storage_check/rejected", json!(260.0)),
            ("/storage_check/network_requests", json!(1)),
            ("/storage_check/positive_control", json!(false)),
            ("/storage_check/passed", json!(false)),
            ("/runtime_version", json!("0.1.0+private-canary")),
            ("/operating_system", json!("private-hostname")),
        ] {
            let mut value = original.clone();
            *value.pointer_mut(pointer).unwrap() = hostile;
            assert!(encode(&value).is_none(), "accepted {pointer}");
        }
        for key in ["configuration", "storage_check"] {
            let mut value = original.clone();
            value[key] = json!({"status":"unavailable","error":"private-path-canary"});
            assert!(encode(&value).is_none());
        }
    }
}
