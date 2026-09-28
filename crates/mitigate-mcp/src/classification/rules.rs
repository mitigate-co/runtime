//! Rules inspect names and schema keys. Descriptions/defaults/examples never
//! change authority or classification, and matched values never enter reports.

use super::types::{
    CapabilityClass as C, Classification, ClassificationSource, Confidence, RiskFlag, flags,
};
use crate::{Error, Result, Tool};
use serde_json::Value;
use std::collections::BTreeSet;

fn tokens(name: &str) -> BTreeSet<String> {
    let bytes = name.as_bytes();
    let mut words = Vec::new();
    let mut word = String::new();
    for (i, &c) in bytes.iter().enumerate() {
        let boundary = !c.is_ascii_alphanumeric()
            || (c.is_ascii_uppercase()
                && i > 0
                && (bytes[i - 1].is_ascii_lowercase()
                    || (bytes[i - 1].is_ascii_uppercase()
                        && bytes.get(i + 1).is_some_and(u8::is_ascii_lowercase))));
        if boundary && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        if c.is_ascii_alphanumeric() {
            word.push((c as char).to_ascii_lowercase());
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words.into_iter().collect()
}

fn schema_keys(
    schema: &Value,
    depth: usize,
    budget: &mut usize,
    names: &mut BTreeSet<String>,
    opaque: &mut bool,
) -> Result<()> {
    if depth > 32 || *budget == 0 {
        return Err(Error::Classification);
    }
    *budget -= 1;
    let Some(fields) = schema.as_object() else {
        return Ok(());
    };
    if fields.contains_key("$ref") || fields.contains_key("$dynamicRef") {
        *opaque = true;
    }
    if (fields.get("type").and_then(Value::as_str) == Some("object")
        || fields.contains_key("properties"))
        && fields.get("additionalProperties") != Some(&Value::Bool(false))
    {
        *opaque = true;
    }
    if let Some(properties) = fields.get("properties").and_then(Value::as_object) {
        for (key, value) in properties {
            names.extend(tokens(key));
            schema_keys(value, depth + 1, budget, names, opaque)?;
        }
    }
    for key in [
        "items",
        "additionalProperties",
        "not",
        "if",
        "then",
        "else",
        "contains",
        "propertyNames",
    ] {
        if let Some(value) = fields.get(key) {
            schema_keys(value, depth + 1, budget, names, opaque)?;
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(items) = fields.get(key).and_then(Value::as_array) {
            for item in items {
                schema_keys(item, depth + 1, budget, names, opaque)?;
            }
        }
    }
    for key in [
        "$defs",
        "definitions",
        "dependentSchemas",
        "patternProperties",
    ] {
        if let Some(items) = fields.get(key).and_then(Value::as_object) {
            for item in items.values() {
                schema_keys(item, depth + 1, budget, names, opaque)?;
            }
        }
    }
    Ok(())
}

pub(super) fn classify(tool: &Tool) -> Result<Classification> {
    let name = tokens(&tool.name);
    let mut keys = BTreeSet::new();
    let mut opaque = false;
    schema_keys(&tool.input_schema, 0, &mut 32_768, &mut keys, &mut opaque)?;
    let has = |set: &BTreeSet<String>, words: &[&str]| words.iter().any(|w| set.contains(*w));
    let mut classes = BTreeSet::new();
    let mut rules = BTreeSet::new();
    for (words, class, rule) in [
        (
            &[
                "read", "get", "list", "search", "fetch", "query", "lookup", "show", "inspect",
                "find",
            ][..],
            C::ReadData,
            "name.read",
        ),
        (
            &[
                "write", "create", "update", "set", "put", "append", "insert", "save", "edit",
                "patch", "import", "upload",
            ][..],
            C::WriteData,
            "name.write",
        ),
        (
            &[
                "delete", "remove", "drop", "truncate", "destroy", "erase", "wipe", "purge",
            ][..],
            C::DeleteData,
            "name.delete",
        ),
        (
            &[
                "execute",
                "exec",
                "run",
                "shell",
                "bash",
                "powershell",
                "eval",
                "spawn",
            ][..],
            C::ExecuteCode,
            "name.execute",
        ),
        (
            &[
                "credential",
                "credentials",
                "secret",
                "secrets",
                "password",
                "token",
                "apikey",
            ][..],
            C::CredentialAccess,
            "name.credentials",
        ),
        (
            &[
                "send", "email", "mail", "http", "request", "publish", "post", "upload", "webhook",
            ][..],
            C::ExternalCommunication,
            "name.external",
        ),
        (
            &[
                "browser",
                "navigate",
                "click",
                "screenshot",
                "playwright",
                "puppeteer",
            ][..],
            C::BrowserAction,
            "name.browser",
        ),
        (
            &[
                "charge", "refund", "payment", "transfer", "purchase", "invoice",
            ][..],
            C::FinancialAction,
            "name.financial",
        ),
    ] {
        if has(&name, words) {
            classes.insert(class);
            rules.insert(rule);
        }
    }
    let mutating = has(
        &name,
        &[
            "create",
            "update",
            "set",
            "delete",
            "remove",
            "assign",
            "revoke",
            "grant",
            "invite",
            "deploy",
            "provision",
            "destroy",
            "restart",
            "scale",
            "apply",
        ],
    );
    if mutating
        && has(
            &name,
            &[
                "user",
                "users",
                "role",
                "roles",
                "permission",
                "permissions",
                "member",
                "members",
                "group",
                "groups",
                "identity",
            ],
        )
    {
        classes.insert(C::IdentityAdmin);
        rules.insert("name.identity_admin");
    }
    if mutating
        && has(
            &name,
            &[
                "deployment",
                "deploy",
                "infrastructure",
                "terraform",
                "cluster",
                "instance",
                "container",
                "service",
                "pod",
                "network",
                "resource",
            ],
        )
    {
        classes.insert(C::InfrastructureChange);
        rules.insert("name.infrastructure");
    }
    let mut schema_evidence = false;
    for (words, class, rule) in [
        (
            &["command", "script", "code", "sql"][..],
            C::ExecuteCode,
            "schema.executable_input",
        ),
        (
            &[
                "credential",
                "credentials",
                "secret",
                "password",
                "token",
                "apikey",
            ][..],
            C::CredentialAccess,
            "schema.credential_input",
        ),
        (
            &["url", "uri", "webhook", "endpoint", "recipient"][..],
            C::ExternalCommunication,
            "schema.destination_input",
        ),
    ] {
        if has(&keys, words) {
            classes.insert(class);
            rules.insert(rule);
            schema_evidence = true;
        }
    }
    if (name.contains("api") && name.contains("key"))
        || (keys.contains("api") && keys.contains("key"))
    {
        classes.insert(C::CredentialAccess);
        rules.insert("key.api_credential");
    }
    if has(&keys, &["action", "operation", "payload", "query"]) {
        opaque = true;
    }
    if classes.is_empty() {
        classes.insert(C::Unknown);
        rules.insert("unclassified");
    }
    let classes: Vec<_> = classes.into_iter().collect();
    let mut risk_flags = flags(&classes);
    if opaque {
        risk_flags.push(RiskFlag::UnknownHighImpact);
        rules.insert("schema.opaque_operation");
    }
    risk_flags.sort();
    risk_flags.dedup();
    Ok(Classification {
        taxonomy_version: 1,
        inferred_classes: classes.clone(),
        classes,
        confidence: if schema_evidence {
            Confidence::Medium
        } else {
            Confidence::Low
        },
        sources: vec![ClassificationSource::Deterministic],
        flags: risk_flags,
        rules: rules.into_iter().collect(),
        overridden: false,
    })
}
