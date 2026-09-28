//! Adapter narrowing. Sensitive values are inspected only for configuration shape
//! and then discarded; output has no field for environment/header/argument values.

use crate::{
    ConfigRisk as Risk, CredentialReferenceType as Credential, DiscoveredServer, SourceKind,
    TransportKind,
};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

type Result<T> = std::result::Result<T, ()>;

fn unsafe_display(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn string<'a>(fields: &'a Map<String, Value>, name: &str, limit: usize) -> Result<Option<&'a str>> {
    fields
        .get(name)
        .map(|value| {
            value
                .as_str()
                .filter(|v| !v.is_empty() && v.len() <= limit && !v.chars().any(unsafe_display))
                .ok_or(())
        })
        .transpose()
}

fn reference(value: &str) -> bool {
    value.starts_with("${") && value.ends_with('}') && value.matches("${").count() == 1
}

fn credentials(
    fields: &Map<String, Value>,
    name: &str,
    inline: Credential,
    referenced: Credential,
    types: &mut BTreeSet<Credential>,
    risks: &mut BTreeSet<Risk>,
) -> Result<()> {
    let Some(value) = fields.get(name) else {
        return Ok(());
    };
    let entries = value.as_object().filter(|v| v.len() <= 64).ok_or(())?;
    for (key, value) in entries {
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(());
        }
        let value = value.as_str().filter(|v| v.len() <= 8192).ok_or(())?;
        if value.contains("${") {
            types.insert(referenced);
        }
        if !value.is_empty() && !reference(value) {
            types.insert(inline);
            risks.insert(Risk::InlineValues);
        }
    }
    Ok(())
}

fn package(program: &str, args: &[&str]) -> (Option<String>, Option<String>) {
    if !matches!(program.to_ascii_lowercase().as_str(), "npx" | "npx.cmd") {
        return (None, None);
    }
    let Some(package) = args
        .iter()
        .copied()
        .find(|arg| !matches!(*arg, "-y" | "--yes"))
    else {
        return (None, None);
    };
    if package.is_empty()
        || package.len() > 214
        || package.starts_with(['-', '.'])
        || !package
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"@/._-+".contains(&c))
    {
        return (None, None);
    }
    let (name, version) = match package.rsplit_once('@') {
        Some((name, version)) if !name.is_empty() => (name, Some(version)),
        _ => (package, None),
    };
    let parts: Vec<_> = name.split('/').collect();
    let valid = match parts.as_slice() {
        [plain] => !plain.contains('@') && !plain.is_empty(),
        [scope, plain] => {
            scope.starts_with('@')
                && scope.len() > 1
                && !scope[1..].contains('@')
                && !plain.is_empty()
                && !plain.contains('@')
        }
        _ => false,
    };
    if !valid {
        return (None, None);
    }
    let version = version
        .filter(|v| {
            // Conservatively recognize numeric release versions only. Tags,
            // ranges and prereleases stay unknown until a version-aware source
            // resolves them; a malformed declaration must not imply provenance.
            let parts: Vec<_> = v.split('.').collect();
            parts.len() == 3
                && parts.iter().all(|p| {
                    !p.is_empty()
                        && (p.len() == 1 || !p.starts_with('0'))
                        && p.bytes().all(|c| c.is_ascii_digit())
                })
        })
        .map(str::to_owned);
    (Some(name.to_owned()), version)
}

pub(super) fn server(
    source: SourceKind,
    name: &str,
    value: &Value,
    top_unknown: bool,
) -> Result<DiscoveredServer> {
    if name.is_empty() || name.len() > 128 || name.chars().any(unsafe_display) {
        return Err(());
    }
    let fields = value.as_object().ok_or(())?;
    let command = string(fields, "command", 4096)?;
    let url = string(fields, "url", 4096)?;
    if command.is_some() == url.is_some() {
        return Err(());
    }
    let declared_type = string(fields, "type", 64)?;
    let cwd = string(fields, "cwd", 4096)?;
    let env_file = string(fields, "envFile", 4096)?;
    let header_helper = string(fields, "headersHelper", 4096)?;
    let args: Vec<&str> = match fields.get("args") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .filter(|v| v.len() <= 64)
            .ok_or(())?
            .iter()
            .map(|v| {
                v.as_str()
                    .filter(|v| v.len() <= 4096 && !v.contains('\0'))
                    .ok_or(())
            })
            .collect::<Result<_>>()?,
    };
    if url.is_some()
        && (!args.is_empty() || cwd.is_some() || env_file.is_some() || fields.contains_key("env"))
    {
        return Err(());
    }
    if command.is_some()
        && (fields.contains_key("headers")
            || fields.contains_key("auth")
            || header_helper.is_some())
    {
        return Err(());
    }
    let mut risks = BTreeSet::new();
    let mut types = BTreeSet::new();
    if top_unknown
        || fields.keys().any(|key| {
            ![
                "type",
                "command",
                "args",
                "cwd",
                "env",
                "envFile",
                "url",
                "headers",
                "auth",
                "headersHelper",
            ]
            .contains(&key.as_str())
        })
    {
        risks.insert(Risk::UnreviewedOptions);
    }
    credentials(
        fields,
        "env",
        Credential::InlineEnvironment,
        Credential::EnvironmentReference,
        &mut types,
        &mut risks,
    )?;
    credentials(
        fields,
        "headers",
        Credential::InlineHeader,
        Credential::HeaderReference,
        &mut types,
        &mut risks,
    )?;
    if env_file.is_some() {
        types.insert(Credential::EnvironmentFile);
        risks.insert(Risk::EnvironmentFile);
    }
    if header_helper.is_some() {
        types.insert(Credential::HeaderHelper);
        risks.insert(Risk::HeaderHelper);
    }
    if let Some(auth) = fields.get("auth") {
        if !auth.is_object() {
            return Err(());
        }
        types.insert(Credential::OAuth);
        // Do not imply OAuth values are safely referenced merely because the
        // auth object exists. Actual client credential handling remains unverified.
        risks.insert(Risk::UnreviewedOptions);
    }
    if command
        .into_iter()
        .chain(url)
        .chain(cwd)
        .chain(env_file)
        .chain(args.iter().copied())
        .any(|v| v.contains("${"))
    {
        risks.insert(Risk::VariableExpansion);
    }
    let (transport, destination, package_name, package_version) = if let Some(command) = command {
        let transport = match declared_type {
            None | Some("stdio") => TransportKind::Stdio,
            _ => {
                risks.insert(Risk::TransportUnresolved);
                TransportKind::Unknown
            }
        };
        let program = command
            .rsplit(['/', '\\'])
            .next()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or(())?;
        if !command.contains(['/', '\\']) {
            risks.insert(Risk::PathLookup);
        }
        let lower = program.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "sh" | "bash"
                | "zsh"
                | "dash"
                | "fish"
                | "cmd"
                | "cmd.exe"
                | "powershell"
                | "powershell.exe"
                | "pwsh"
                | "pwsh.exe"
        ) {
            risks.insert(Risk::ShellWrapper);
        }
        if lower.ends_with(".cmd") || lower.ends_with(".bat") {
            risks.insert(Risk::BatchScript);
        }
        let (package_name, package_version) = package(program, &args);
        let destination = (!program.contains("${")).then(|| program.to_owned());
        (transport, destination, package_name, package_version)
    } else {
        // Exactly one of command/url was validated above; avoid retaining a raw
        // URL in errors or the normalized record even if parsing fails.
        let raw = url.ok_or(())?;
        let transport = match declared_type {
            Some("http" | "streamable-http") => TransportKind::Http,
            Some("sse") => TransportKind::Sse,
            _ => {
                risks.insert(Risk::TransportUnresolved);
                TransportKind::Unknown
            }
        };
        if raw.contains("${") {
            risks.insert(Risk::TransportUnresolved);
            (transport, None, None, None)
        } else {
            let parsed = url::Url::parse(raw).map_err(|_| ())?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
                return Err(());
            }
            if !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                risks.insert(Risk::UrlCredentials);
                types.insert(Credential::Url);
            }
            if parsed.scheme() == "http"
                && !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            {
                risks.insert(Risk::InsecureRemote);
            }
            (
                transport,
                Some(parsed.origin().ascii_serialization()),
                None,
                None,
            )
        }
    };
    Ok(DiscoveredServer {
        source_kind: source,
        source_path: source.path(),
        server_name: name.to_owned(),
        transport,
        command_or_url: destination,
        argument_count: args.len(),
        package_name,
        package_version,
        credential_reference_types: types.into_iter().collect(),
        risks: risks.into_iter().collect(),
    })
}
