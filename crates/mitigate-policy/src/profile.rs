//! Positive AST allowlist. Feature flags alone are not a builtin sandbox.
use crate::{Decision, Error, MAX_SOURCE, PolicyInput};
use regorus::{
    Engine, Value,
    unstable::{Expr, Literal, Module, Rule, RuleHead},
    utils::limits::{ExecutionTimerConfig, PolicyLengthConfig},
};
use std::{
    num::{NonZeroU32, NonZeroUsize},
    time::{Duration, Instant},
};

/// A checked policy. No Debug/Serialize: its source is local administrator data.
/// Evaluation grants no gateway authority on its own.
pub struct Policy {
    engine: Engine,
}
impl Policy {
    /// Parse only after lexical size/depth guards, then validate every AST node.
    pub fn compile(source: &str) -> Result<Self, Error> {
        preflight(source)?;
        let mut engine = Engine::new();
        engine.set_rego_v0(false);
        engine.set_gather_prints(true);
        engine.set_strict_builtin_errors(true);
        engine.set_execution_timer_config(ExecutionTimerConfig {
            limit: Duration::from_millis(50),
            check_interval: NonZeroU32::new(1).unwrap(),
        });
        engine.set_policy_length_config(PolicyLengthConfig {
            max_col: NonZeroU32::new(1024).unwrap(),
            max_file_bytes: NonZeroUsize::new(MAX_SOURCE).unwrap(),
            max_lines: NonZeroUsize::new(512).unwrap(),
        });
        let package = engine
            .add_policy("policy.rego".into(), source.into())
            .map_err(|_| Error::Profile)?;
        if package != "data.mitigate.mcp" {
            return Err(Error::Profile);
        }
        let modules = engine.get_modules();
        if modules.len() != 1 {
            return Err(Error::Profile);
        }
        validate_module(&modules[0])?;
        Ok(Self { engine })
    }
    /// Undefined, conflicting, timed-out or malformed decisions fail closed.
    pub fn evaluate(&mut self, input: &PolicyInput) -> Result<Decision, Error> {
        input.validate()?;
        let bytes = serde_json::to_string(input).map_err(|_| Error::Input)?;
        self.engine
            .set_input_json(&bytes)
            .map_err(|_| Error::Input)?;
        let started = Instant::now();
        let output = self
            .engine
            .eval_rule("data.mitigate.mcp.decision".into())
            .map_err(|_| Error::Evaluation)?;
        if started.elapsed() > Duration::from_millis(50) {
            return Err(Error::Evaluation);
        }
        Decision::parse(output.as_string().map_err(|_| Error::Evaluation)?.as_ref())
    }
}
fn named(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Var { value, .. } if value.as_string().is_ok_and(|v| v.as_ref() == name))
}
fn text(value: &Value) -> Result<&str, Error> {
    value
        .as_string()
        .map(|s| s.as_ref())
        .map_err(|_| Error::Profile)
}
fn decision(expr: &Expr) -> Result<Decision, Error> {
    if let Expr::String { value, .. } = expr {
        Decision::parse(text(value)?).map_err(|_| Error::Profile)
    } else {
        Err(Error::Profile)
    }
}
fn validate_module(module: &Module) -> Result<(), Error> {
    if !module.rego_v1
        || !module.imports.is_empty()
        || module.target.is_some()
        || module.policy.len() > 33
        || module.num_expressions > 512
        || module.num_statements > 256
    {
        return Err(Error::Profile);
    }
    let mut defaults = 0;
    let mut bodies_count = 0;
    for rule in &module.policy {
        match rule.as_ref() {
            Rule::Default {
                refr, args, value, ..
            } if named(refr, "decision") && args.is_empty() => {
                if decision(value)? != Decision::Deny {
                    return Err(Error::Profile);
                }
                defaults += 1;
            }
            Rule::Spec {
                head:
                    RuleHead::Compr {
                        refr,
                        assign: Some(assign),
                        ..
                    },
                bodies,
                ..
            } if named(refr, "decision") => {
                decision(&assign.value)?;
                if bodies.is_empty() {
                    return Err(Error::Profile);
                }
                bodies_count += bodies.len();
                if bodies_count > 32 {
                    return Err(Error::Profile);
                }
                for body in bodies {
                    if let Some(assign) = &body.assign {
                        decision(&assign.value)?;
                    }
                    if body.query.stmts.is_empty() || body.query.stmts.len() > 16 {
                        return Err(Error::Profile);
                    }
                    for statement in &body.query.stmts {
                        if !statement.with_mods.is_empty() {
                            return Err(Error::Profile);
                        }
                        match &statement.literal {
                            Literal::Expr { expr, .. } | Literal::NotExpr { expr, .. } => {
                                condition(expr)?
                            }
                            _ => return Err(Error::Profile),
                        }
                    }
                }
            }
            _ => return Err(Error::Profile),
        }
    }
    if defaults != 1 {
        return Err(Error::Profile);
    }
    Ok(())
}
fn input_field(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::RefDot { refr, field, .. } if named(refr, "input") => text(&field.1).ok(),
        _ => None,
    }
}
fn scalar(expr: &Expr) -> bool {
    match expr {
        Expr::String { value, .. } => text(value).is_ok_and(|s| s.len() <= 128),
        Expr::Number { value, .. } => value.as_u64().is_ok_and(|v| v <= 999),
        Expr::Bool { .. } | Expr::Null { .. } => true,
        _ => false,
    }
}
fn operand(expr: &Expr) -> bool {
    scalar(expr)
        || input_field(expr).is_some_and(|field| {
            matches!(
                field,
                "schema_version"
                    | "client"
                    | "principal"
                    | "agent"
                    | "server"
                    | "tool"
                    | "schema_fingerprint"
                    | "schema_changed"
                    | "grant"
                    | "offline"
            )
        })
        || matches!(expr, Expr::Call { fcn, params, .. } if named(fcn, "count") && params.len() == 1 && input_field(&params[0]) == Some("capabilities"))
}
fn condition(expr: &Expr) -> Result<(), Error> {
    let valid = match expr {
        Expr::BoolExpr { lhs, rhs, .. } => operand(lhs) && operand(rhs),
        Expr::Membership {
            key: None,
            value,
            collection,
            ..
        } => {
            operand(value)
                && (input_field(collection) == Some("capabilities")
                    || matches!(collection.as_ref(), Expr::Array { items, .. } | Expr::Set { items, .. } if items.len() <= 32 && items.iter().all(|i| scalar(i))))
        }
        Expr::Bool { .. } => true,
        _ => input_field(expr).is_some_and(|f| matches!(f, "schema_changed" | "offline")),
    };
    if valid { Ok(()) } else { Err(Error::Profile) }
}

/// Bound parser recursion and numeric/string expansion before Regorus allocates
/// an AST. This is a lexical guard, not a replacement Rego parser. AST validation
/// below remains authoritative. No escapes/raw strings/exponents in profile v1.
fn preflight(source: &str) -> Result<(), Error> {
    if source.is_empty() || source.len() > MAX_SOURCE || !source.is_ascii() {
        return Err(Error::Profile);
    }
    let bytes = source.as_bytes();
    let (mut cursor, mut tokens, mut depth) = (0, 0, 0usize);
    while cursor < bytes.len() {
        let b = bytes[cursor];
        if b.is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        if b == b'#' {
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }
        tokens += 1;
        if tokens > 1024 {
            return Err(Error::Profile);
        }
        if b == b'"' {
            cursor += 1;
            let start = cursor;
            while cursor < bytes.len() && bytes[cursor] != b'"' {
                if !(32..=126).contains(&bytes[cursor]) || bytes[cursor] == b'\\' {
                    return Err(Error::Profile);
                }
                cursor += 1;
            }
            if cursor == bytes.len() || cursor - start > 128 {
                return Err(Error::Profile);
            }
            cursor += 1;
        } else if b.is_ascii_alphabetic() || b == b'_' {
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
        } else if b.is_ascii_digit() {
            let start = cursor;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                cursor += 1;
            }
            if cursor - start > 3
                || bytes
                    .get(cursor)
                    .is_some_and(|b| *b == b'.' || b.is_ascii_alphabetic())
            {
                return Err(Error::Profile);
            }
        } else {
            match b {
                b'{' | b'[' | b'(' => {
                    depth += 1;
                    if depth > 16 {
                        return Err(Error::Profile);
                    }
                }
                b'}' | b']' | b')' => {
                    depth = depth.checked_sub(1).ok_or(Error::Profile)?;
                }
                b'.' | b',' | b';' | b':' | b'=' | b'!' | b'<' | b'>' => (),
                _ => return Err(Error::Profile),
            }
            cursor += 1;
        }
    }
    if depth != 0 {
        return Err(Error::Profile);
    }
    Ok(())
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    #[test]
    fn exhausted_timer_never_returns_allow() {
        let mut policy = Policy::compile(
            "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"allow\" if { true }",
        )
        .unwrap();
        policy
            .engine
            .set_execution_timer_config(ExecutionTimerConfig {
                limit: Duration::ZERO,
                check_interval: NonZeroU32::new(1).unwrap(),
            });
        let input =
            PolicyInput::from_bytes(include_bytes!("../../../examples/policies/read-input.json"))
                .unwrap();
        assert_eq!(policy.evaluate(&input), Err(Error::Evaluation));
    }
}
