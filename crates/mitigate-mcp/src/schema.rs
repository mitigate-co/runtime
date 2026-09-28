//! Local tool-schema validation. Untrusted schemas never retrieve resources.
//!
//! The versioned execution profile is deliberately narrower than unrestricted
//! JSON Schema. Unsupported schemas remain inspectable but cannot authorize a
//! call. See docs/SCHEMA_VALIDATION.md for dialect, complexity and timeout limits.

mod profile;

use crate::{Error, Result};
use jsonschema::{Draft, PatternOptions, Validator};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// Execution profile; changing accepted semantics requires a new version.
pub const PROFILE: &str = "mitigate-tool-schema-2020-12-v1";

// A timed-out blocking task retains its permit until it actually exits. Dropped
// futures cannot accumulate unbounded detached validators on Tokio's work queue.
static WORKERS: Semaphore = Semaphore::const_new(4);
const DEADLINE: Duration = Duration::from_secs(2);

pub(crate) fn argument_bounds(value: &Value) -> Result<()> {
    profile::document(value, 60_000)
        .map(|_| ())
        .map_err(|_| Error::Limit)
}

/// Compiled, bounded local schema. No serialization/debug API exposes its source.
#[derive(Clone)]
pub struct ToolSchema {
    validator: Arc<Validator>,
    cost: usize,
}

impl ToolSchema {
    /// Check the execution profile and compile a Draft 2020-12 object schema.
    /// Compilation never retrieves external schemas, files or native secrets.
    pub async fn compile(schema: &Value) -> Result<Self> {
        profile::document(schema, 65_536)?;
        let schema = schema.clone();
        blocking(move || {
            let cost = profile::check(&schema)?;
            let validator = jsonschema::options()
                .with_draft(Draft::Draft202012)
                .offline()
                .should_validate_formats(false)
                .with_pattern_options(
                    PatternOptions::regex()
                        .size_limit(65_536)
                        .dfa_size_limit(65_536),
                )
                .build(&schema)
                .map_err(|_| Error::Schema)?;
            Ok(Self {
                validator: Arc::new(validator),
                cost,
            })
        })
        .await
    }

    /// Validate one local value without echoing it, coercing types, inserting
    /// defaults or returning source-bearing dependency diagnostics.
    pub async fn validate(&self, value: &Value) -> Result<()> {
        let complexity = profile::document(value, 1_048_576)?;
        if self.cost.saturating_mul(complexity) > 4_194_304 {
            return Err(Error::SchemaLimit);
        }
        let validator = self.validator.clone();
        let value = value.clone();
        blocking(move || {
            validator
                .validate(&value)
                .map_err(|_| Error::SchemaMismatch)
        })
        .await
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    blocking_with(&WORKERS, DEADLINE, work).await
}

async fn blocking_with<T: Send + 'static>(
    workers: &'static Semaphore,
    limit: Duration,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    // This bounds the caller's wait, not the OS thread's execution. The profile
    // bounds work independently. There is no process launch in this worker.
    let deadline = tokio::time::Instant::now() + limit;
    let permit = tokio::time::timeout_at(deadline, workers.acquire())
        .await
        .map_err(|_| Error::SchemaLimit)?
        .map_err(|_| Error::SchemaLimit)?;
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::SchemaLimit);
        }
        let result = work();
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::SchemaLimit);
        }
        result
    });
    let result = tokio::time::timeout_at(deadline, task)
        .await
        .map_err(|_| Error::SchemaLimit)?
        .map_err(|_| Error::SchemaLimit)?;
    // A ready future can win timeout's poll even after the deadline elapsed.
    if tokio::time::Instant::now() >= deadline {
        return Err(Error::SchemaLimit);
    }
    result
}

#[cfg(test)]
mod tests;
