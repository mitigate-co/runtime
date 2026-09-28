//! Closed taxonomy and explainable sources. No arbitrary metadata or matched values.

use serde::{Deserialize, Serialize};

/// Version-one capability taxonomy. These are hints, not granted permissions.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    /// Reads data or inventory.
    ReadData,
    /// Creates or modifies data.
    WriteData,
    /// Removes data or resources.
    DeleteData,
    /// Runs commands, scripts or unconstrained queries.
    ExecuteCode,
    /// Reads, changes or accepts credentials.
    CredentialAccess,
    /// Sends data or requests to an external destination.
    ExternalCommunication,
    /// Controls browser actions.
    BrowserAction,
    /// Modifies identity, membership, roles or permissions.
    IdentityAdmin,
    /// Performs financial operations.
    FinancialAction,
    /// Changes infrastructure resources or configuration.
    InfrastructureChange,
    /// Available evidence cannot classify the operation.
    Unknown,
}

/// Confidence in a declared classification, not confidence that a tool is safe.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Name-only inference or insufficient evidence.
    Low,
    /// Schema shape contributes evidence; implementation remains unverified.
    Medium,
    /// Explicit administrator declaration bound to the observed definition.
    High,
}

/// Implemented source of classification evidence.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationSource {
    /// Versioned deterministic rules, not description instructions.
    Deterministic,
    /// Explicit local administrator override.
    Admin,
}

/// Security-significant review flags. None authorizes or blocks execution itself.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlag {
    /// Potential data/resource destruction.
    Destructive,
    /// Potential credential access.
    CredentialAccess,
    /// Potential unconstrained code/command/query execution.
    ArbitraryCodeExecution,
    /// Potential external communication.
    ExternalCommunication,
    /// Potential identity/permission administration.
    IdentityAdmin,
    /// Potential infrastructure changes.
    InfrastructureChange,
    /// Unknown or opaque operation requires review, not a safe default.
    UnknownHighImpact,
}

/// Structured classification with auditable rule IDs and baseline preservation.
#[derive(Serialize)]
pub struct Classification {
    /// Taxonomy/rule contract version.
    pub taxonomy_version: u32,
    /// Effective classes after an explicit matching override, if any.
    pub classes: Vec<CapabilityClass>,
    /// Strength/type of classification evidence, not a safety rating.
    pub confidence: Confidence,
    /// Contributing sources. Registry enrichment is a later package.
    pub sources: Vec<ClassificationSource>,
    /// Conservative union of baseline and override risk flags.
    pub flags: Vec<RiskFlag>,
    /// Fixed rule identifiers, never raw matched property names or values.
    pub rules: Vec<&'static str>,
    /// Original deterministic classes, retained even after replacement.
    pub inferred_classes: Vec<CapabilityClass>,
    /// Whether a matching administrator override changed the effective classes.
    pub overridden: bool,
}

pub(super) fn flags(classes: &[CapabilityClass]) -> Vec<RiskFlag> {
    use CapabilityClass as C;
    use RiskFlag as F;
    let mut result = std::collections::BTreeSet::new();
    for class in classes {
        match class {
            C::DeleteData => {
                result.insert(F::Destructive);
            }
            C::ExecuteCode => {
                result.insert(F::ArbitraryCodeExecution);
            }
            C::CredentialAccess => {
                result.insert(F::CredentialAccess);
            }
            C::ExternalCommunication => {
                result.insert(F::ExternalCommunication);
            }
            C::IdentityAdmin => {
                result.insert(F::IdentityAdmin);
            }
            C::InfrastructureChange => {
                result.insert(F::InfrastructureChange);
            }
            C::Unknown => {
                result.insert(F::UnknownHighImpact);
            }
            _ => (),
        }
    }
    result.into_iter().collect()
}
