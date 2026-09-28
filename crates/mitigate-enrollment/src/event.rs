//! Integrity for one previously admitted Zero-Content outbox event. No network,
//! consent mutation, native-store access or receipt persistence occurs here.
use crate::{EnrollmentIdentity, PlatformOrigin};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use mitigate_egress::{SyncRef, outbox::Lease};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[cfg(test)]
mod tests;

/// Fixed endpoint, also bound into the signature transcript.
pub const EVENT_PATH: &str = "/api/v1/runtime/events";
/// Checked event (4 KiB) plus a bounded signature/identity envelope.
pub const MAX_SIGNED_EVENT_BYTES: usize = mitigate_egress::MAX_EVENT_BYTES + 1024;
/// Closed receiver acknowledgment, before untrusted JSON parsing.
pub const MAX_EVENT_RECEIPT_BYTES: usize = 1024;

/// Fixed failure categories; no rejected body, identifier or parser diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The lease belongs to another Runtime or enrollment.
    Scope,
    /// A bounded signed envelope could not be encoded.
    Encoding,
    /// Receipt is malformed or does not acknowledge this exact signed event.
    Receipt,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Scope => "The queued event does not match this enrollment. Pause sync and inspect its configuration.",
            Self::Encoding => "The checked event could not be signed within its limits.",
            Self::Receipt => "Event acceptance was not confirmed. Retain the same queued event for recovery.",
        })
    }
}
impl std::error::Error for Error {}

/// Bounded signed request. Only a checked, journaled outbox lease can construct
/// it; there is no raw-body constructor or generic Debug/Serialize/Deserialize.
/// A stale/purged lease is still owned memory: the sender must recheck consent,
/// current lease and enrollment before sending. Signing is not authorization.
///
/// ```compile_fail
/// let _: mitigate_enrollment::event::SignedEvent = serde_json::from_str("{}").unwrap();
/// ```
pub struct SignedEvent {
    origin: PlatformOrigin,
    identity: EnrollmentIdentity,
    event_id: SyncRef,
    digest: String,
    bytes: Vec<u8>,
}
impl SignedEvent {
    pub(crate) fn from_lease(
        key: &SigningKey,
        origin: &PlatformOrigin,
        identity: &EnrollmentIdentity,
        lease: &Lease,
    ) -> Result<Self, Error> {
        let partition = lease.partition();
        if &partition.runtime_ref != identity.runtime_ref()
            || &partition.enrollment_ref != identity.enrollment_ref()
            || lease.event().runtime_ref() != identity.runtime_ref()
        {
            return Err(Error::Scope);
        }
        let event = lease.event();
        // Only the canonical admitted event is hashed. Never hash rejected raw
        // workload content or substitute local audit/config fingerprints.
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(event.as_bytes()));
        let transcript = format!(
            "mitigate.runtime.event.v1\n{}\nPOST\n{EVENT_PATH}\n{}\n{}\n{}\n{digest}\n",
            origin.as_str(),
            identity.runtime_ref().as_str(),
            identity.enrollment_ref().as_str(),
            event.event_id().as_str(),
        );
        let signature = URL_SAFE_NO_PAD.encode(key.sign(transcript.as_bytes()).to_bytes());
        #[derive(Serialize)]
        struct Envelope<'a> {
            schema_version: u8,
            enrollment_ref: &'a SyncRef,
            event: serde_json::Value,
            signature: String,
        }
        let bytes = serde_json::to_vec(&Envelope {
            schema_version: 1,
            enrollment_ref: identity.enrollment_ref(),
            event: serde_json::from_slice(event.as_bytes()).map_err(|_| Error::Encoding)?,
            signature,
        })
        .map_err(|_| Error::Encoding)?;
        if bytes.len() > MAX_SIGNED_EVENT_BYTES {
            return Err(Error::Encoding);
        }
        Ok(Self {
            origin: origin.clone(),
            identity: identity.clone(),
            event_id: event.event_id().clone(),
            digest,
            bytes,
        })
    }
    /// The fixed HTTPS audience that the caller must authenticate without redirects.
    pub fn origin(&self) -> &PlatformOrigin {
        &self.origin
    }
    /// Explicit bytes for the fixed POST endpoint, never ordinary log output.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Require an authenticated receiver's acknowledgment of the exact event,
    /// enrollment and canonical digest. This does not authenticate HTTPS, prove
    /// current authority or complete/delete a local outbox lease.
    pub fn verify_receipt(&self, bytes: &[u8]) -> Result<EventReceipt, Error> {
        if bytes.len() > MAX_EVENT_RECEIPT_BYTES {
            return Err(Error::Receipt);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Receipt {
            schema_version: u8,
            event_id: SyncRef,
            runtime_ref: SyncRef,
            enrollment_ref: SyncRef,
            event_digest: String,
            status: Accepted,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Accepted {
            Accepted,
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Receipt)?;
        let receipt: Receipt = serde_json::from_value(value).map_err(|_| Error::Receipt)?;
        if receipt.schema_version != 1
            || receipt.event_id != self.event_id
            || &receipt.runtime_ref != self.identity.runtime_ref()
            || &receipt.enrollment_ref != self.identity.enrollment_ref()
            || receipt.event_digest != self.digest
        {
            return Err(Error::Receipt);
        }
        let Accepted::Accepted = receipt.status;
        Ok(EventReceipt {
            event_id: self.event_id.clone(),
        })
    }
}

/// Receipt bound to the original signed body, without a public constructor.
/// Valid JSON alone must never claim successful durable delivery.
///
/// ```compile_fail
/// let _: mitigate_enrollment::event::EventReceipt = serde_json::from_str("{}").unwrap();
/// ```
pub struct EventReceipt {
    event_id: SyncRef,
}
impl EventReceipt {
    /// The exact event whose digest and enrollment were acknowledged.
    pub fn event_id(&self) -> &SyncRef {
        &self.event_id
    }
}
