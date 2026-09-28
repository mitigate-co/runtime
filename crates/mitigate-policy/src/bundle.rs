use crate::{Decision, Error, PROFILE, Policy, PolicyInput};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mitigate_fingerprint::{Fingerprint, canonicalize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const MAX_BUNDLE: usize = 32_768;
const DOMAIN: &[u8] = b"mitigate-mcp-policy-bundle-v1\0";

/// Independently provisioned authority. Never accept a verification key supplied
/// inside an untrusted replacement bundle. Protect this local trust document.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    /// Trust document format, currently one.
    pub schema_version: u32,
    /// Stable policy identifier, not a fingerprint of the changing source.
    pub policy_ref: Fingerprint,
    /// Ed25519 public key as 64 lowercase hex characters; never a private seed.
    pub public_key: String,
}
impl Authority {
    /// Parse a closed, bounded local trust document. Invalid/weak keys fail.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 1024 {
            return Err(Error::Signature);
        }
        let result: Self =
            serde_json::from_value(mitigate_json::parse(bytes).map_err(|_| Error::Signature)?)
                .map_err(|_| Error::Signature)?;
        result.key()?;
        Ok(result)
    }
    pub(crate) fn key(&self) -> Result<VerifyingKey, Error> {
        if self.schema_version != 1 {
            return Err(Error::Signature);
        }
        let key = VerifyingKey::from_bytes(&decode_hex::<32>(&self.public_key)?)
            .map_err(|_| Error::Signature)?;
        if key.is_weak() {
            return Err(Error::Signature);
        }
        Ok(key)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    profile: String,
    policy_ref: Fingerprint,
    version: u64,
    source: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    manifest: Manifest,
    signature: String,
}

/// Signed local source. Deliberately not Debug/Serialize; exporting is explicit.
pub struct SignedBundle {
    envelope: Envelope,
}
impl SignedBundle {
    /// Parse untrusted bytes only. Parsing does not establish trust or activate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BUNDLE {
            return Err(Error::Signature);
        }
        let envelope: Envelope =
            serde_json::from_value(mitigate_json::parse(bytes).map_err(|_| Error::Signature)?)
                .map_err(|_| Error::Signature)?;
        let result = Self { envelope };
        result.validate_format()?;
        Ok(result)
    }
    /// Sign bounded source using a deliberately exposed native-store seed lease.
    /// The caller owns/clears the seed; Dalek clears its owned key on drop.
    pub fn sign(
        policy_ref: Fingerprint,
        version: u64,
        source: String,
        seed: &[u8; 32],
    ) -> Result<Self, Error> {
        Policy::compile(&source)?;
        let mut result = Self {
            envelope: Envelope {
                manifest: Manifest {
                    schema_version: 1,
                    profile: PROFILE.into(),
                    policy_ref,
                    version,
                    source,
                },
                signature: "0".repeat(128),
            },
        };
        result.validate_format()?;
        result.envelope.signature = encode_hex(
            &SigningKey::from_bytes(seed)
                .sign(&result.message()?)
                .to_bytes(),
        );
        result.to_bytes()?;
        Ok(result)
    }
    /// Export the canonical local bundle; never send this through telemetry.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let bytes =
            canonicalize(&serde_json::to_value(&self.envelope).map_err(|_| Error::Signature)?)
                .map_err(|_| Error::Signature)?;
        if bytes.len() > MAX_BUNDLE {
            return Err(Error::Signature);
        }
        Ok(bytes)
    }
    /// Verify the pinned authority and signature before parsing policy source.
    pub fn verify(&self, authority: &Authority) -> Result<ActivePolicy, Error> {
        self.verify_signature(authority)?;
        Ok(ActivePolicy {
            policy: Policy::compile(&self.envelope.manifest.source)?,
            receipt: self.receipt()?,
            authority: authority.clone(),
        })
    }
    pub(crate) fn verify_signature(&self, authority: &Authority) -> Result<(), Error> {
        self.validate_format()?;
        if self.envelope.manifest.policy_ref != authority.policy_ref {
            return Err(Error::Signature);
        }
        authority
            .key()?
            .verify_strict(
                &self.message()?,
                &Signature::from_bytes(&decode_hex::<64>(&self.envelope.signature)?),
            )
            .map_err(|_| Error::Signature)
    }
    fn validate_format(&self) -> Result<(), Error> {
        let m = &self.envelope.manifest;
        if m.schema_version != 1
            || m.profile != PROFILE
            || m.version == 0
            || m.version > 9_007_199_254_740_991
            || m.source.len() > crate::MAX_SOURCE
        {
            return Err(Error::Signature);
        }
        decode_hex::<64>(&self.envelope.signature)?;
        Ok(())
    }
    fn message(&self) -> Result<Vec<u8>, Error> {
        let mut message = DOMAIN.to_vec();
        message.extend(
            canonicalize(
                &serde_json::to_value(&self.envelope.manifest).map_err(|_| Error::Signature)?,
            )
            .map_err(|_| Error::Signature)?,
        );
        Ok(message)
    }
    pub(crate) fn version(&self) -> u64 {
        self.envelope.manifest.version
    }
    fn receipt(&self) -> Result<Receipt, Error> {
        Ok(Receipt {
            schema_version: 1,
            profile: PROFILE.into(),
            policy_ref: self.envelope.manifest.policy_ref.clone(),
            version: self.version(),
            bundle_hash: format!("{:x}", Sha256::digest(self.message()?)),
        })
    }
}
/// Safe local status without source or signing material; not telemetry.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Receipt {
    /// Status format version.
    pub schema_version: u32,
    /// Validated Rego profile.
    pub profile: String,
    /// Bound stable policy reference.
    pub policy_ref: Fingerprint,
    /// Activated positive version.
    pub version: u64,
    /// SHA-256 of the domain-separated signed message, not anonymization.
    pub bundle_hash: String,
}
/// Verified in-memory policy. Disk/network failures do not clear this owner.
pub struct ActivePolicy {
    policy: Policy,
    receipt: Receipt,
    authority: Authority,
}
impl ActivePolicy {
    /// Current verified version and identifiers, with no policy source.
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    /// Evaluate locally without network or persistent-storage dependencies.
    pub fn evaluate(&mut self, input: &PolicyInput) -> Result<Decision, Error> {
        self.policy.evaluate(input)
    }
    /// Persist a valid newer replacement before swapping the loaded policy.
    /// Any error preserves this loaded last-known-good policy.
    pub fn refresh(
        &mut self,
        store: &mut crate::PolicyStore,
        bundle: &SignedBundle,
    ) -> Result<(), Error> {
        if bundle.envelope.manifest.policy_ref != self.receipt.policy_ref
            || bundle.version() <= self.receipt.version
        {
            return Err(Error::Rollback);
        }
        bundle.verify_signature(&self.authority)?;
        let replacement = store.activate(bundle)?;
        *self = replacement;
        Ok(())
    }
}

/// Public key for an explicitly supplied local signing seed.
pub fn public_key(seed: &[u8; 32]) -> String {
    encode_hex(&SigningKey::from_bytes(seed).verifying_key().to_bytes())
}
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 15) as usize] as char);
    }
    text
}
pub(crate) fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Signature);
    }
    let mut bytes = [0u8; N];
    for (i, chunk) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let n = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes[i] = n(chunk[0]) * 16 + n(chunk[1]);
    }
    Ok(bytes)
}
