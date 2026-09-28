use crate::{EnrollmentCode, EnrollmentIdentity, Error, MAX_ENROLLMENT_BYTES, PlatformOrigin};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use mitigate_egress::SyncRef;
use mitigate_secrets::Secret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Private signing key, zeroized by Dalek on drop. No generic formatting/export.
/// The seed may be exported only into the existing native-store secret owner.
pub struct EnrollmentKey(SigningKey);
impl EnrollmentKey {
    /// Generate a fresh Ed25519 seed using OS randomness.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *seed).map_err(|_| Error::Randomness)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }
    /// Restore a canonical 32-byte base64url seed read from the native store.
    pub fn from_secret(secret: Secret) -> Result<Self, Error> {
        secret.expose(|value| {
            if value.len() != 43 {
                return Err(Error::Key);
            }
            let mut seed = Zeroizing::new([0; 32]);
            if URL_SAFE_NO_PAD
                .decode_slice(value, &mut *seed)
                .map_err(|_| Error::Key)?
                != 32
            {
                return Err(Error::Key);
            }
            Ok(Self(SigningKey::from_bytes(&seed)))
        })
    }
    /// Explicit native-store material; never write this to config, SQLite or logs.
    pub fn to_secret(&self) -> Result<Secret, Error> {
        let seed = Zeroizing::new(self.0.to_bytes());
        // Borrow slices so the encoder cannot copy the fixed array out of its
        // zeroizing owner, even though generic AsRef would also accept by value.
        Secret::from_bytes(URL_SAFE_NO_PAD.encode(seed.as_slice()).into_bytes())
            .map_err(|_| Error::Key)
    }
    /// Pure Ed25519 possession proof binding the origin, grant, token digest,
    /// public key and both references. This does not authorize network transmission.
    pub fn claim(
        &self,
        origin: &PlatformOrigin,
        code: &EnrollmentCode,
        identity: &EnrollmentIdentity,
    ) -> Result<EnrollmentClaim, Error> {
        let public_key = URL_SAFE_NO_PAD.encode(self.0.verifying_key().to_bytes());
        let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(code.token.as_slice()));
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(code.token.as_slice()));
        let message = Zeroizing::new(format!(
            "mitigate.runtime.enrollment.v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
            origin.as_str(),
            code.grant_id(),
            digest,
            public_key,
            identity.runtime_ref().as_str(),
            identity.enrollment_ref().as_str()
        ));
        let signature = URL_SAFE_NO_PAD.encode(self.0.sign(message.as_bytes()).to_bytes());
        #[derive(Serialize)]
        struct Body<'a> {
            grant_id: &'a str,
            token: &'a str,
            public_key: &'a str,
            runtime_ref: &'a str,
            enrollment_ref: &'a str,
            signature: &'a str,
        }
        let bytes = Zeroizing::new(
            serde_json::to_vec(&Body {
                grant_id: code.grant_id(),
                token: &token,
                public_key: &public_key,
                runtime_ref: identity.runtime_ref().as_str(),
                enrollment_ref: identity.enrollment_ref().as_str(),
                signature: &signature,
            })
            .map_err(|_| Error::Encoding)?,
        );
        if bytes.len() > MAX_ENROLLMENT_BYTES {
            return Err(Error::Encoding);
        }
        Ok(EnrollmentClaim {
            bytes,
            origin: origin.clone(),
            identity: identity.clone(),
        })
    }
}

/// Secret-bearing signed HTTP body. Deliberate byte access only; no generic Debug,
/// Display, Clone or Serialize. A lost response must retry these identical bytes.
///
/// ```compile_fail
/// fn accidental_log(claim: &mitigate_enrollment::EnrollmentClaim) {
///     println!("{claim:?}");
/// }
/// ```
pub struct EnrollmentClaim {
    bytes: Zeroizing<Vec<u8>>,
    origin: PlatformOrigin,
    identity: EnrollmentIdentity,
}
impl EnrollmentClaim {
    /// Borrow only for an explicit HTTPS bootstrap POST, never telemetry or audit.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Independently validated destination bound into this exact signature.
    pub fn origin(&self) -> &PlatformOrigin {
        &self.origin
    }
    /// Accept only the closed success receipt for this exact pair of references.
    /// HTTPS authentication is still required; JSON cannot authenticate a server.
    pub fn verify_receipt(&self, bytes: &[u8]) -> Result<EnrollmentReceipt, Error> {
        if bytes.len() > MAX_ENROLLMENT_BYTES {
            return Err(Error::Receipt);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Receipt)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            schema_version: u8,
            enrollment: ReceiptBody,
        }
        let response: Envelope = serde_json::from_value(value).map_err(|_| Error::Receipt)?;
        let receipt = response.enrollment;
        if response.schema_version != 1
            || receipt.runtime_ref != self.identity.runtime
            || receipt.enrollment_ref != self.identity.enrollment
            || receipt.enrolled_at_ms > 253_402_300_799_999
        {
            return Err(Error::Receipt);
        }
        Ok(EnrollmentReceipt {
            identity: self.identity.clone(),
            enrolled_at_ms: receipt.enrolled_at_ms,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Active {
    Active,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptBody {
    enrollment_ref: SyncRef,
    runtime_ref: SyncRef,
    enrolled_at_ms: u64,
    #[serde(rename = "status")]
    _status: Active,
}
/// Public opaque receipt validated against a specific claim. No public constructor
/// or Deserialize: parsing alone must not confer confirmed enrollment state.
///
/// ```compile_fail
/// let _: mitigate_enrollment::EnrollmentReceipt = serde_json::from_str("{}").unwrap();
/// ```
pub struct EnrollmentReceipt {
    identity: EnrollmentIdentity,
    enrolled_at_ms: u64,
}
impl EnrollmentReceipt {
    /// Confirmed opaque Runtime reference.
    pub fn runtime_ref(&self) -> &SyncRef {
        self.identity.runtime_ref()
    }
    /// Confirmed opaque enrollment reference.
    pub fn enrollment_ref(&self) -> &SyncRef {
        self.identity.enrollment_ref()
    }
    /// Server observation time in Unix milliseconds, not local clock authority.
    pub fn enrolled_at_ms(&self) -> u64 {
        self.enrolled_at_ms
    }
}
