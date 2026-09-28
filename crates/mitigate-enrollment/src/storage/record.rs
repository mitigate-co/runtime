use super::{Error, anchor::Anchor};
use crate::{EnrollmentCode, EnrollmentIdentity, EnrollmentKey};
use mitigate_egress::SyncRef;
use mitigate_secrets::Secret;

const MAGIC: &str = "mitigate.enrollment.local.v1";
const MAX_RECORD: usize = 768;
pub(super) enum Phase {
    Pending(EnrollmentCode),
    Confirmed(u64),
}
pub(super) struct Record {
    pub key: EnrollmentKey,
    pub identity: EnrollmentIdentity,
    pub phase: Phase,
}
impl Record {
    pub fn encode(&self, anchor: &Anchor) -> Result<Secret, Error> {
        let seed = self.key.to_secret().map_err(|_| Error::Integrity)?;
        let (phase, state) = match &self.phase {
            Phase::Pending(code) => ("pending", code.to_secret().map_err(|_| Error::Integrity)?),
            Phase::Confirmed(time) => ("confirmed", secret(&time.to_string())?),
        };
        seed.expose(|seed| {
            state.expose(|state| {
                Secret::from_bytes(
                    format!(
                        "{MAGIC}\n{}\n{}\n{}\n{}\n{seed}\n{phase}\n{state}\n",
                        anchor.reference.as_str(),
                        anchor.origin.as_str(),
                        self.identity.runtime_ref().as_str(),
                        self.identity.enrollment_ref().as_str()
                    )
                    .into_bytes(),
                )
                .map_err(|_| Error::Integrity)
            })
        })
    }
    pub fn decode(value: Secret, anchor: &Anchor) -> Result<Self, Error> {
        // Borrow fields from the zeroizing owner. Generic JSON deserialization
        // would leave temporary copies of the seed/token in ordinary Strings.
        value.expose(|value| {
            if value.len() > MAX_RECORD {
                return Err(Error::Integrity);
            }
            let mut fields = value.split('\n');
            if fields.next() != Some(MAGIC)
                || fields.next() != Some(anchor.reference.as_str())
                || fields.next() != Some(anchor.origin.as_str())
            {
                return Err(Error::Integrity);
            }
            let runtime = reference(fields.next().ok_or(Error::Integrity)?)?;
            let enrollment = reference(fields.next().ok_or(Error::Integrity)?)?;
            let identity = EnrollmentIdentity::from_references(runtime, enrollment)
                .map_err(|_| Error::Integrity)?;
            let key = EnrollmentKey::from_secret(secret(fields.next().ok_or(Error::Integrity)?)?)
                .map_err(|_| Error::Integrity)?;
            let phase = fields.next().ok_or(Error::Integrity)?;
            let state = fields.next().ok_or(Error::Integrity)?;
            let phase = match phase {
                "pending" => Phase::Pending(
                    EnrollmentCode::from_secret(secret(state)?).map_err(|_| Error::Integrity)?,
                ),
                "confirmed" => {
                    let time: u64 = state.parse().map_err(|_| Error::Integrity)?;
                    if time > 253_402_300_799_999 || time.to_string() != state {
                        return Err(Error::Integrity);
                    }
                    Phase::Confirmed(time)
                }
                _ => return Err(Error::Integrity),
            };
            if fields.next() != Some("") || fields.next().is_some() {
                return Err(Error::Integrity);
            }
            Ok(Self {
                key,
                identity,
                phase,
            })
        })
    }
}
fn secret(value: &str) -> Result<Secret, Error> {
    Secret::from_bytes(value.as_bytes().to_vec()).map_err(|_| Error::Integrity)
}
fn reference(value: &str) -> Result<SyncRef, Error> {
    // References are nonsensitive fixed public fields; only these use serde.
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| Error::Integrity)
}
