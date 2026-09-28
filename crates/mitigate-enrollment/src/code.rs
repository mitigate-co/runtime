use crate::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mitigate_secrets::Secret;
use zeroize::Zeroizing;

/// One-use enrollment credential. No Debug/Display/Clone/Serialize or raw export.
/// Consume a zeroizing secret owner so malformed input is cleared as well.
pub struct EnrollmentCode {
    pub(crate) grant_id: String,
    pub(crate) token: Zeroizing<[u8; 32]>,
}
impl EnrollmentCode {
    /// Parse exactly `mcp1:<lowercase UUIDv4>:<43-character base64url token>`.
    /// Whitespace, alternate alphabets/padding and nonzero unused bits fail closed.
    pub fn from_secret(input: Secret) -> Result<Self, Error> {
        input.expose(|value| {
            if !value.is_ascii()
                || value.len() != 85
                || !value.starts_with("mcp1:")
                || value.as_bytes()[41] != b':'
                || !valid_uuid(&value[5..41])
            {
                return Err(Error::Code);
            }
            let mut token = Zeroizing::new([0; 32]);
            let count = URL_SAFE_NO_PAD
                .decode_slice(&value[42..], &mut *token)
                .map_err(|_| Error::Code)?;
            if count != 32 {
                return Err(Error::Code);
            }
            Ok(Self {
                grant_id: value[5..41].to_owned(),
                token,
            })
        })
    }
    /// Public receipt identifier. The bootstrap secret is not recoverable here.
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
}
fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, byte)| match i {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'4',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}
