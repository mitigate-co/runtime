//! Native local credentials. Values cannot be formatted, cloned or serialized.
//! Store access is explicit; this module never enumerates a user's credentials.

mod native;
use std::{fmt, io::Read};
use zeroize::Zeroizing;

/// Portable Windows/macOS/Linux environment credential limit, in UTF-8 bytes.
pub const MAX_SECRET_BYTES: usize = 2560;
/// Fixed native-store namespace. This is not an authorization boundary against
/// another process running with the same user's OS privileges.
pub const SERVICE: &str = "co.mitigate.runtime.credentials.v1";

/// An opaque reference, never an inline value, path, account name or provider URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef(String);
impl SecretRef {
    /// Require `sec_` followed by exactly 32 lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() != 36
            || !value.starts_with("sec_")
            || !value.as_bytes()[4..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(Error::InvalidReference);
        }
        Ok(Self(value.to_owned()))
    }
    /// Generate a new reference from 128 bits of OS randomness.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
        let mut value = String::from("sec_");
        for byte in bytes {
            use fmt::Write;
            write!(&mut value, "{byte:02x}").map_err(|_| Error::Unavailable)?;
        }
        Ok(Self(value))
    }
    /// Reference suitable for a local launch document; contains no credential.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Short-lived UTF-8 credential owner. Drop clears the owned allocation.
///
/// No Debug/Display/Serialize/Clone. Exposing a borrow is deliberate: consumers
/// must not copy it into reports or caches. OS/standard-library environment copies
/// and memory in the authorized upstream are outside this allocation's lifetime.
///
/// ```compile_fail
/// let value = mitigate_secrets::Secret::from_bytes(b"synthetic".to_vec()).unwrap();
/// println!("{value:?}"); // Secret values cannot accidentally enter Debug logs.
/// ```
pub struct Secret(Zeroizing<Vec<u8>>);
impl Secret {
    /// Take ownership before validation so rejected data is also cleared.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::validate(Zeroizing::new(bytes))
    }
    fn validate(bytes: Zeroizing<Vec<u8>>) -> Result<Self, Error> {
        if bytes.is_empty()
            || bytes.len() > MAX_SECRET_BYTES
            || bytes.contains(&0)
            || std::str::from_utf8(&bytes).is_err()
        {
            return Err(Error::InvalidValue);
        }
        Ok(Self(bytes))
    }
    /// Read at most 2563 bytes, removing one final LF or CRLF from a pipe.
    /// Callers must reject terminal input rather than accidentally echoing it.
    pub fn from_reader(reader: impl Read) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 3));
        reader
            .take((MAX_SECRET_BYTES + 3) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        Self::validate(bytes)
    }
    /// Borrow only for a local execution/store operation. Never log this value.
    pub fn expose<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        operation(std::str::from_utf8(&self.0).expect("validated secret encoding"))
    }
}

/// Safe errors deliberately discard provider errors, OS paths and secret bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Reference format is invalid.
    InvalidReference,
    /// Empty, oversized, non-UTF-8 or NUL-containing value.
    InvalidValue,
    /// No credential exists at this exact reference.
    Missing,
    /// Store is locked, denied, unavailable, ambiguous or failed.
    Unavailable,
    /// This target has no reviewed native store adapter.
    Unsupported,
}
impl Error {
    /// Stable diagnostic category without user-controlled strings.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidReference => "secret_reference_invalid",
            Self::InvalidValue => "secret_value_invalid",
            Self::Missing => "secret_missing",
            Self::Unavailable => "secret_store_unavailable",
            Self::Unsupported => "secret_store_unsupported",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidReference => "Use a reference returned by mitigate secrets import.",
            Self::InvalidValue => "Supply 1–2560 UTF-8 bytes without NUL characters.",
            Self::Missing => "The credential is missing. Import it locally and update the launch reference.",
            Self::Unavailable => "Cannot access the native credential store. Unlock it through your OS, check permissions, and retry.",
            Self::Unsupported => "No native store is supported on this OS. Use explicit environment references from your secret manager.",
        })
    }
}
impl std::error::Error for Error {}

/// Read-for-execution boundary. Implementations must return content-free errors,
/// never fall back silently, and avoid retaining credential values between reads.
#[allow(async_fn_in_trait)]
pub trait SecretStore {
    /// Resolve exactly one reviewed reference; the caller owns a narrow lease.
    async fn read(&self, reference: &SecretRef) -> Result<Secret, Error>;
}

/// Platform-selected native store, with no process-global provider or value cache.
#[derive(Default)]
pub struct NativeStore;
impl SecretStore for NativeStore {
    async fn read(&self, reference: &SecretRef) -> Result<Secret, Error> {
        native::read(reference).await
    }
}
impl NativeStore {
    /// Explicitly create or replace a value. Do not automatically retry an
    /// interrupted write: check the store or deliberately repeat the operation.
    pub async fn put(&self, reference: &SecretRef, secret: Secret) -> Result<(), Error> {
        native::put(reference, secret).await
    }
    /// Delete precisely one reference; missing values return `Missing`.
    pub async fn delete(&self, reference: &SecretRef) -> Result<(), Error> {
        native::delete(reference).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_opaque_references() {
        let a = SecretRef::generate().unwrap();
        let b = SecretRef::generate().unwrap();
        assert_ne!(a, b);
        assert_eq!(SecretRef::parse(a.as_str()).unwrap(), a);
        for value in [
            "",
            "secret-canary",
            "sec_../../file",
            "sec_ABCDEFGHIJKLMNOP0123456789abcdef",
            "sec_0123456789abcdef0123456789abcdeF",
        ] {
            assert_eq!(SecretRef::parse(value).err(), Some(Error::InvalidReference));
        }
    }
    #[test]
    fn rejected_values_and_read_errors_never_carry_content() {
        for bytes in [vec![], vec![b'x'; MAX_SECRET_BYTES + 1], vec![0], vec![255]] {
            assert_eq!(Secret::from_bytes(bytes).err(), Some(Error::InvalidValue));
        }
        for error in [
            Error::InvalidValue,
            Error::InvalidReference,
            Error::Missing,
            Error::Unavailable,
            Error::Unsupported,
        ] {
            assert!(!format!("{error:?} {error} {}", error.code()).contains("secret-canary"));
        }
    }
    #[test]
    fn pipe_input_is_bounded_and_only_removes_one_line_ending() {
        for bytes in [
            b"secret-canary".as_slice(),
            b"secret-canary\n",
            b"secret-canary\r\n",
        ] {
            assert!(
                Secret::from_reader(bytes)
                    .unwrap()
                    .expose(|s| s == "secret-canary")
            );
        }
        assert!(
            Secret::from_reader(b" a \n\n".as_slice())
                .unwrap()
                .expose(|s| s == " a \n")
        );
        assert!(Secret::from_reader(vec![b'x'; MAX_SECRET_BYTES].as_slice()).is_ok());
        assert_eq!(
            Secret::from_reader(vec![b'x'; MAX_SECRET_BYTES + 10].as_slice()).err(),
            Some(Error::InvalidValue)
        );
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("secret-canary"))
            }
        }
        assert_eq!(Secret::from_reader(Failing).err(), Some(Error::Unavailable));
    }
}
