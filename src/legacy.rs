//! Safe wrapper for legacy CryptoAPI CSP RSA signing.

use std::{ptr, sync::Arc};

use windows_sys::Win32::Security::Cryptography::*;

use crate::{Result, cert::CertContext, error::CngError};

// windows-sys 0.61 names the legacy provider handle HCRYPTPROV_LEGACY.
#[allow(non_camel_case_types)]
type HCRYPTPROV = HCRYPTPROV_LEGACY;

#[derive(Debug)]
struct InnerLegacyCspKey {
    handle: HCRYPTPROV,
    key_spec: u32,
    caller_free: bool,
    // Retain the certificate context, whose cached key handle can be owned by it.
    _context: CertContext,
}

impl Drop for InnerLegacyCspKey {
    fn drop(&mut self) {
        if self.caller_free {
            unsafe {
                let _ = CryptReleaseContext(self.handle, 0);
            }
        }
    }
}

/// An Arc-backed legacy CryptoAPI provider handle.
#[derive(Clone, Debug)]
pub struct LegacyCspKey {
    inner: Arc<InnerLegacyCspKey>,
}

impl LegacyCspKey {
    /// Wrap a CSP handle while retaining its certificate context.
    pub(crate) fn new(
        handle: HCRYPTPROV,
        key_spec: u32,
        caller_free: bool,
        context: CertContext,
        _silent: bool,
    ) -> Self {
        Self {
            inner: Arc::new(InnerLegacyCspKey {
                handle,
                key_spec,
                caller_free,
                _context: context,
            }),
        }
    }

    /// Return the CryptoAPI key specification for this provider handle.
    pub fn key_spec(&self) -> u32 {
        self.inner.key_spec
    }

    /// Set the provider PIN for the key specification held by this wrapper.
    ///
    /// CryptoAPI expects a NUL-terminated ASCII PIN. Non-ASCII text and
    /// embedded NUL bytes are rejected before making a system call.
    pub fn set_pin(&self, pin: &str) -> Result<()> {
        let mut pin_bytes = pin_bytes(pin).ok_or(CngError::InvalidPinEncoding)?;
        let parameter = match self.inner.key_spec {
            AT_SIGNATURE => PP_SIGNATURE_PIN,
            AT_KEYEXCHANGE => PP_KEYEXCHANGE_PIN,
            _ => {
                pin_bytes.fill(0);
                return Err(CngError::UnsupportedKeyProvider);
            }
        };

        let succeeded = unsafe { CryptSetProvParam(self.inner.handle, parameter, pin_bytes.as_ptr(), 0) != 0 };
        if !succeeded {
            // Capture the error immediately, before doing anything else.
            let error = CngError::from_win32_error();
            pin_bytes.fill(0);
            return Err(error);
        }
        pin_bytes.fill(0);
        Ok(())
    }

    /// Probe whether the CSP can create a hash of the requested digest length.
    ///
    /// This checks CSP hash-algorithm support only; it does not access the
    /// private key or determine whether a PIN will be required for signing.
    pub fn supports_hash(&self, digest_len: usize) -> bool {
        let algorithm = match hash_algorithm(digest_len) {
            Some(algorithm) => algorithm,
            None => return false,
        };
        let mut hash = 0usize;
        if unsafe { CryptCreateHash(self.inner.handle, algorithm, 0, 0, &mut hash) } == 0 {
            return false;
        }
        drop(HashHandle(hash));
        true
    }

    /// Sign a SHA-256, SHA-384, or SHA-512 digest with the legacy CSP key.
    ///
    /// CryptoAPI returns RSA signatures in little-endian byte order; this
    /// method reverses the bytes for the conventional big-endian encoding.
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let algorithm = hash_algorithm(digest.len()).ok_or(CngError::InvalidHashLength)?;

        self.validate_rsa_key()?;

        let mut hash = 0usize;
        if unsafe { CryptCreateHash(self.inner.handle, algorithm, 0, 0, &mut hash) } == 0 {
            return Err(CngError::from_win32_error());
        }
        let hash = HashHandle(hash);

        if unsafe { CryptSetHashParam(hash.0, HP_HASHVAL, digest.as_ptr(), 0) } == 0 {
            return Err(CngError::from_win32_error());
        }

        let mut signature_len = 0u32;
        if unsafe {
            CryptSignHashW(
                hash.0,
                self.inner.key_spec,
                ptr::null(),
                0,
                ptr::null_mut(),
                &mut signature_len,
            )
        } == 0
        {
            return Err(CngError::from_win32_error());
        }

        let mut signature = vec![0u8; signature_len as usize];
        if unsafe {
            CryptSignHashW(
                hash.0,
                self.inner.key_spec,
                ptr::null(),
                0,
                signature.as_mut_ptr(),
                &mut signature_len,
            )
        } == 0
        {
            return Err(CngError::from_win32_error());
        }

        signature.truncate(signature_len as usize);
        signature.reverse();
        Ok(signature)
    }

    pub(crate) fn validate_rsa_key(&self) -> Result<()> {
        let mut key = 0usize;
        if unsafe { CryptGetUserKey(self.inner.handle, self.inner.key_spec, &mut key) } == 0 {
            return Err(CngError::from_win32_error());
        }
        let key = UserKeyHandle(key);

        let mut algorithm = 0u32;
        let mut algorithm_len = std::mem::size_of_val(&algorithm) as u32;
        if unsafe {
            CryptGetKeyParam(
                key.0,
                KP_ALGID,
                (&mut algorithm as *mut u32).cast(),
                &mut algorithm_len,
                0,
            )
        } == 0
        {
            return Err(CngError::from_win32_error());
        }
        if is_rsa_algorithm(self.inner.key_spec, algorithm) {
            Ok(())
        } else {
            Err(CngError::UnsupportedKeyProvider)
        }
    }
}

/// Owned hash handle, destroyed on every return path.
struct HashHandle(usize);

impl Drop for HashHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptDestroyHash(self.0);
        }
    }
}

/// Owned user-key handle, destroyed on every return path.
struct UserKeyHandle(usize);

impl Drop for UserKeyHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptDestroyKey(self.0);
        }
    }
}

fn hash_algorithm(digest_len: usize) -> Option<ALG_ID> {
    match digest_len {
        32 => Some(CALG_SHA_256),
        48 => Some(CALG_SHA_384),
        64 => Some(CALG_SHA_512),
        _ => None,
    }
}

fn is_rsa_algorithm(key_spec: u32, algorithm: ALG_ID) -> bool {
    match key_spec {
        AT_SIGNATURE => algorithm == CALG_RSA_SIGN,
        AT_KEYEXCHANGE => algorithm == CALG_RSA_KEYX,
        _ => false,
    }
}

fn pin_bytes(pin: &str) -> Option<Vec<u8>> {
    if !pin.is_ascii() || pin.as_bytes().contains(&0) {
        return None;
    }
    let capacity = pin.len().checked_add(1)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(pin.as_bytes());
    bytes.push(0);
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::{hash_algorithm, is_rsa_algorithm, pin_bytes};
    use windows_sys::Win32::Security::Cryptography::*;

    #[test]
    fn pin_bytes_are_ascii_and_nul_terminated() {
        assert_eq!(pin_bytes("1234"), Some(b"1234\0".to_vec()));
        assert_eq!(pin_bytes(""), Some(b"\0".to_vec()));
    }

    #[test]
    fn pin_bytes_reject_non_ascii_and_embedded_nul() {
        assert_eq!(pin_bytes("pīn"), None);
        assert_eq!(pin_bytes("one\0two"), None);
    }

    #[test]
    fn hash_algorithm_support_is_limited_to_sha2_digest_sizes() {
        assert_eq!(hash_algorithm(32), Some(CALG_SHA_256));
        assert_eq!(hash_algorithm(48), Some(CALG_SHA_384));
        assert_eq!(hash_algorithm(64), Some(CALG_SHA_512));
        assert_eq!(hash_algorithm(20), None);
    }

    #[test]
    fn only_rsa_key_algorithms_are_accepted_for_their_key_specs() {
        assert!(is_rsa_algorithm(AT_SIGNATURE, CALG_RSA_SIGN));
        assert!(is_rsa_algorithm(AT_KEYEXCHANGE, CALG_RSA_KEYX));
        assert!(!is_rsa_algorithm(AT_SIGNATURE, CALG_DSS_SIGN));
        assert!(!is_rsa_algorithm(AT_KEYEXCHANGE, CALG_RSA_SIGN));
    }
}
