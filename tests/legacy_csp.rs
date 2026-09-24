#![cfg(windows)]

use std::ptr;

use rustls_cng::cert::{AcquiredKey, CertContext};
use rustls_cng::rustls::crypto::{SignatureScheme, SigningKey};
use rustls_cng::signer::ProviderSigningKey;
use sha2::{Digest, Sha256};
use windows_sys::Win32::{Foundation::GetLastError, Security::Cryptography::*};

const PROVIDER_NAME: &str = "Microsoft Enhanced RSA and AES Cryptographic Provider";

struct TemporaryContainer {
    handle: usize,
    name: Vec<u16>,
}

impl Drop for TemporaryContainer {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptReleaseContext(self.handle, 0);
            // Deleting the keyset removes the generated private key and its container.
            let mut deleted_handle = 0usize;
            let _ = CryptAcquireContextW(
                &mut deleted_handle,
                self.name.as_ptr(),
                ptr::null(),
                PROV_RSA_AES,
                CRYPT_DELETEKEYSET,
            );
        }
    }
}

struct CryptoHash(usize);

impl Drop for CryptoHash {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptDestroyHash(self.0);
        }
    }
}

struct CryptoKey(usize);

impl Drop for CryptoKey {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptDestroyKey(self.0);
        }
    }
}

fn windows_error(operation: &str) -> String {
    format!("{operation} failed with Win32 error {}", unsafe { GetLastError() })
}

fn create_container() -> TemporaryContainer {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    let name = format!("rustls-cng-legacy-csp-test-{}-{nonce}", std::process::id())
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut handle = 0usize;
    let succeeded =
        unsafe { CryptAcquireContextW(&mut handle, name.as_ptr(), ptr::null(), PROV_RSA_AES, CRYPT_NEWKEYSET) } != 0;
    assert!(succeeded, "{}", windows_error("CryptAcquireContextW(CRYPT_NEWKEYSET)"));

    let container = TemporaryContainer { handle, name };
    let mut private_key = 0usize;
    let succeeded = unsafe {
        CryptGenKey(
            container.handle,
            AT_SIGNATURE,
            (2048 << 16) | CRYPT_EXPORTABLE,
            &mut private_key,
        )
    } != 0;
    let private_key = CryptoKey(private_key);
    assert!(succeeded, "{}", windows_error("CryptGenKey"));
    drop(private_key);
    container
}

fn self_signed_certificate(container: &TemporaryContainer) -> CertContext {
    let subject = "CN=rustls-cng-legacy-csp-test\0".encode_utf16().collect::<Vec<_>>();
    let encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    let mut name_len = 0u32;
    let succeeded = unsafe {
        CertStrToNameW(
            encoding,
            subject.as_ptr(),
            CERT_X500_NAME_STR,
            ptr::null(),
            ptr::null_mut(),
            &mut name_len,
            ptr::null_mut(),
        )
    } != 0;
    assert!(succeeded, "{}", windows_error("CertStrToNameW(size)"));
    let mut encoded_name = vec![0u8; name_len as usize];
    let succeeded = unsafe {
        CertStrToNameW(
            encoding,
            subject.as_ptr(),
            CERT_X500_NAME_STR,
            ptr::null(),
            encoded_name.as_mut_ptr(),
            &mut name_len,
            ptr::null_mut(),
        )
    } != 0;
    assert!(succeeded, "{}", windows_error("CertStrToNameW(encode)"));
    let subject_blob = CRYPT_INTEGER_BLOB {
        cbData: name_len,
        pbData: encoded_name.as_mut_ptr(),
    };
    let container_name = container.name.as_ptr() as *mut u16;
    let mut provider_name = PROVIDER_NAME.encode_utf16().chain([0]).collect::<Vec<_>>();
    let key_provider_info = CRYPT_KEY_PROV_INFO {
        pwszContainerName: container_name,
        pwszProvName: provider_name.as_mut_ptr(),
        dwProvType: PROV_RSA_AES,
        dwKeySpec: AT_SIGNATURE,
        ..Default::default()
    };

    let context = unsafe {
        CertCreateSelfSignCertificate(
            container.handle,
            &subject_blob,
            0,
            &key_provider_info,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    assert!(!context.is_null(), "{}", windows_error("CertCreateSelfSignCertificate"));
    CertContext::new_owned(context)
}

#[test]
fn acquires_and_uses_a_real_legacy_csp_rsa_key() {
    let container = create_container();
    let certificate = self_signed_certificate(&container);

    let key = match certificate
        .acquire_signing_key(true)
        .expect("acquire certificate signing key")
    {
        AcquiredKey::LegacyCsp(key) => key,
        AcquiredKey::Cng(_) => panic!("software CryptoAPI key unexpectedly acquired as CNG"),
    };
    assert_eq!(key.key_spec(), AT_SIGNATURE);

    let message = b"legacy CSP integration signing test";
    let digest = Sha256::digest(message);
    assert!(key.supports_hash(digest.len()), "CSP does not support SHA-256");
    assert!(key.set_pin("bad\0pin").is_err(), "embedded NUL PIN must be rejected");
    let signer = ProviderSigningKey::new(AcquiredKey::LegacyCsp(key.clone())).expect("create rustls signer");
    assert!(signer.supported_schemes().contains(&SignatureScheme::RSA_PKCS1_SHA256));
    assert!(!signer.supported_schemes().contains(&SignatureScheme::RSA_PSS_SHA256));
    let signature = signer
        .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
        .expect("select CSP RSA PKCS#1 scheme")
        .sign(message)
        .expect("sign SHA-256 digest");

    // Independently verify the result with CryptoAPI's public-key verifier and the
    // public key encoded in the self-signed certificate.
    let public_key = unsafe {
        let info = &(*certificate.inner().pCertInfo).SubjectPublicKeyInfo;
        let mut imported = 0usize;
        let succeeded = CryptImportPublicKeyInfo(
            container.handle,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            info,
            &mut imported,
        ) != 0;
        assert!(succeeded, "{}", windows_error("CryptImportPublicKeyInfo"));
        CryptoKey(imported)
    };
    let mut hash = 0usize;
    let succeeded = unsafe { CryptCreateHash(container.handle, CALG_SHA_256, 0, 0, &mut hash) } != 0;
    assert!(succeeded, "{}", windows_error("CryptCreateHash"));
    let hash = CryptoHash(hash);
    let succeeded = unsafe { CryptSetHashParam(hash.0, HP_HASHVAL, digest.as_ptr(), 0) } != 0;
    assert!(succeeded, "{}", windows_error("CryptSetHashParam"));

    // CryptVerifySignatureW consumes CryptoAPI's little-endian RSA signature form.
    let mut cryptoapi_signature = signature;
    cryptoapi_signature.reverse();
    let succeeded = unsafe {
        CryptVerifySignatureW(
            hash.0,
            cryptoapi_signature.as_ptr(),
            cryptoapi_signature.len() as u32,
            public_key.0,
            ptr::null(),
            0,
        )
    } != 0;
    assert!(succeeded, "{}", windows_error("CryptVerifySignatureW"));

    drop(hash);
    drop(public_key);
    drop(key);
    drop(certificate);
    drop(container);
}
