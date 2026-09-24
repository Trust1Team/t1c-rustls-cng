//! On Windows: cargo run --example diagnose_provider -- <certificate SHA-1 thumbprint>
//! Uses CurrentUser\My and lets the provider display its normal PIN UI.
//! Never pass a PIN on the command line or record it in a log.

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rustls_cng::{
        cert::AcquiredKey,
        signer::ProviderSigningKey,
        store::{CertStore, CertStoreType},
    };
    use sha2::{Digest, Sha256};

    let arg = std::env::args()
        .nth(1)
        .ok_or("Provide a certificate SHA-1 thumbprint")?;
    let hex = arg.replace([' ', ':'], "");
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Expected a 40-character SHA-1 certificate thumbprint".into());
    }
    let thumbprint = (0..40)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;

    let store = CertStore::open(CertStoreType::CurrentUser, "My")?;
    let matches = store.find_by_sha1(thumbprint)?;
    if matches.len() != 1 {
        return Err(format!("Expected exactly one matching certificate, found {}", matches.len()).into());
    }
    let certificate = &matches[0];
    println!("Matching certificate found in CurrentUser\\My");
    let acquired = certificate.acquire_signing_key(false)?;
    println!(
        "Acquired private key using {}",
        match &acquired {
            AcquiredKey::Cng(_) => "CNG KSP",
            AcquiredKey::LegacyCsp(_) => "legacy CryptoAPI CSP",
        }
    );

    let key = ProviderSigningKey::new(acquired)?;
    println!("Supported schemes: {:?}", key.supported_schemes());
    let digest = Sha256::digest(b"rustls-cng provider diagnostic");
    let signature = key.sign_rsa_pkcs1(&digest)?;
    println!(
        "RSA PKCS#1 SHA-256 signing succeeded ({} signature bytes)",
        signature.len()
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This diagnostic requires Windows.");
}
