# Windows CNG bridge for rustls

[![github actions](https://github.com/ancwrd1/rustls-cng/workflows/CI/badge.svg)](https://github.com/rustls/rustls-cng/actions)
[![crates](https://img.shields.io/crates/v/rustls-cng.svg)](https://crates.io/crates/rustls-cng)
[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![docs.rs](https://docs.rs/rustls-cng/badge.svg)](https://docs.rs/rustls-cng)

This crate allows you to use the Windows CNG private keys together with [rustls](https://docs.rs/rustls/latest/rustls)
 for both the client and server sides of the TLS channel.

Rationale: In many situations, it is required to use non-exportable private certificate chains
 from the Windows certificate store instead of the external PKCS8 file.
 `rustls-cng` can use such chains in the `rustls` context.

Supported key/certificate types: **RSA**, **ECDSA/ECDH**. Supported elliptic curves: secp256r1 (prime256v1), secp384r1, secp521r1.

[Documentation](https://docs.rs/rustls-cng).

## Usage

The main struct to use in `rustls-cng` is `CngSigningKey`, which can be constructed
 from the low-level `NCryptKey` handle. The instance of `CngSigningKey` can then be
 used in `rustls` in the custom `ServerCredentialResolver` or `ClientCredentialResolver` implementation.

See the `examples` directory for usage examples.

### Legacy CryptoAPI CSP tokens (feature/support-legacy)

`CertContext::acquire_key(silent)` remains CNG-only. To accept either a CNG KSP
or a legacy CryptoAPI CSP, use `CertContext::acquire_signing_key(silent)` and
pass its `AcquiredKey` to `ProviderSigningKey::new`. The `AcquiredKey` variant
identifies the provider; do not wrap a CSP handle in `NCryptKey`.

```rust
use rustls_cng::{cert::AcquiredKey, signer::ProviderSigningKey};

let acquired = context.acquire_signing_key(false)?; // UI permitted
let provider = match &acquired {
    AcquiredKey::Cng(_) => "CNG",
    AcquiredKey::LegacyCsp(_) => "CryptoAPI CSP",
};
// Log the provider name, not the PIN or private key.
println!("Signing provider: {provider}");
let key = ProviderSigningKey::new(acquired)?;
// Optional: key.set_pin(pin)?; only set a PIN if the provider supports it.
let signature = key.sign_rsa_pkcs1(&sha256_digest)?;
```

The legacy path currently supports **RSA PKCS#1 v1.5** with SHA-256, SHA-384,
or SHA-512 when the CSP supports the hash. It does not support RSA-PSS or
legacy CSP ECDSA. A successful hash capability probe does not guarantee
hardware-token signing or PIN authentication. CSP-backed RSA cannot sign the
RSA-PSS CertificateVerify required by TLS 1.3: configure TLS 1.2 only when
using `ProviderCredentials` with a legacy CSP for TLS authentication. The
provider-aware client/server configuration helpers do **not** change protocol
versions on your behalf.

For an interactive test on the affected Windows PC, obtain the QuoVadis
certificate's SHA-1 thumbprint from `certmgr.msc` and run:

```text
cargo run --example diagnose_provider -- <SHA-1 thumbprint>
```

This selects exactly one certificate from the **running account's**
`CurrentUser\My`, attempts acquisition with UI allowed, reports whether it
used CNG or a CSP, and signs a fixed test digest without logging PINs.
It is a diagnostic, not proof of a successful end-to-end T1C transaction.

`silent: false` permits Windows/provider prompts; `silent: true` suppresses
prompts during key acquisition. If acquisition fails (including a cancelled
prompt), no PIN can be set through the returned-key APIs. Test the QuoVadis
middleware under the same interactive Windows account as the caller.

This development branch changes the fork's `dev` API (rustls development
dependency). Applications pinned to an older tag must explicitly update
their dependency and adapt to its rustls API; merely pushing this branch
does not change the version used by an existing application.

## License

Licensed under the MIT or Apache licenses ([LICENSE-MIT](https://opensource.org/licenses/MIT) or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
