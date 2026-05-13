# Local Encryption Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `@provider=local` encryption mode using age (X25519 + ChaCha20-Poly1305) for DEK wrapping, so users can encrypt `.sec` files without AWS.

**Architecture:** Extract shared crypto (AES-256-GCM value encrypt/decrypt) from the `aws` crate into a new `crypto` crate. Add age-based DEK wrapping to `crypto`. Update `dotsec-core` to dispatch encrypt/decrypt based on `EncryptionEngine::Local` vs `::Aws`. Update `init` to support local provider selection.

**Tech Stack:** Rust, `age` crate (X25519 + ChaCha20-Poly1305), `aes-gcm` (existing), `zeroize`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `crypto/Cargo.toml` | Create | New crate for shared crypto + local key wrapping |
| `crypto/src/lib.rs` | Create | Shared value encrypt/decrypt, pad/unpad, key commitment |
| `crypto/src/local.rs` | Create | age keypair generation, DEK wrap/unwrap, key discovery |
| `aws/Cargo.toml` | Modify | Add dependency on `crypto` |
| `aws/src/lib.rs` | Modify | Remove shared crypto functions, re-export from `crypto` |
| `Cargo.toml` | Modify | Add `crypto` to workspace members |
| `dotsec-core/Cargo.toml` | Modify | Add dependency on `crypto` |
| `dotsec-core/src/configuration.rs` | Modify | Add `Local` variant + `LocalEncryptionOptions` |
| `dotsec-core/src/lib.rs` | Modify | Dispatch encrypt/decrypt for local provider |
| `dotsec/src/cli/helpers.rs` | Modify | Update `prompt_config` for local provider |
| `dotsec/src/cli/commands/init.rs` | Modify | Generate keypair when local selected |

---

### Task 1: Create `crypto` crate with shared functions

**Files:**
- Create: `crypto/Cargo.toml`
- Create: `crypto/src/lib.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Create `crypto/Cargo.toml`**

```toml
[package]
name = "crypto"
version = "5.0.0"
edition = "2021"
description = "Shared cryptographic functions for dotsec"
license = "MIT"

[dependencies]
aes-gcm = "0.10.3"
base64 = { workspace = true }
hmac = "0.12"
rand = "0.8"
sha2 = "0.10"
subtle = "2"
thiserror = { workspace = true }
zeroize = "1.8"
```

- [ ] **Step 2: Create `crypto/src/lib.rs` with shared functions extracted from `aws/src/lib.rs`**

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    AeadCore, Aes256Gcm,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub mod local;

type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    AesError(String),
    #[error("base64 decoding failed: {0}")]
    DecodeError(#[from] base64::DecodeError),
    #[error("invalid encrypted format")]
    InvalidFormat,
    #[error("key commitment verification failed")]
    KeyCommitmentFailed,
}

/// Compute a 32-byte key commitment: HMAC-SHA256(key=DEK, msg="dotsec-key-commit").
fn compute_key_commitment(dek: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(dek).expect("HMAC accepts any key length");
    mac.update(b"dotsec-key-commit");
    mac.finalize().into_bytes().to_vec()
}

/// Verify key commitment matches the DEK (constant-time comparison).
fn verify_key_commitment(dek: &[u8], commitment: &[u8]) -> Result<(), CryptoError> {
    let expected = compute_key_commitment(dek);
    if expected.len() != commitment.len() || expected.ct_eq(commitment).unwrap_u8() != 1 {
        return Err(CryptoError::KeyCommitmentFailed);
    }
    Ok(())
}

/// Pad plaintext with random bytes so ciphertext length doesn't leak value length.
/// Wire format: `[2-byte big-endian original length] [original data] [random padding]`
pub fn pad(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use rand::RngCore;

    if data.len() > u16::MAX as usize {
        return Err(CryptoError::AesError(format!(
            "value too large to pad: {} bytes exceeds maximum of {} bytes",
            data.len(),
            u16::MAX
        )));
    }

    let header_len = 2;
    let total = header_len + data.len();
    let base_padded = total.div_ceil(64) * 64;
    let extra_blocks = (OsRng.next_u32() % 2) as usize;
    let padded_len = base_padded + (extra_blocks * 64);

    let mut buf = vec![0u8; padded_len];
    OsRng.fill_bytes(&mut buf);
    let len = data.len() as u16;
    buf[0..2].copy_from_slice(&len.to_be_bytes());
    buf[2..2 + data.len()].copy_from_slice(data);
    Ok(buf)
}

/// Remove padding and return the original plaintext bytes.
pub fn unpad(data: &[u8]) -> Result<&[u8], CryptoError> {
    if data.len() < 2 {
        return Err(CryptoError::InvalidFormat);
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + len > data.len() {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(&data[2..2 + len])
}

/// Encrypt a single value with AES-256-GCM using the given DEK.
/// Format: `ENC[base64(commitment || nonce || ciphertext || tag)]`
pub fn encrypt_value(plaintext: &str, dek: &[u8], aad: &str) -> Result<String, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| CryptoError::AesError(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut padded = pad(plaintext.as_bytes())?;
    let commitment = compute_key_commitment(dek);

    let payload = Payload {
        msg: &padded,
        aad: aad.as_bytes(),
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| CryptoError::AesError(e.to_string()))?;

    padded.zeroize();

    let mut blob = Vec::with_capacity(32 + 12 + ciphertext.len());
    blob.extend_from_slice(&commitment);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(format!("ENC[{}]", STANDARD.encode(&blob)))
}

/// Decrypt a value in `ENC[base64(...)]` format using the given DEK.
pub fn decrypt_value(enc_str: &str, dek: &[u8], aad: &str) -> Result<String, CryptoError> {
    let inner = enc_str
        .strip_prefix("ENC[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(CryptoError::InvalidFormat)?;

    let blob = STANDARD.decode(inner)?;
    if blob.len() < 32 + 12 + 16 {
        return Err(CryptoError::InvalidFormat);
    }

    let (commitment, rest) = blob.split_at(32);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    verify_key_commitment(dek, commitment)?;

    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| CryptoError::AesError(e.to_string()))?;

    let payload = Payload {
        msg: ciphertext,
        aad: aad.as_bytes(),
    };
    let mut decrypted = cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::AesError(e.to_string()))?;

    let plaintext = unpad(&decrypted)?.to_vec();
    decrypted.zeroize();

    String::from_utf8(plaintext).map_err(|e| CryptoError::AesError(e.to_string()))
}

/// Check if a value is in the `ENC[...]` envelope format.
pub fn is_encrypted_value(value: &str) -> bool {
    value.starts_with("ENC[") && value.ends_with(']')
}

/// Generate a random 32-byte AES-256 data encryption key.
pub fn generate_dek() -> Zeroizing<Vec<u8>> {
    use rand::RngCore;
    let mut dek = vec![0u8; 32];
    OsRng.fill_bytes(&mut dek);
    Zeroizing::new(dek)
}
```

- [ ] **Step 3: Add `crypto` to workspace**

In `Cargo.toml` (workspace root), add `"crypto"` to the members list:

```toml
members = ["dotsec", "dotsec-core", "aws", "dotenv", "dotsec-napi", "crypto"]
```

- [ ] **Step 4: Build to verify**

Run: `cargo build -p crypto`
Expected: compiles successfully

- [ ] **Step 5: Commit**

```bash
git add crypto/ Cargo.toml
git commit -m "feat: create crypto crate with shared value encryption"
```

---

### Task 2: Add age-based local key wrapping to `crypto`

**Files:**
- Create: `crypto/src/local.rs`
- Modify: `crypto/Cargo.toml`

- [ ] **Step 1: Add age dependency to `crypto/Cargo.toml`**

Add to `[dependencies]`:

```toml
age = { version = "0.11", features = ["armor"] }
```

- [ ] **Step 2: Write tests for local key operations in `crypto/src/local.rs`**

```rust
use std::io::{Read, Write};
use age::secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Generate a new age keypair. Returns (identity_string, recipient_string).
pub fn generate_keypair() -> (String, String) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    (identity.to_string().expose_secret().clone(), recipient.to_string())
}

/// Wrap (encrypt) a DEK using an age recipient string.
pub fn wrap_dek(dek: &[u8], recipient_str: &str) -> Result<Vec<u8>, CryptoError> {
    let recipient: age::x25519::Recipient = recipient_str
        .parse()
        .map_err(|e| CryptoError::AesError(format!("invalid age recipient: {}", e)))?;

    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
        .map_err(|e| CryptoError::AesError(format!("age encryptor error: {}", e)))?;

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CryptoError::AesError(format!("age wrap error: {}", e)))?;
    writer
        .write_all(dek)
        .map_err(|e| CryptoError::AesError(format!("age write error: {}", e)))?;
    writer
        .finish()
        .map_err(|e| CryptoError::AesError(format!("age finish error: {}", e)))?;

    Ok(encrypted)
}

/// Unwrap (decrypt) a DEK using an age identity string.
pub fn unwrap_dek(wrapped: &[u8], identity_str: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let identity: age::x25519::Identity = identity_str
        .parse()
        .map_err(|e| CryptoError::AesError(format!("invalid age identity: {}", e)))?;

    let decryptor = age::Decryptor::new(wrapped)
        .map_err(|e| CryptoError::AesError(format!("age decryptor error: {}", e)))?;

    let mut reader = match decryptor {
        age::Decryptor::Recipients(d) => d
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| CryptoError::AesError(format!("age decrypt error: {}", e)))?,
        _ => return Err(CryptoError::AesError("unexpected age format".into())),
    };

    let mut dek = vec![];
    reader
        .read_to_end(&mut dek)
        .map_err(|e| CryptoError::AesError(format!("age read error: {}", e)))?;

    Ok(Zeroizing::new(dek))
}

/// Derive the age recipient (public key) from an identity (private key) string.
pub fn recipient_from_identity(identity_str: &str) -> Result<String, CryptoError> {
    let identity: age::x25519::Identity = identity_str
        .parse()
        .map_err(|e| CryptoError::AesError(format!("invalid age identity: {}", e)))?;
    Ok(identity.to_public().to_string())
}

/// Discover the key file for a given sec file. Returns `<sec_file>.key` if it exists.
pub fn discover_key_file(sec_file: &str) -> Option<String> {
    let key_path = format!("{}.key", sec_file);
    if std::path::Path::new(&key_path).exists() {
        Some(key_path)
    } else {
        None
    }
}

/// Load the private key from DOTSEC_PRIVATE_KEY env var or <sec_file>.key file.
pub fn load_private_key(sec_file: &str, key_file_override: Option<&str>) -> Result<Zeroizing<String>, CryptoError> {
    // 1. Check env var
    if let Ok(key) = std::env::var("DOTSEC_PRIVATE_KEY") {
        return Ok(Zeroizing::new(key));
    }

    // 2. Check key file
    let key_path = match key_file_override {
        Some(p) => p.to_string(),
        None => format!("{}.key", sec_file),
    };

    let content = std::fs::read_to_string(&key_path)
        .map_err(|_| CryptoError::AesError(format!(
            "private key not found — set DOTSEC_PRIVATE_KEY or create {}",
            key_path
        )))?;

    let key = content.lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .ok_or_else(|| CryptoError::AesError(format!(
            "{} does not contain a valid age identity (expected AGE-SECRET-KEY-...)",
            key_path
        )))?
        .trim()
        .to_string();

    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_identity() {
        let (identity, recipient) = generate_keypair();
        assert!(identity.starts_with("AGE-SECRET-KEY-"));
        assert!(recipient.starts_with("age1"));
    }

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        let (identity, recipient) = generate_keypair();
        let dek = vec![42u8; 32];

        let wrapped = wrap_dek(&dek, &recipient).unwrap();
        let unwrapped = unwrap_dek(&wrapped, &identity).unwrap();

        assert_eq!(&*unwrapped, &dek);
    }

    #[test]
    fn unwrap_with_wrong_identity_fails() {
        let (_, recipient) = generate_keypair();
        let (wrong_identity, _) = generate_keypair();
        let dek = vec![42u8; 32];

        let wrapped = wrap_dek(&dek, &recipient).unwrap();
        let result = unwrap_dek(&wrapped, &wrong_identity);

        assert!(result.is_err());
    }

    #[test]
    fn recipient_from_identity_roundtrip() {
        let (identity, recipient) = generate_keypair();
        let derived = recipient_from_identity(&identity).unwrap();
        assert_eq!(derived, recipient);
    }

    #[test]
    fn discover_key_file_not_found() {
        assert!(discover_key_file("/nonexistent/path/.sec").is_none());
    }

    #[test]
    fn load_private_key_from_file() {
        let dir = std::env::temp_dir().join("dotsec-test-local-key");
        let _ = std::fs::create_dir_all(&dir);
        let sec_path = dir.join("test.sec");
        let key_path = dir.join("test.sec.key");

        let (identity, _) = generate_keypair();
        std::fs::write(&key_path, &identity).unwrap();

        let loaded = load_private_key(sec_path.to_str().unwrap(), None).unwrap();
        assert_eq!(&*loaded, &identity);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_private_key_missing_gives_helpful_error() {
        let result = load_private_key("/nonexistent/.sec", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DOTSEC_PRIVATE_KEY"), "error should mention env var: {}", err);
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p crypto`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add crypto/
git commit -m "feat: add age-based local key wrapping to crypto crate"
```

---

### Task 3: Migrate `aws` crate to use `crypto` for shared functions

**Files:**
- Modify: `aws/Cargo.toml`
- Modify: `aws/src/lib.rs`

- [ ] **Step 1: Add `crypto` dependency to `aws/Cargo.toml`**

Add to `[dependencies]`:

```toml
crypto = { path = "../crypto" }
```

Remove from `[dependencies]` (now provided by `crypto`):

```toml
# Remove these — they come from crypto now:
# aes-gcm = "0.10.3"
# hmac = "0.12"
# sha2 = "0.10"
# subtle = "2"
```

Keep: `aws-config`, `aws-sdk-kms`, `aws-sdk-ssm`, `aws-sdk-secretsmanager`, `base64`, `rand`, `thiserror`, `zeroize`.

- [ ] **Step 2: Replace shared crypto functions in `aws/src/lib.rs`**

Remove the following functions and types from `aws/src/lib.rs` (they now live in `crypto`):
- `compute_key_commitment`
- `verify_key_commitment`
- `pad`
- `unpad`
- `encrypt_value`
- `decrypt_value`
- `is_encrypted_value`
- The `HmacSha256` type alias
- The imports for `aes_gcm`, `hmac`, `sha2`, `subtle`

Replace the removed `DataStoreError` variants that overlap with `CryptoError`:
- Keep `KmsError`, `SsmError`, `SecretsManagerError` in `DataStoreError`
- Re-export `CryptoError` from `crypto` and convert where needed

Add re-exports at the top of `aws/src/lib.rs`:

```rust
pub use crypto::{encrypt_value, decrypt_value, is_encrypted_value, CryptoError};
```

Update the remaining imports to remove `aes_gcm`, `hmac`, `sha2`, `subtle`.

- [ ] **Step 3: Build and run existing tests**

Run: `cargo test -p aws`
Expected: all 12 existing tests pass (they now use re-exported functions from `crypto`)

Run: `cargo test --workspace`
Expected: all tests pass (dotsec-core still uses `aws::encrypt_value` etc. via re-exports)

- [ ] **Step 4: Commit**

```bash
git add aws/
git commit -m "refactor: migrate aws crate to use crypto for shared functions"
```

---

### Task 4: Add `EncryptionEngine::Local` variant

**Files:**
- Modify: `dotsec-core/src/configuration.rs`
- Modify: `dotsec-core/Cargo.toml`

- [ ] **Step 1: Add `crypto` dependency to `dotsec-core/Cargo.toml`**

Add to `[dependencies]`:

```toml
crypto = { path = "../crypto" }
```

- [ ] **Step 2: Add `Local` variant and `LocalEncryptionOptions`**

In `dotsec-core/src/configuration.rs`, add the new variant and struct:

```rust
/// Internal encryption engine used for dispatch.
#[derive(Clone, Debug, Default)]
pub enum EncryptionEngine {
    Aws(AwsEncryptionOptions),
    Local(LocalEncryptionOptions),
    #[default]
    None,
}

#[derive(Clone, Debug, Default)]
pub struct LocalEncryptionOptions {
    pub key_file: Option<String>,
}
```

Update `TryFrom<FileConfig>`:

```rust
impl TryFrom<dotenv::FileConfig> for EncryptionEngine {
    type Error = String;

    fn try_from(config: dotenv::FileConfig) -> Result<Self, Self::Error> {
        match config.provider.as_deref() {
            Some("aws") => Ok(EncryptionEngine::Aws(AwsEncryptionOptions {
                key_id: config.key_id,
                region: config.region,
            })),
            Some("local") => Ok(EncryptionEngine::Local(LocalEncryptionOptions {
                key_file: config.key_id,
            })),
            Some(unknown) => Err(format!(
                "unknown encryption provider '{}', expected 'aws' or 'local'",
                unknown
            )),
            None => Ok(EncryptionEngine::None),
        }
    }
}
```

- [ ] **Step 3: Build**

Run: `cargo build --workspace`
Expected: compile errors in `dotsec-core/src/lib.rs` — the match arms in `encrypt_lines_to_sec` and `decrypt_v2` don't handle `Local` yet. This is expected; we fix it in Task 5.

- [ ] **Step 4: Commit**

```bash
git add dotsec-core/
git commit -m "feat: add EncryptionEngine::Local variant and LocalEncryptionOptions"
```

---

### Task 5: Wire up local encrypt/decrypt in dotsec-core

**Files:**
- Modify: `dotsec-core/src/lib.rs`

This is the core integration. The `encrypt_lines_to_sec` and `decrypt_v2` functions need to dispatch on the engine variant.

- [ ] **Step 1: Update `encrypt_lines_to_sec` to handle `Local`**

Replace the current match on `encryption_engine` (lines 100-106) and DEK loading:

```rust
pub async fn encrypt_lines_to_sec(
    lines: &[Line],
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = lines_to_entries(lines);

    let (dek, wrapped_dek) = match encryption_engine {
        EncryptionEngine::Aws(opts) => {
            let key_id = opts.key_id.as_deref().ok_or("AWS key_id is required")?;
            let region = opts.region.as_deref();
            match load_existing_dek_aws(sec_file, region).await {
                Ok(pair) => pair,
                Err(e) => {
                    let is_new_file = e.downcast_ref::<std::io::Error>()
                        .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound);
                    let is_no_key = e.to_string().contains("No __DOTSEC_KEY__ found");
                    if is_new_file || is_no_key {
                        let (plaintext, wrapped) = aws::generate_data_key(key_id, region).await?;
                        (plaintext, wrapped)
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        EncryptionEngine::Local(opts) => {
            let private_key = crypto::local::load_private_key(sec_file, opts.key_file.as_deref())?;
            let recipient = crypto::local::recipient_from_identity(&private_key)?;
            match load_existing_dek_local(sec_file, &private_key) {
                Ok(pair) => pair,
                Err(e) => {
                    let is_new_file = e.downcast_ref::<std::io::Error>()
                        .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound);
                    let is_no_key = e.to_string().contains("No __DOTSEC_KEY__ found");
                    if is_new_file || is_no_key {
                        let dek = crypto::generate_dek();
                        let wrapped = crypto::local::wrap_dek(&dek, &recipient)?;
                        (dek, wrapped)
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        EncryptionEngine::None => return Err("Encryption engine is required".into()),
    };

    encrypt_with_dek(lines, &entries, &dek, &wrapped_dek, sec_file)
}
```

- [ ] **Step 2: Rename `load_existing_dek` to `load_existing_dek_aws` and add `load_existing_dek_local`**

Rename existing function:

```rust
async fn load_existing_dek_aws(
    sec_file: &str,
    region: Option<&str>,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>), Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let wrapped_b64 = dotenv::get_value(&lines, DOTSEC_KEY_NAME)
        .ok_or("No __DOTSEC_KEY__ found")?;
    let wrapped_dek = base64::engine::general_purpose::STANDARD.decode(&wrapped_b64)?;
    let dek = aws::unwrap_data_key(&wrapped_dek, region).await?;
    Ok((dek, wrapped_dek))
}
```

Add new function:

```rust
fn load_existing_dek_local(
    sec_file: &str,
    identity: &str,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>), Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let wrapped_b64 = dotenv::get_value(&lines, DOTSEC_KEY_NAME)
        .ok_or("No __DOTSEC_KEY__ found")?;
    let wrapped_dek = base64::engine::general_purpose::STANDARD.decode(&wrapped_b64)?;
    let dek = crypto::local::unwrap_dek(&wrapped_dek, identity)?;
    Ok((dek, wrapped_dek))
}
```

- [ ] **Step 3: Update `decrypt_v2` to handle `Local`**

```rust
async fn decrypt_v2(
    lines: &[Line],
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let wrapped_dek_b64 = dotenv::get_value(lines, DOTSEC_KEY_NAME)
        .ok_or("No __DOTSEC_KEY__ found in .sec file")?;
    let wrapped_dek = base64::engine::general_purpose::STANDARD.decode(&wrapped_dek_b64)?;

    let dek = match encryption_engine {
        EncryptionEngine::Aws(opts) => {
            aws::unwrap_data_key(&wrapped_dek, opts.region.as_deref()).await?
        }
        EncryptionEngine::Local(opts) => {
            let sec_file_hint = ""; // not needed for env var discovery
            let private_key = crypto::local::load_private_key(sec_file_hint, opts.key_file.as_deref())?;
            crypto::local::unwrap_dek(&wrapped_dek, &private_key)?
        }
        EncryptionEngine::None => return Err("Encryption engine is required".into()),
    };

    let mut resolved: Vec<Line> = Vec::new();

    for line in lines {
        match line {
            Line::Kv { key, value, quote_type } => {
                if key == DOTSEC_KEY_NAME {
                    continue;
                }
                if crypto::is_encrypted_value(value) {
                    let plaintext = crypto::decrypt_value(value, &dek, key)?;
                    resolved.push(Line::Kv { key: key.clone(), value: plaintext, quote_type: quote_type.clone() });
                } else {
                    resolved.push(line.clone());
                }
            }
            Line::Comment { text }
                if text.contains("do not edit the line below, it is managed by dotsec") =>
            {
                continue;
            }
            _ => resolved.push(line.clone()),
        }
    }

    Ok(resolved)
}
```

- [ ] **Step 4: Update `encrypt_with_dek` to use `crypto::` instead of `aws::`**

Replace `aws::is_encrypted_value` with `crypto::is_encrypted_value` and `aws::encrypt_value` with `crypto::encrypt_value` in `encrypt_with_dek`.

- [ ] **Step 5: Update `decrypt_sec_to_lines` to use `crypto::is_encrypted_value`**

In the `SecFormat::None` branch, replace `aws::is_encrypted_value` with `crypto::is_encrypted_value`.

- [ ] **Step 6: Build and test**

Run: `cargo build --workspace`
Expected: compiles

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 7: Commit**

```bash
git add dotsec-core/
git commit -m "feat: wire up local encrypt/decrypt dispatch in dotsec-core"
```

---

### Task 6: Update `dotsec init` for local provider

**Files:**
- Modify: `dotsec/src/cli/helpers.rs`
- Modify: `dotsec/src/cli/commands/init.rs`
- Modify: `dotsec/Cargo.toml`

- [ ] **Step 1: Add `crypto` dependency to `dotsec/Cargo.toml`**

Add to `[dependencies]`:

```toml
crypto = { path = "../crypto" }
```

- [ ] **Step 2: Update `prompt_config` in `helpers.rs`**

```rust
pub fn prompt_config() -> Result<dotenv::FileConfig, Box<dyn std::error::Error>> {
    let provider = Select::new("Encryption provider?", vec!["local", "aws"]).prompt()?;

    match provider {
        "local" => {
            Ok(dotenv::FileConfig {
                provider: Some("local".to_string()),
                key_id: None,
                region: None,
                default_encrypt: None,
            })
        }
        "aws" => {
            let key_id = Text::new("KMS key ID?")
                .with_default("alias/dotsec")
                .prompt()?;
            let default_region = std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .unwrap_or_else(|_| "us-east-1".to_string());
            let region = Text::new("AWS region?")
                .with_default(&default_region)
                .prompt()?;

            Ok(dotenv::FileConfig {
                provider: Some("aws".to_string()),
                key_id: Some(key_id),
                region: Some(region),
                default_encrypt: None,
            })
        }
        _ => unreachable!(),
    }
}
```

- [ ] **Step 3: Update `init.rs` to generate keypair for local provider**

After the config prompt and before writing the `.sec` file, add keypair generation:

```rust
    // Generate keypair for local provider
    if config.provider.as_deref() == Some("local") {
        let key_file = format!("{}.key", sec_file);
        if std::path::Path::new(&key_file).exists() {
            println!("{} {} already exists, reusing existing keypair", "✓".green(), key_file);
        } else {
            let (identity, _recipient) = crypto::local::generate_keypair();
            dotsec::write_sec_file(&key_file, &format!("{}\n", identity))?;
            println!("{} Created {}", "✓".green(), key_file);

            // Check .gitignore
            let gitignore_path = std::path::Path::new(sec_file)
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join(".gitignore");
            let has_key_pattern = std::fs::read_to_string(&gitignore_path)
                .map(|c| c.lines().any(|l| l.trim() == "*.key" || l.trim() == ".sec.key" || l.contains(".key")))
                .unwrap_or(false);
            if !has_key_pattern {
                eprintln!("{} Add {} to .gitignore to avoid committing private keys", "⚠".yellow().bold(), "*.key");
            }
        }
    }
```

- [ ] **Step 4: Build and verify**

Run: `cargo build -p dotsec`
Expected: compiles

Run: `cargo run -p dotsec -- init --help`
Expected: shows help

- [ ] **Step 5: Commit**

```bash
git add dotsec/
git commit -m "feat: support local provider in dotsec init with age keypair generation"
```

---

### Task 7: Integration tests

**Files:**
- Modify: `dotsec-core/src/lib.rs` (test section)

- [ ] **Step 1: Add local encryption roundtrip test**

Add to the test module in `dotsec-core/src/lib.rs`:

```rust
    #[tokio::test]
    async fn local_encrypt_decrypt_roundtrip() {
        let dir = std::env::temp_dir().join("dotsec-test-local-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();

        // Generate keypair
        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        // Build lines with encrypted value
        let lines = vec![
            Line::Directive { name: "provider".to_string(), value: Some("local".to_string()) },
            Line::Newline,
            Line::Directive { name: "encrypt".to_string(), value: None },
            Line::Newline,
            Line::Kv { key: "SECRET".into(), value: "hunter2".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "PUBLIC".into(), value: "hello".into(), quote_type: QuoteType::None },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file.clone()),
        });

        // Encrypt
        encrypt_lines_to_sec(&lines, &sec_file, &engine).await.unwrap();

        // Verify encrypted file contains ENC[...] and __DOTSEC_KEY__
        let content = std::fs::read_to_string(&sec_file).unwrap();
        assert!(content.contains("ENC["), "encrypted value should contain ENC[...]");
        assert!(content.contains("__DOTSEC_KEY__"), "should contain wrapped DEK");
        assert!(!content.contains("hunter2"), "plaintext should not appear");

        // Decrypt
        let decrypted = decrypt_sec_to_lines(&sec_file, &engine).await.unwrap();
        let secret_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l { if key == "SECRET" { Some(value.clone()) } else { None } } else { None }
        });
        assert_eq!(secret_val.as_deref(), Some("hunter2"));

        let public_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l { if key == "PUBLIC" { Some(value.clone()) } else { None } } else { None }
        });
        assert_eq!(public_val.as_deref(), Some("hello"));

        let _ = std::fs::remove_dir_all(&dir);
    }
```

- [ ] **Step 2: Add test for wrong key fails**

```rust
    #[tokio::test]
    async fn local_decrypt_with_wrong_key_fails() {
        let dir = std::env::temp_dir().join("dotsec-test-local-wrong-key");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let wrong_key_file = dir.join("wrong.sec.key").to_string_lossy().to_string();

        // Generate two keypairs
        let (identity, _) = crypto::local::generate_keypair();
        let (wrong_identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();
        std::fs::write(&wrong_key_file, &wrong_identity).unwrap();

        let lines = vec![
            Line::Directive { name: "encrypt".to_string(), value: None },
            Line::Newline,
            Line::Kv { key: "SECRET".into(), value: "hunter2".into(), quote_type: QuoteType::Double },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });

        encrypt_lines_to_sec(&lines, &sec_file, &engine).await.unwrap();

        // Try decrypting with wrong key
        let wrong_engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(wrong_key_file),
        });
        let result = decrypt_sec_to_lines(&sec_file, &wrong_engine).await;
        assert!(result.is_err(), "decrypting with wrong key should fail");

        let _ = std::fs::remove_dir_all(&dir);
    }
```

- [ ] **Step 3: Run all tests**

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add dotsec-core/src/lib.rs
git commit -m "test: local encryption roundtrip and wrong-key tests"
```

---

### Task 8: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Verify CLI**

Run: `cargo run -p dotsec -- --help`
Expected: shows all commands including `extract-schema`, `header`

- [ ] **Step 4: Push**

```bash
git push -u origin feat/local-encryption
```
