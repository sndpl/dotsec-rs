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
pub fn compute_key_commitment(dek: &[u8]) -> Vec<u8> {
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
