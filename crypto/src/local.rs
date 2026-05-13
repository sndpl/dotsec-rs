use std::io::{Read, Write};
use age::secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Generate a new age keypair. Returns (identity_string, recipient_string).
pub fn generate_keypair() -> (String, String) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    (identity.to_string().expose_secret().to_string(), recipient.to_string())
}

/// Wrap (encrypt) a DEK using an age recipient string.
pub fn wrap_dek(dek: &[u8], recipient_str: &str) -> Result<Vec<u8>, CryptoError> {
    let recipient: age::x25519::Recipient = recipient_str
        .parse()
        .map_err(|e: &str| CryptoError::AesError(format!("invalid age recipient: {}", e)))?;

    let encryptor = age::Encryptor::with_recipients(
        std::iter::once(&recipient as &dyn age::Recipient)
    )
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
        .map_err(|e: &str| CryptoError::AesError(format!("invalid age identity: {}", e)))?;

    let decryptor = age::Decryptor::new(wrapped)
        .map_err(|e| CryptoError::AesError(format!("age decryptor error: {}", e)))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| CryptoError::AesError(format!("age decrypt error: {}", e)))?;

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
        .map_err(|e: &str| CryptoError::AesError(format!("invalid age identity: {}", e)))?;
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
