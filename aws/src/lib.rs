use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use thiserror::Error;
use zeroize::Zeroizing;

// Re-export shared crypto functions so existing callers (dotsec-core) don't break
pub use crypto::{encrypt_value, decrypt_value, is_encrypted_value, pad, unpad, CryptoError};

#[derive(Error, Debug)]
pub enum DataStoreError {
    #[error("encryption failed: {0}")]
    AesError(String),
    #[error("KMS error: {0}")]
    KmsError(String),
    #[error("base64 decoding failed: {0}")]
    DecodeError(#[from] base64::DecodeError),
    #[error("invalid encrypted format")]
    InvalidFormat,
    #[error("key commitment verification failed")]
    KeyCommitmentFailed,
    #[error("SSM error: {0}")]
    SsmError(String),
    #[error("Secrets Manager error: {0}")]
    SecretsManagerError(String),
}

impl From<CryptoError> for DataStoreError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::AesError(msg) => DataStoreError::AesError(msg),
            CryptoError::DecodeError(e) => DataStoreError::DecodeError(e),
            CryptoError::InvalidFormat => DataStoreError::InvalidFormat,
            CryptoError::KeyCommitmentFailed => DataStoreError::KeyCommitmentFailed,
        }
    }
}

async fn create_kms_client(region: Option<&str>) -> aws_sdk_kms::Client {
    let region_provider = match region {
        Some(r) => RegionProviderChain::default_provider()
            .or_else(aws_config::Region::new(r.to_string())),
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_kms::Client::new(&config)
}

/// Check if a KMS key alias exists. Returns the key ARN if found.
pub async fn check_key_alias(
    alias: &str,
    region: Option<&str>,
) -> Result<Option<String>, DataStoreError> {
    let client = create_kms_client(region).await;
    match client.describe_key().key_id(alias).send().await {
        Ok(resp) => {
            let arn = resp
                .key_metadata()
                .and_then(|m| m.arn())
                .ok_or_else(|| DataStoreError::KmsError("key metadata missing ARN".into()))?
                .to_string();
            Ok(Some(arn))
        }
        Err(err) => {
            let is_not_found = err
                .as_service_error()
                .is_some_and(|e| e.is_not_found_exception());
            if is_not_found {
                Ok(None)
            } else {
                Err(DataStoreError::KmsError(err.to_string()))
            }
        }
    }
}

/// Create a new KMS key and associate an alias with it.
pub async fn create_key_with_alias(
    alias: &str,
    region: Option<&str>,
) -> Result<String, DataStoreError> {
    let client = create_kms_client(region).await;

    let key_resp = client
        .create_key()
        .description("Created by dotsec")
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(e.to_string()))?;

    let metadata = key_resp
        .key_metadata()
        .ok_or_else(|| DataStoreError::KmsError("no key metadata in response".into()))?;

    let key_id = metadata.key_id().to_string();
    let key_arn = metadata.arn().unwrap_or(&key_id).to_string();

    client
        .create_alias()
        .alias_name(alias)
        .target_key_id(&key_id)
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(e.to_string()))?;

    Ok(key_arn)
}

/// Generate a new AES-256 data encryption key via KMS.
/// Returns (plaintext_dek, wrapped_dek) where wrapped_dek is KMS-encrypted.
pub async fn generate_data_key(
    key_id: &str,
    region: Option<&str>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Box<dyn std::error::Error>> {
    let client = create_kms_client(region).await;
    let resp = client
        .generate_data_key()
        .key_id(key_id)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(e.to_string()))?;

    let plaintext = resp
        .plaintext()
        .ok_or_else(|| DataStoreError::KmsError("no plaintext in response".into()))?
        .as_ref()
        .to_vec();

    let wrapped = resp
        .ciphertext_blob()
        .ok_or_else(|| DataStoreError::KmsError("no ciphertext_blob in response".into()))?
        .as_ref()
        .to_vec();

    Ok((Zeroizing::new(plaintext), wrapped))
}

/// Unwrap a KMS-encrypted data key back to plaintext.
pub async fn unwrap_data_key(
    wrapped_dek: &[u8],
    region: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let client = create_kms_client(region).await;
    let resp = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped_dek))
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(e.to_string()))?;

    let plaintext = resp
        .plaintext()
        .ok_or_else(|| DataStoreError::KmsError("no plaintext in decrypt response".into()))?
        .as_ref()
        .to_vec();

    Ok(Zeroizing::new(plaintext))
}

// --- Push to AWS services ---

async fn create_ssm_client(region: Option<&str>) -> aws_sdk_ssm::Client {
    let region_provider = match region {
        Some(r) => RegionProviderChain::default_provider()
            .or_else(aws_config::Region::new(r.to_string())),
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_ssm::Client::new(&config)
}

async fn create_secrets_manager_client(
    region: Option<&str>,
) -> aws_sdk_secretsmanager::Client {
    let region_provider = match region {
        Some(r) => RegionProviderChain::default_provider()
            .or_else(aws_config::Region::new(r.to_string())),
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_secretsmanager::Client::new(&config)
}

/// Push a value to AWS SSM Parameter Store.
pub async fn push_to_ssm(
    name: &str,
    value: &str,
    secure: bool,
    region: Option<&str>,
) -> Result<(), DataStoreError> {
    let client = create_ssm_client(region).await;
    let param_type = if secure {
        aws_sdk_ssm::types::ParameterType::SecureString
    } else {
        aws_sdk_ssm::types::ParameterType::String
    };

    client
        .put_parameter()
        .name(name)
        .value(value)
        .r#type(param_type)
        .overwrite(true)
        .send()
        .await
        .map_err(|e| DataStoreError::SsmError(e.to_string()))?;

    Ok(())
}

/// Push a value to AWS Secrets Manager.
pub async fn push_to_secrets_manager(
    name: &str,
    value: &str,
    region: Option<&str>,
) -> Result<(), DataStoreError> {
    let client = create_secrets_manager_client(region).await;

    let result = client
        .put_secret_value()
        .secret_id(name)
        .secret_string(value)
        .send()
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            let is_not_found = err
                .as_service_error()
                .is_some_and(|e| e.is_resource_not_found_exception());

            if is_not_found {
                client
                    .create_secret()
                    .name(name)
                    .secret_string(value)
                    .send()
                    .await
                    .map_err(|e| DataStoreError::SecretsManagerError(e.to_string()))?;
                Ok(())
            } else {
                Err(DataStoreError::SecretsManagerError(err.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dek = [0x42u8; 32];
        let plaintext = "hello world secret";
        let aad = "API_KEY";
        let encrypted = encrypt_value(plaintext, &dek, aad).unwrap();
        assert!(encrypted.starts_with("ENC["));
        assert!(encrypted.ends_with(']'));
        let decrypted = decrypt_value(&encrypted, &dek, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let dek = [0x42u8; 32];
        let plaintext = "same input";
        let a = encrypt_value(plaintext, &dek, "KEY").unwrap();
        let b = encrypt_value(plaintext, &dek, "KEY").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_wrong_aad_fails() {
        let dek = [0x42u8; 32];
        let encrypted = encrypt_value("secret", &dek, "API_KEY").unwrap();
        assert!(decrypt_value(&encrypted, &dek, "DB_PASSWORD").is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails_commitment() {
        let dek1 = [0x42u8; 32];
        let dek2 = [0x43u8; 32];
        let encrypted = encrypt_value("secret", &dek1, "KEY").unwrap();
        let err = decrypt_value(&encrypted, &dek2, "KEY").unwrap_err();
        assert!(matches!(err, CryptoError::KeyCommitmentFailed));
    }

    #[test]
    fn decrypt_invalid_format() {
        let dek = [0x42u8; 32];
        assert!(decrypt_value("not encrypted", &dek, "").is_err());
        assert!(decrypt_value("ENC[]", &dek, "").is_err());
        assert!(decrypt_value("ENC[dG9vc2hvcnQ=]", &dek, "").is_err());
    }

    #[test]
    fn is_encrypted_value_checks() {
        assert!(is_encrypted_value("ENC[abc123]"));
        assert!(!is_encrypted_value("plaintext"));
        assert!(!is_encrypted_value("ENC[no closing"));
        assert!(!is_encrypted_value("prefix ENC[abc]"));
    }

    #[test]
    fn encrypt_empty_string() {
        let dek = [0x42u8; 32];
        let encrypted = encrypt_value("", &dek, "EMPTY").unwrap();
        let decrypted = decrypt_value(&encrypted, &dek, "EMPTY").unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn encrypt_unicode() {
        let dek = [0x42u8; 32];
        let plaintext = "héllo wörld 🔑";
        let encrypted = encrypt_value(plaintext, &dek, "UNI").unwrap();
        let decrypted = decrypt_value(&encrypted, &dek, "UNI").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn key_commitment_deterministic() {
        let dek = [0x42u8; 32];
        let a = crypto::compute_key_commitment(&dek);
        let b = crypto::compute_key_commitment(&dek);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn key_commitment_differs_per_key() {
        let a = crypto::compute_key_commitment(&[0x42u8; 32]);
        let b = crypto::compute_key_commitment(&[0x43u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn pad_rejects_oversized_input() {
        let data = vec![0u8; 65536];
        let result = pad(&data);
        assert!(result.is_err(), "pad should reject data larger than u16::MAX bytes");
    }

    #[test]
    fn pad_accepts_max_size() {
        let data = vec![0u8; 65535];
        let result = pad(&data);
        assert!(result.is_ok(), "pad should accept data of exactly u16::MAX bytes");
    }
}
