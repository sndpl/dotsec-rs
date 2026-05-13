/// Internal encryption engine used for dispatch.
#[derive(Clone, Debug, Default)]
pub enum EncryptionEngine {
    Aws(AwsEncryptionOptions),
    Local(LocalEncryptionOptions),
    #[default]
    None,
}

#[derive(Clone, Default)]
pub struct AwsEncryptionOptions {
    pub key_id: Option<String>,
    pub region: Option<String>,
}

impl std::fmt::Debug for AwsEncryptionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsEncryptionOptions")
            .field("key_id", &self.key_id.as_ref().map(|_| "[REDACTED]"))
            .field("region", &self.region)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LocalEncryptionOptions {
    pub key_file: Option<String>,
}

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
