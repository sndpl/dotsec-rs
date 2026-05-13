pub use dotenv;
use base64::Engine as _;
use dotenv::{lines_to_entries, Line};

mod configuration;
pub use configuration::*;

// --- File helpers ---

pub fn load_file(file: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(file)
}

/// Write content to a .sec or schema file with restricted permissions (0600 on Unix).
pub fn write_sec_file(path: &str, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .mode(0o600)
            .open(path)?
            .write_all(content.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
    }
    Ok(())
}

// --- Header ---

/// Generate the standard dotsec file header (two comment lines + newlines).
pub fn generate_header() -> Vec<Line> {
    vec![
        Line::Comment { text: "# dotsec v5 — encrypted environment file".into() },
        Line::Newline,
        Line::Comment { text: "# https://github.com/jpwesselink/dotsec-rs".into() },
        Line::Newline,
    ]
}

/// Check whether parsed lines contain the dotsec header.
pub fn has_header(lines: &[Line]) -> bool {
    lines.iter().any(|line| {
        matches!(line, Line::Comment { text } if text.starts_with("# dotsec v"))
    })
}

pub fn parse_content(content: &str) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    Ok(dotenv::parse_dotenv(content)?)
}

// --- Constants ---

const DOTSEC_KEY_NAME: &str = "__DOTSEC_KEY__";
const DOTSEC_V1_NAME: &str = "__DOTSEC__";

// --- Format detection ---

/// Detect whether a .sec file uses v1 (blob) or v2 (per-value) format.
fn detect_format(lines: &[Line]) -> SecFormat {
    for line in lines {
        if let Line::Kv { key, .. } = line {
            if key == DOTSEC_KEY_NAME {
                return SecFormat::V2;
            }
            if key == DOTSEC_V1_NAME {
                return SecFormat::V1;
            }
        }
    }
    SecFormat::None
}

#[derive(Debug, PartialEq)]
enum SecFormat {
    V1,   // Old blob format with __DOTSEC__
    V2,   // New per-value format with __DOTSEC_KEY__
    None, // No encryption markers
}

// --- Encrypt (v2) ---

/// Encrypt in-memory lines and write the result to a .sec file.
///
/// For each entry with `@encrypt`:
///   - Encrypt the value with the DEK → `ENC[base64(commitment||nonce||ciphertext||tag)]`
///
/// The DEK is wrapped by KMS and stored as `__DOTSEC_KEY__="base64(wrapped_dek)"`.
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
                    let is_new = is_new_or_no_key(&e);
                    if is_new {
                        aws::generate_data_key(key_id, region).await?
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
                    let is_new = is_new_or_no_key(&e);
                    if is_new {
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

#[allow(clippy::borrowed_box)]
fn is_new_or_no_key(e: &Box<dyn std::error::Error>) -> bool {
    let is_new_file = e.downcast_ref::<std::io::Error>()
        .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound);
    let is_no_key = e.to_string().contains("No __DOTSEC_KEY__ found");
    is_new_file || is_no_key
}

/// Inner encryption logic, separated so the caller can zeroize the DEK.
fn encrypt_with_dek(
    lines: &[Line],
    entries: &[dotenv::Entry],
    dek: &[u8],
    wrapped_dek: &[u8],
    sec_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped_dek_b64 = base64::engine::general_purpose::STANDARD.encode(wrapped_dek);

    let mut sec_lines: Vec<Line> = Vec::new();
    let mut has_key_line = false;

    for line in lines {
        match line {
            Line::Kv { key, value, quote_type } => {
                if key == DOTSEC_KEY_NAME {
                    sec_lines.push(Line::Kv {
                        key: DOTSEC_KEY_NAME.to_string(),
                        value: wrapped_dek_b64.clone(),
                        quote_type: dotenv::QuoteType::Double,
                    });
                    has_key_line = true;
                    continue;
                }

                if key == DOTSEC_V1_NAME {
                    continue;
                }

                let entry = entries.iter().find(|e| e.key == *key);
                let should_encrypt = entry.is_some_and(|e| e.has_directive("encrypt"));

                if should_encrypt {
                    if crypto::is_encrypted_value(value) {
                        sec_lines.push(line.clone());
                    } else {
                        let encrypted = crypto::encrypt_value(value, dek, key)?;
                        sec_lines.push(Line::Kv { key: key.clone(), value: encrypted, quote_type: quote_type.clone() });
                    }
                } else {
                    sec_lines.push(line.clone());
                }
            }
            Line::Comment { text } if text.contains("do not edit the line below, it is managed by dotsec") => {
                continue;
            }
            other => sec_lines.push(other.clone()),
        }
    }

    if !has_key_line {
        let last_is_newline = matches!(sec_lines.last(), Some(Line::Newline));
        if !sec_lines.is_empty() && !last_is_newline {
            sec_lines.push(Line::Newline);
        }
        sec_lines.push(Line::Newline);
        sec_lines.push(Line::Comment {
            text: "# do not edit the line below, it is managed by dotsec".to_string(),
        });
        sec_lines.push(Line::Newline);
        sec_lines.push(Line::Kv {
            key: DOTSEC_KEY_NAME.to_string(),
            value: wrapped_dek_b64,
            quote_type: dotenv::QuoteType::Double,
        });
        sec_lines.push(Line::Newline);
    }

    let output = dotenv::lines_to_string(&sec_lines);
    write_sec_file(sec_file, &output)?;

    Ok(())
}

// --- Decrypt ---

/// Decrypt a .sec file and return resolved lines with plaintext values.
pub async fn decrypt_sec_to_lines(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;

    match detect_format(&lines) {
        SecFormat::V2 => decrypt_v2(sec_file, &lines, encryption_engine).await,
        SecFormat::V1 => decrypt_v1(&lines, encryption_engine).await,
        SecFormat::None => {
            let has_enc_values = lines.iter().any(|l| {
                if let Line::Kv { value: v, .. } = l { crypto::is_encrypted_value(v) } else { false }
            });
            if has_enc_values {
                return Err("File contains ENC[...] values but no __DOTSEC_KEY__. File may be corrupted.".into());
            }
            Ok(lines)
        }
    }
}

/// Decrypt v2 format: unwrap DEK from __DOTSEC_KEY__, then decrypt each ENC[...] value.
async fn decrypt_v2(
    sec_file: &str,
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
            let private_key = crypto::local::load_private_key(sec_file, opts.key_file.as_deref())?;
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

/// Decrypt v1 format (legacy blob): decrypt __DOTSEC__ blob, resolve ID references.
async fn decrypt_v1(
    lines: &[Line],
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let dotsec_value = dotenv::get_value(lines, DOTSEC_V1_NAME)
        .ok_or("No __DOTSEC__ entry found")?;

    let secrets_json = decrypt_blob_v1(&dotsec_value, encryption_engine).await?;
    let secrets: std::collections::HashMap<String, String> =
        serde_json::from_str(&secrets_json)?;

    let mut resolved: Vec<Line> = Vec::new();
    let mut skip_dotsec_comment = false;

    for line in lines {
        match line {
            Line::Comment { text }
                if text.contains("do not edit the line below, it is managed by dotsec") =>
            {
                skip_dotsec_comment = true;
                continue;
            }
            Line::Kv { key, value, quote_type } => {
                if key == DOTSEC_V1_NAME {
                    continue;
                }
                if let Some(real_value) = secrets.get(value.as_str()) {
                    resolved.push(Line::Kv {
                        key: key.clone(),
                        value: real_value.clone(),
                        quote_type: quote_type.clone(),
                    });
                } else {
                    resolved.push(line.clone());
                }
            }
            Line::Newline if skip_dotsec_comment => {
                skip_dotsec_comment = false;
                continue;
            }
            _ => resolved.push(line.clone()),
        }
    }

    Ok(resolved)
}

/// Attempt to decrypt a v1 blob (legacy envelopers format).
///
/// This always returns an error directing users to migrate, because v1 blobs
/// are base64-encoded `envelopers::EncryptedRecord` and we no longer bundle the
/// envelopers crate. Users must decrypt with dotsec v4.x first, then re-encrypt
/// with v5.x to migrate to the new per-value encryption format.
async fn decrypt_blob_v1(
    _ciphertext: &str,
    _engine: &EncryptionEngine,
) -> Result<String, Box<dyn std::error::Error>> {
    Err("This .sec file uses the legacy v1 format (single encrypted blob). \
         Please decrypt it with dotsec v4.x first, then re-encrypt with v5.x to migrate \
         to the new per-value encryption format."
        .into())
}

// --- DEK helpers ---

type DekPair = (zeroize::Zeroizing<Vec<u8>>, Vec<u8>);

/// Try to load and unwrap the existing DEK from a .sec file.
async fn load_existing_dek_aws(
    sec_file: &str,
    region: Option<&str>,
) -> Result<DekPair, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let wrapped_b64 = dotenv::get_value(&lines, DOTSEC_KEY_NAME)
        .ok_or("No __DOTSEC_KEY__ found")?;
    let wrapped_dek = base64::engine::general_purpose::STANDARD.decode(&wrapped_b64)?;
    let dek = aws::unwrap_data_key(&wrapped_dek, region).await?;
    Ok((dek, wrapped_dek))
}

fn load_existing_dek_local(
    sec_file: &str,
    identity: &str,
) -> Result<DekPair, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let wrapped_b64 = dotenv::get_value(&lines, DOTSEC_KEY_NAME)
        .ok_or("No __DOTSEC_KEY__ found")?;
    let wrapped_dek = base64::engine::general_purpose::STANDARD.decode(&wrapped_b64)?;
    let dek = crypto::local::unwrap_dek(&wrapped_dek, identity)?;
    Ok((dek, wrapped_dek))
}

// --- Run helpers ---

/// Extract key-value pairs from lines and resolve `${VAR}` interpolation.
/// Only double-quoted and unquoted values are interpolated; single-quoted values stay literal.
pub fn resolve_env_vars(lines: &[Line]) -> Vec<(String, String)> {
    let mut resolved: Vec<(String, String)> = Vec::new();

    for line in lines {
        if let Line::Kv { key, value, quote_type } = line {
            if key == DOTSEC_KEY_NAME || key == DOTSEC_V1_NAME {
                continue;
            }
            let final_value = match quote_type {
                dotenv::QuoteType::Single => value.clone(),
                _ => interpolate(value, &resolved),
            };
            resolved.push((key.clone(), final_value));
        }
    }

    resolved
}

/// Replace `${VAR}` and `$VAR` patterns with values from the resolved map.
fn interpolate(value: &str, resolved: &[(String, String)]) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let mut var_name = String::new();
                while chars.peek().is_some_and(|c| *c != '}') {
                    var_name.push(chars.next().unwrap());
                }
                if chars.peek() == Some(&'}') {
                    chars.next(); // consume '}'
                    let val = lookup(&var_name, resolved);
                    result.push_str(&val);
                } else {
                    // Unclosed ${ — treat as literal text
                    eprintln!("warning: unclosed ${{{}}} in value, treating as literal text", var_name);
                    result.push_str("${");
                    result.push_str(&var_name);
                }
            } else if chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == '_')
            {
                let mut var_name = String::new();
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    var_name.push(chars.next().unwrap());
                }
                let val = lookup(&var_name, resolved);
                result.push_str(&val);
            } else {
                result.push('$');
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Look up a variable from the resolved list, falling back to the process environment.
fn lookup(name: &str, resolved: &[(String, String)]) -> String {
    for (k, v) in resolved.iter().rev() {
        if k == name {
            return v.clone();
        }
    }
    std::env::var(name).unwrap_or_default()
}

/// Collect the values of entries marked `@encrypt` from the resolved env vars.
pub fn collect_secret_values(lines: &[Line], env_vars: &[(String, String)]) -> Vec<String> {
    let entries = lines_to_entries(lines);
    let mut secrets = Vec::new();
    for entry in &entries {
        if entry.has_directive("encrypt") {
            if let Some((_, val)) = env_vars.iter().find(|(k, _)| k == &entry.key) {
                if !val.is_empty() {
                    secrets.push(val.clone());
                }
            }
        }
    }
    // Sort longest first so we replace longer matches before shorter substrings
    secrets.sort_by_key(|b| std::cmp::Reverse(b.len()));
    secrets
}

/// Replace all occurrences of secret values in a string with asterisks.
pub fn redact(line: &str, secrets: &[String]) -> String {
    let mut result = line.to_string();
    for secret in secrets {
        result = result.replace(secret, &"*".repeat(secret.len()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::{Line, QuoteType};

    // --- write_sec_file ---

    #[test]
    #[cfg(unix)]
    fn write_sec_file_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("dotsec-test-write-sec");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.sec");

        write_sec_file(path.to_str().unwrap(), "SECRET=hunter2\n").unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- header ---

    #[test]
    fn generate_header_has_two_comment_lines() {
        let header = generate_header();
        let comments: Vec<_> = header.iter().filter(|l| matches!(l, Line::Comment { .. })).collect();
        assert_eq!(comments.len(), 2);
    }

    #[test]
    fn generate_header_first_line_contains_version() {
        let header = generate_header();
        assert!(matches!(&header[0], Line::Comment { text } if text.contains("dotsec v5")));
    }

    #[test]
    fn generate_header_second_line_contains_url() {
        let header = generate_header();
        assert!(matches!(&header[2], Line::Comment { text } if text.contains("https://github.com/jpwesselink/dotsec-rs")));
    }

    #[test]
    fn has_header_true_when_present() {
        let lines = generate_header();
        assert!(has_header(&lines));
    }

    #[test]
    fn has_header_false_when_absent() {
        let lines = vec![
            Line::Comment { text: "# just a comment".into() },
            Line::Newline,
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::None },
        ];
        assert!(!has_header(&lines));
    }

    #[test]
    fn has_header_matches_any_version() {
        let lines = vec![
            Line::Comment { text: "# dotsec v99 — encrypted environment file".into() },
        ];
        assert!(has_header(&lines));
    }

    // --- interpolate ---

    #[test]
    fn interpolate_braced_var() {
        let resolved = vec![("FOO".into(), "100".into())];
        assert_eq!(interpolate("val is ${FOO}", &resolved), "val is 100");
    }

    #[test]
    fn interpolate_unbraced_var() {
        let resolved = vec![("FOO".into(), "100".into())];
        assert_eq!(interpolate("val is $FOO!", &resolved), "val is 100!");
    }

    #[test]
    fn interpolate_missing_var_yields_empty() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("${NOPE}", &resolved), "");
    }

    #[test]
    fn interpolate_multiple_vars() {
        let resolved = vec![
            ("A".into(), "hello".into()),
            ("B".into(), "world".into()),
        ];
        assert_eq!(interpolate("${A} ${B}", &resolved), "hello world");
    }

    #[test]
    fn interpolate_bare_dollar_preserved() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("price is $5", &resolved), "price is $5");
    }

    #[test]
    fn interpolate_no_vars() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("plain text", &resolved), "plain text");
    }

    #[test]
    fn interpolate_unclosed_brace_is_literal() {
        let resolved = vec![("A".into(), "val".into())];
        assert_eq!(interpolate("path is ${UNCLOSED", &resolved), "path is ${UNCLOSED");
    }

    #[test]
    fn interpolate_unclosed_brace_mixed() {
        let resolved = vec![("A".into(), "val".into())];
        assert_eq!(interpolate("${A} then ${UNCLOSED", &resolved), "val then ${UNCLOSED");
    }

    // --- resolve_env_vars ---

    #[test]
    fn resolve_env_vars_basic() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "BAZ".into(), value: "qux".into(), quote_type: QuoteType::None },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(
            resolved,
            vec![("FOO".into(), "bar".into()), ("BAZ".into(), "qux".into()),]
        );
    }

    #[test]
    fn resolve_env_vars_interpolation() {
        let lines = vec![
            Line::Kv { key: "HOST".into(), value: "localhost".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv {
                key: "URL".into(),
                value: "http://${HOST}:3000".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved[1].1, "http://localhost:3000");
    }

    #[test]
    fn resolve_env_vars_single_quote_no_interpolation() {
        let lines = vec![
            Line::Kv { key: "HOST".into(), value: "localhost".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "LITERAL".into(), value: "${HOST}".into(), quote_type: QuoteType::Single },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved[1].1, "${HOST}");
    }

    #[test]
    fn resolve_env_vars_skips_dotsec_key() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "__DOTSEC_KEY__".into(), value: "wrapped".into(), quote_type: QuoteType::Double },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "FOO");
    }

    #[test]
    fn resolve_env_vars_skips_dotsec_v1() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "__DOTSEC__".into(), value: "blob".into(), quote_type: QuoteType::Double },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "FOO");
    }

    // --- format detection ---

    #[test]
    fn detect_v2_format() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "ENC[abc]".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "__DOTSEC_KEY__".into(), value: "wrapped".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(detect_format(&lines), SecFormat::V2);
    }

    #[test]
    fn detect_v1_format() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "hexid".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "__DOTSEC__".into(), value: "blob".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(detect_format(&lines), SecFormat::V1);
    }

    #[test]
    fn detect_no_format() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_with_enc_values_but_no_dotsec_key() {
        // ENC[...] values present but no __DOTSEC_KEY__ or __DOTSEC__ marker
        let lines = vec![
            Line::Kv { key: "SECRET".into(), value: "ENC[base64data]".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "OTHER".into(), value: "ENC[moredata]".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_for_empty_lines() {
        let lines: Vec<Line> = vec![];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_for_only_comments_and_newlines() {
        let lines = vec![
            Line::Comment { text: "# just a comment".into() },
            Line::Newline,
            Line::Newline,
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_v2_takes_priority_over_enc_values() {
        // Both ENC values and __DOTSEC_KEY__ present → V2
        let lines = vec![
            Line::Kv { key: "SECRET".into(), value: "ENC[data]".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "__DOTSEC_KEY__".into(), value: "wrapped_key".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(detect_format(&lines), SecFormat::V2);
    }

    // --- redact ---

    #[test]
    fn redact_replaces_secrets() {
        let secrets = vec!["s3cret".to_string()];
        assert_eq!(
            redact("my password is s3cret", &secrets),
            "my password is ******"
        );
    }

    #[test]
    fn redact_multiple_secrets() {
        let secrets = vec!["longersecret".to_string(), "short".to_string()];
        assert_eq!(
            redact("short and longersecret here", &secrets),
            "***** and ************ here"
        );
    }

    #[test]
    fn redact_no_secrets() {
        let secrets: Vec<String> = vec![];
        assert_eq!(redact("nothing to hide", &secrets), "nothing to hide");
    }

    #[test]
    fn redact_secret_appearing_multiple_times() {
        let secrets = vec!["tok".to_string()];
        assert_eq!(redact("tok and tok again", &secrets), "*** and *** again");
    }

    // --- collect_secret_values ---

    #[test]
    fn collect_secrets_only_encrypted_entries() {
        let lines = vec![
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Newline,
            Line::Kv { key: "SECRET".into(), value: "shhh".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "PUBLIC".into(), value: "visible".into(), quote_type: QuoteType::None },
        ];
        let env_vars = vec![
            ("SECRET".into(), "shhh".into()),
            ("PUBLIC".into(), "visible".into()),
        ];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["shhh"]);
    }

    #[test]
    fn collect_secrets_sorted_longest_first() {
        let lines = vec![
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Newline,
            Line::Kv { key: "A".into(), value: "ab".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Newline,
            Line::Kv { key: "B".into(), value: "abcdef".into(), quote_type: QuoteType::Double },
        ];
        let env_vars = vec![
            ("A".into(), "ab".into()),
            ("B".into(), "abcdef".into()),
        ];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["abcdef", "ab"]);
    }

    #[test]
    fn collect_secrets_skips_empty_values() {
        let lines = vec![
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Newline,
            Line::Kv { key: "EMPTY".into(), value: "".into(), quote_type: QuoteType::Double },
        ];
        let env_vars = vec![("EMPTY".into(), "".into())];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert!(secrets.is_empty());
    }

    // --- detect_format tests ---

    #[test]
    fn detect_enc_values_without_key_is_none() {
        let lines = vec![
            Line::Kv { key: "SECRET".into(), value: "ENC[base64data]".into(), quote_type: QuoteType::Double },
        ];
        assert!(matches!(detect_format(&lines), SecFormat::None));
    }

    #[test]
    fn detect_empty_lines_is_none() {
        let lines: Vec<Line> = vec![];
        assert!(matches!(detect_format(&lines), SecFormat::None));
    }

    #[test]
    fn detect_dotsec_key_is_v2() {
        let lines = vec![
            Line::Kv { key: "__DOTSEC_KEY__".into(), value: "wrapped_dek".into(), quote_type: QuoteType::Double },
            Line::Kv { key: "SECRET".into(), value: "ENC[data]".into(), quote_type: QuoteType::Double },
        ];
        assert!(matches!(detect_format(&lines), SecFormat::V2));
    }

    // --- Plaintext .sec roundtrip tests ---

    #[test]
    fn plaintext_sec_roundtrip() {
        // Create lines with @default-plaintext + some Kv entries
        let lines = vec![
            Line::Directive { name: "default-plaintext".into(), value: None },
            Line::Newline,
            Line::Newline,
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "PORT".into(), value: "3000".into(), quote_type: QuoteType::None },
            Line::Newline,
        ];

        // Serialize to string
        let content = dotenv::lines_to_string(&lines);

        // Parse back and verify values match
        let reparsed = dotenv::parse_dotenv(&content).unwrap();
        let entries = dotenv::lines_to_entries(&reparsed);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "FOO");
        assert_eq!(entries[0].value, "bar");
        assert_eq!(entries[1].key, "PORT");
        assert_eq!(entries[1].value, "3000");
    }

    #[test]
    fn detect_format_none_for_plaintext_file() {
        // A file with no ENC[...] values and no __DOTSEC_KEY__
        let lines = vec![
            Line::Directive { name: "default-plaintext".into(), value: None },
            Line::Newline,
            Line::Newline,
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "PORT".into(), value: "3000".into(), quote_type: QuoteType::None },
            Line::Newline,
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn sec_format_none_with_enc_values_detected() {
        // A file with ENC[...] values but NO __DOTSEC_KEY__
        let lines = vec![
            Line::Kv { key: "SECRET".into(), value: "ENC[base64data]".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Kv { key: "OTHER".into(), value: "ENC[moredata]".into(), quote_type: QuoteType::Double },
            Line::Newline,
        ];

        // detect_format returns None (no __DOTSEC_KEY__)
        assert_eq!(detect_format(&lines), SecFormat::None);

        // But we can detect the ENC values are present, which should be an error condition
        let has_enc_values = lines.iter().any(|l| {
            if let Line::Kv { value: v, .. } = l {
                crypto::is_encrypted_value(v)
            } else {
                false
            }
        });
        assert!(has_enc_values, "ENC values should be detected");

        // This combination (ENC values without __DOTSEC_KEY__) indicates a corrupted file
    }

    // --- redact (extended) ---

    #[test]
    fn redact_across_full_line() {
        let secrets = vec!["entire-line-is-secret".to_string()];
        let redacted = redact("entire-line-is-secret", &secrets);
        assert_eq!(
            redacted,
            "*".repeat("entire-line-is-secret".len()),
            "a secret that spans the full line should be fully masked"
        );
    }

    #[test]
    fn redact_preserves_non_secret_content() {
        let secrets = vec!["hidden".to_string()];
        let result = redact("prefix hidden suffix", &secrets);
        assert_eq!(result, "prefix ****** suffix");
        assert!(result.contains("prefix"));
        assert!(result.contains("suffix"));
        assert!(!result.contains("hidden"));
    }

    #[test]
    fn redact_empty_secrets_list() {
        let secrets: Vec<String> = vec![];
        let line = "nothing changes here";
        assert_eq!(redact(line, &secrets), line);
    }

    #[test]
    fn collect_and_redact_integration() {
        // Parse a .sec-style string with @encrypt directive
        let sec_content = "# @encrypt\nDB_PASSWORD=\"super-secret-pw\"\nPUBLIC_URL=http://example.com\n";
        let lines = dotenv::parse_dotenv(sec_content).unwrap();

        // Resolve env vars
        let env_vars = resolve_env_vars(&lines);
        assert_eq!(env_vars.len(), 2);

        // Collect secret values (only @encrypt entries)
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["super-secret-pw"]);

        // Redact a line containing one of the secret values
        let output_line = "connecting to DB with password super-secret-pw ...";
        let redacted = redact(output_line, &secrets);
        assert!(
            !redacted.contains("super-secret-pw"),
            "secret value should be masked"
        );
        assert!(
            redacted.contains("***************"),
            "masked value should be asterisks of same length"
        );
        assert!(
            redacted.contains("connecting to DB with password"),
            "non-secret text should be preserved"
        );
    }

    // --- resolve_env_vars (extended for run --using env) ---

    #[test]
    fn resolve_env_vars_from_plain_env() {
        let env_content = "APP_NAME=myapp\nPORT=8080\nDEBUG=true\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0], ("APP_NAME".into(), "myapp".into()));
        assert_eq!(resolved[1], ("PORT".into(), "8080".into()));
        assert_eq!(resolved[2], ("DEBUG".into(), "true".into()));
    }

    #[test]
    fn resolve_env_vars_with_interpolation() {
        let env_content = "BASE=\"http://localhost\"\nURL=\"${BASE}/api\"\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0], ("BASE".into(), "http://localhost".into()));
        assert_eq!(resolved[1], ("URL".into(), "http://localhost/api".into()));
    }

    #[test]
    fn resolve_env_vars_single_quotes_no_interpolation() {
        let env_content = "HOST=\"localhost\"\nLITERAL='${HOST}/path'\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0], ("HOST".into(), "localhost".into()));
        assert_eq!(
            resolved[1],
            ("LITERAL".into(), "${HOST}/path".into()),
            "single-quoted values should not interpolate"
        );
    }

    #[test]
    fn plaintext_lines_to_string_roundtrip_with_directives() {
        let source = "# @default-plaintext\n\n# @type=string\nFOO=\"hello\"\n\n# @type=number\nPORT=3000\n";
        let lines = dotenv::parse_dotenv(source).unwrap();
        let output = dotenv::lines_to_string(&lines);
        assert_eq!(output, source);

        // Re-parse and validate entries
        let reparsed = dotenv::parse_dotenv(&output).unwrap();
        let entries = dotenv::lines_to_entries(&reparsed);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "FOO");
        assert_eq!(entries[0].value, "hello");
        assert!(!entries[0].has_directive("encrypt"), "plaintext default should not add encrypt");
    }

    // --- local encryption integration ---

    #[tokio::test]
    async fn local_encrypt_decrypt_roundtrip() {
        let dir = std::env::temp_dir().join("dotsec-test-local-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();

        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

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

        encrypt_lines_to_sec(&lines, &sec_file, &engine).await.unwrap();

        let content = std::fs::read_to_string(&sec_file).unwrap();
        assert!(content.contains("ENC["), "encrypted value should contain ENC[...]");
        assert!(content.contains("__DOTSEC_KEY__"), "should contain wrapped DEK");
        assert!(!content.contains("hunter2"), "plaintext should not appear");

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

    #[tokio::test]
    async fn local_decrypt_with_wrong_key_fails() {
        let dir = std::env::temp_dir().join("dotsec-test-local-wrong-key");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let wrong_key_file = dir.join("wrong.sec.key").to_string_lossy().to_string();

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

        let wrong_engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(wrong_key_file),
        });
        let result = decrypt_sec_to_lines(&sec_file, &wrong_engine).await;
        assert!(result.is_err(), "decrypting with wrong key should fail");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_decrypt_discovers_sibling_key_file() {
        let dir = std::env::temp_dir().join("dotsec-test-local-discovery");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();

        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let lines = vec![
            Line::Directive { name: "encrypt".to_string(), value: None },
            Line::Newline,
            Line::Kv { key: "SECRET".into(), value: "hunter2".into(), quote_type: QuoteType::Double },
            Line::Newline,
        ];

        let encrypt_engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file.clone()),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &encrypt_engine).await.unwrap();

        // Decrypt with key_file: None — must auto-discover <sec>.key.
        let decrypt_engine = EncryptionEngine::Local(LocalEncryptionOptions { key_file: None });
        let decrypted = decrypt_sec_to_lines(&sec_file, &decrypt_engine).await.unwrap();
        let secret_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l { if key == "SECRET" { Some(value.clone()) } else { None } } else { None }
        });
        assert_eq!(secret_val.as_deref(), Some("hunter2"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
