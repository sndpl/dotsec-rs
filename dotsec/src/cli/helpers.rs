use colored::Colorize;
use inquire::{Confirm, Select, Text};
use std::future::Future;
use std::sync::OnceLock;
use std::time::Duration;

static ANIMATION_DELAY: OnceLock<Duration> = OnceLock::new();

/// Set a cosmetic delay applied after each `with_progress` future resolves
/// but before the fade-out, so users can savor the animation.
pub fn set_animation_delay(delay: Duration) {
    let _ = ANIMATION_DELAY.set(delay);
}

/// Run an async operation with a dark_n_stormy glow animation as progress indicator.
/// When done, the label fades to the terminal's foreground color.
pub async fn with_progress<T>(label: &str, fut: impl Future<Output = T>) -> T {
    let anim = chromakopia::animate::glow(chromakopia::presets::dark_n_stormy(), label, 1.0);
    let result = fut.await;
    if let Some(delay) = ANIMATION_DELAY.get() {
        tokio::time::sleep(*delay).await;
    }
    anim.fade_to_foreground(Duration::from_millis(400)).await;
    result
}

/// Heuristic: does this key name look like it holds a secret?
pub fn looks_like_secret(key: &str) -> bool {
    let key_upper = key.to_uppercase();
    let secret_patterns = [
        "SECRET", "KEY", "TOKEN", "PASSWORD", "PASSWD", "PWD",
        "CREDENTIAL", "AUTH", "PRIVATE", "API_KEY", "APIKEY",
        "DATABASE_URL", "DB_URL", "CONNECTION_STRING",
    ];
    secret_patterns.iter().any(|p| key_upper.contains(p))
}

/// Heuristic: guess the type index for a value.
/// Returns an index into the type_options vec: 0=string, 1=number, 2=boolean.
/// Used as `with_starting_cursor` for the type selection prompt.
pub fn guess_type(value: &str) -> usize {
    if value == "true" || value == "false" {
        return 2; // boolean
    }
    if value.parse::<f64>().is_ok() {
        return 1; // number
    }
    0 // string
}

/// Truncate a string, appending "..." if it exceeds max characters.
/// Uses character count (not byte count) to avoid panicking on multi-byte UTF-8.
pub fn truncate_value(value: &str, max: usize) -> String {
    if value.chars().count() > max {
        format!("{}...", value.chars().take(max).collect::<String>())
    } else {
        value.to_string()
    }
}

/// Build config directive lines for the .sec file header.
pub fn build_config_directives(config: &dotenv::FileConfig, encrypt_all: bool) -> Vec<dotenv::Line> {
    let mut directives = Vec::new();

    if let Some(ref provider) = config.provider {
        directives.push(dotenv::Line::Directive { name: "provider".to_string(), value: Some(provider.clone()) });
    }
    if let Some(ref key_id) = config.key_id {
        directives.push(dotenv::Line::Directive { name: "key-id".to_string(), value: Some(key_id.clone()) });
    }
    if let Some(ref region) = config.region {
        directives.push(dotenv::Line::Directive { name: "region".to_string(), value: Some(region.clone()) });
    }

    let default_directive = if encrypt_all { "default-encrypt" } else { "default-plaintext" };
    directives.push(dotenv::Line::Directive { name: default_directive.to_string(), value: None });

    directives
}

/// Strip per-key schema directives from parsed lines, keeping file-level and env directives.
/// Returns the filtered lines (for rewriting .sec) and the extracted schema entries.
pub fn extract_schema_from_lines(lines: &[dotenv::Line]) -> (Vec<dotenv::Line>, Vec<dotenv::SchemaEntry>) {
    let mut output_lines: Vec<dotenv::Line> = Vec::new();
    let mut schema_entries: Vec<dotenv::SchemaEntry> = Vec::new();
    let mut pending_all: Vec<(dotenv::Line, String, Option<String>)> = Vec::new(); // (original line, name, value)

    for line in lines {
        match line {
            dotenv::Line::Directive { name, value } => {
                pending_all.push((line.clone(), name.clone(), value.clone()));
            }
            dotenv::Line::Kv { key: k, value: v, quote_type: qt } => {
                let mut schema_directives: Vec<(String, Option<String>)> = Vec::new();

                for (orig_line, name, value) in &pending_all {
                    if dotenv::SCHEMA_DIRECTIVES.contains(&name.as_str()) {
                        schema_directives.push((name.clone(), value.clone()));
                    } else {
                        // env/file-level directive — keep in output
                        output_lines.push(orig_line.clone());
                    }
                }

                if !schema_directives.is_empty() {
                    schema_entries.push(dotenv::SchemaEntry {
                        directives: schema_directives,
                        key: k.clone(),
                    });
                } else {
                    schema_entries.push(dotenv::SchemaEntry {
                        directives: vec![],
                        key: k.clone(),
                    });
                }

                output_lines.push(dotenv::Line::Kv { key: k.clone(), value: v.clone(), quote_type: qt.clone() });
                pending_all.clear();
            }
            dotenv::Line::Comment { .. } => {
                // Comments break the directive chain — flush pending as-is
                for (orig_line, _, _) in &pending_all {
                    output_lines.push(orig_line.clone());
                }
                pending_all.clear();
                output_lines.push(line.clone());
            }
            _ => {
                output_lines.push(line.clone());
            }
        }
    }

    // Any remaining pending directives (no KV followed)
    for (orig_line, _, _) in &pending_all {
        output_lines.push(orig_line.clone());
    }

    (output_lines, schema_entries)
}

/// Strip per-key schema directives from lines, keeping only file-level + env directives + KV pairs.
pub fn strip_schema_directives(lines: &[dotenv::Line]) -> Vec<dotenv::Line> {
    extract_schema_from_lines(lines).0
}

/// Compare two FileConfigs and return human-readable differences.
pub fn config_diffs(source: &dotenv::FileConfig, existing: &dotenv::FileConfig) -> Vec<String> {
    let mut diffs = Vec::new();

    if source.provider != existing.provider {
        diffs.push(format!(
            "provider: {} vs {}",
            source.provider.as_deref().unwrap_or("(none)"),
            existing.provider.as_deref().unwrap_or("(none)")
        ));
    }
    if source.key_id != existing.key_id {
        diffs.push(format!(
            "key-id: {} vs {}",
            source.key_id.as_deref().unwrap_or("(none)"),
            existing.key_id.as_deref().unwrap_or("(none)")
        ));
    }
    if source.region != existing.region {
        diffs.push(format!(
            "region: {} vs {}",
            source.region.as_deref().unwrap_or("(none)"),
            existing.region.as_deref().unwrap_or("(none)")
        ));
    }
    if source.default_encrypt != existing.default_encrypt {
        let fmt = |v: Option<bool>| match v {
            Some(true) => "encrypt all",
            Some(false) => "encrypt none",
            None => "(none)",
        };
        diffs.push(format!("default: {} vs {}", fmt(source.default_encrypt), fmt(existing.default_encrypt)));
    }

    diffs
}

/// Prompt for encryption provider config (like init).
pub fn prompt_config() -> Result<dotenv::FileConfig, Box<dyn std::error::Error>> {
    let provider = Select::new("Encryption provider?", vec!["local", "aws"]).prompt()?;

    match provider {
        "local" => Ok(dotenv::FileConfig {
            provider: Some("local".to_string()),
            key_id: None,
            region: None,
            default_encrypt: None,
        }),
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

/// Prompt for encryption default. Uses source config if available.
pub fn resolve_encrypt_default(source_config: &dotenv::FileConfig) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(val) = source_config.default_encrypt {
        let label = if val { "encrypt all" } else { "encrypt none" };
        println!("{} Using source default: {}", "✓".green(), label);
        Ok(val)
    } else {
        let choice = Select::new(
            "Default encryption policy?",
            vec!["encrypt all", "encrypt none"],
        )
        .prompt()?;
        Ok(choice == "encrypt all")
    }
}

/// Prompt for per-variable directives (encrypt, type, push).
/// If `source_directives` is provided, use them as defaults instead of heuristics.
/// Returns the directive lines for this variable.
pub fn prompt_variable_directives(
    key: &str,
    value: &str,
    encrypt_all: bool,
    source_directives: Option<&[(String, Option<String>)]>,
) -> Result<Vec<dotenv::Line>, Box<dyn std::error::Error>> {
    let mut directives: Vec<dotenv::Line> = Vec::new();

    // Check source directives for existing encrypt/plaintext
    let source_has_encrypt = source_directives
        .map(|d| d.iter().any(|(n, _)| n == "encrypt"))
        .unwrap_or(false);
    let source_has_plaintext = source_directives
        .map(|d| d.iter().any(|(n, _)| n == "plaintext"))
        .unwrap_or(false);

    // Encrypt? Default: source directive > heuristic
    let is_secret = looks_like_secret(key);
    let is_exception = if encrypt_all {
        // "Exclude from encryption?" — default yes if source says plaintext, else heuristic
        let default = if source_has_plaintext { true }
            else if source_has_encrypt { false }
            else { !is_secret };
        Confirm::new("  Exclude from encryption?")
            .with_default(default)
            .prompt()?
    } else {
        // "Encrypt?" — default yes if source says encrypt, else heuristic
        let default = if source_has_encrypt { true }
            else if source_has_plaintext { false }
            else { is_secret };
        Confirm::new("  Encrypt?")
            .with_default(default)
            .prompt()?
    };

    if is_exception {
        let directive = if encrypt_all { "plaintext" } else { "encrypt" };
        directives.push(dotenv::Line::Directive { name: directive.to_string(), value: None });
    }

    // Type? Default: source @type directive > value heuristic
    let source_type = source_directives.and_then(|d| {
        d.iter().find(|(n, _)| n == "type").and_then(|(_, v)| v.as_deref())
    });

    let type_options = vec!["string", "number", "boolean", "enum", "skip"];
    let default_type = if let Some(st) = source_type {
        let base = st.trim().trim_matches('"');
        if base.starts_with("enum(") { 3 } // enum index
        else { type_options.iter().position(|o| *o == base).unwrap_or_else(|| guess_type(value)) }
    } else {
        guess_type(value)
    };

    let var_type = Select::new("  Type?", type_options)
        .with_starting_cursor(default_type)
        .prompt()?;

    match var_type {
        "string" | "number" | "boolean" => {
            directives.push(dotenv::Line::Directive {
                name: "type".to_string(),
                value: Some(var_type.to_string()),
            });
        }
        "enum" => {
            // Pre-fill with source enum values if available
            let source_enum_default = source_type
                .filter(|s| s.contains("enum("))
                .and_then(|s| {
                    let inner = &s[s.find('(')? + 1..s.rfind(')')?];
                    // Convert "val1", "val2" back to val1, val2
                    let vals: Vec<&str> = inner.split(',')
                        .map(|v| v.trim().trim_matches('"'))
                        .collect();
                    Some(vals.join(", "))
                });

            let mut prompt = Text::new("  Enum values (comma-separated)?")
                .with_help_message("e.g. development, staging, production");
            if let Some(ref default) = source_enum_default {
                prompt = prompt.with_default(default);
            }
            let variants = prompt.prompt()?;

            let formatted = variants
                .split(',')
                .map(|v| format!("\"{}\"", v.trim()))
                .collect::<Vec<_>>()
                .join(", ");
            directives.push(dotenv::Line::Directive {
                name: "type".to_string(),
                value: Some(format!("enum({})", formatted)),
            });
        }
        _ => {} // skip
    }

    // Push? Default: source @push directive > none
    let source_push = source_directives.and_then(|d| {
        d.iter().find(|(n, _)| n == "push").and_then(|(_, v)| v.as_deref())
    });

    let push_options = vec!["none", "aws-ssm", "aws-secrets-manager", "both"];
    let default_push = if let Some(sp) = source_push {
        let has_ssm = sp.contains("aws-ssm") || sp.contains("ssm");
        let has_sm = sp.contains("secrets-manager") || sp.contains("secretsmanager");
        if has_ssm && has_sm { 3 } // both
        else if has_sm { 2 } // aws-secrets-manager
        else if has_ssm { 1 } // aws-ssm
        else { 0 }
    } else {
        0
    };

    let push = Select::new("  Push target?", push_options)
        .with_starting_cursor(default_push)
        .prompt()?;

    match push {
        "aws-ssm" => {
            // Pre-fill SSM path from source if available
            let source_ssm_path = source_push.and_then(|sp| {
                if let Some(start) = sp.find("aws-ssm(") {
                    let after = &sp[start + 8..];
                    if let Some(end) = after.find(')') {
                        let params = &after[..end];
                        // Extract path="..." value
                        if let Some(pstart) = params.find("path=\"") {
                            let val_start = pstart + 6;
                            let val = &params[val_start..];
                            if let Some(pend) = val.find('"') {
                                return Some(val[..pend].to_string());
                            }
                        }
                    }
                }
                None
            });

            let mut prompt = Text::new("  SSM path?")
                .with_help_message("e.g. /myapp/prod/db-url (leave empty for default)");
            if let Some(ref default_path) = source_ssm_path {
                prompt = prompt.with_default(default_path);
            }
            let path = prompt.prompt()?;

            let val = if path.is_empty() {
                "aws-ssm".to_string()
            } else {
                format!("aws-ssm(path=\"{}\")", path)
            };
            directives.push(dotenv::Line::Directive { name: "push".to_string(), value: Some(val) });
        }
        "aws-secrets-manager" => {
            directives.push(dotenv::Line::Directive {
                name: "push".to_string(),
                value: Some("aws-secrets-manager".to_string()),
            });
        }
        "both" => {
            directives.push(dotenv::Line::Directive {
                name: "push".to_string(),
                value: Some("aws-ssm, aws-secrets-manager".to_string()),
            });
        }
        _ => {} // none
    }

    Ok(directives)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::{FileConfig, Line};

    // --- looks_like_secret ---

    #[test]
    fn secret_key_patterns() {
        assert!(looks_like_secret("DATABASE_URL"));
        assert!(looks_like_secret("API_KEY"));
        assert!(looks_like_secret("APIKEY"));
        assert!(looks_like_secret("MY_SECRET_VALUE"));
        assert!(looks_like_secret("auth_token"));
        assert!(looks_like_secret("PASSWORD"));
        assert!(looks_like_secret("PRIVATE_KEY"));
        assert!(looks_like_secret("CONNECTION_STRING"));
        assert!(looks_like_secret("DB_URL"));
    }

    #[test]
    fn non_secret_key_patterns() {
        assert!(!looks_like_secret("ENVIRONMENT_NAME"));
        assert!(!looks_like_secret("PORT"));
        assert!(!looks_like_secret("DEBUG"));
        assert!(!looks_like_secret("LOG_LEVEL"));
        assert!(!looks_like_secret("APP_NAME"));
    }

    #[test]
    fn secret_detection_case_insensitive() {
        assert!(looks_like_secret("my_password"));
        assert!(looks_like_secret("My_Token"));
        assert!(looks_like_secret("database_url"));
    }

    // --- guess_type ---

    #[test]
    fn guess_type_boolean() {
        assert_eq!(guess_type("true"), 2);
        assert_eq!(guess_type("false"), 2);
    }

    #[test]
    fn guess_type_zero_and_one_are_numbers() {
        assert_eq!(guess_type("1"), 1);
        assert_eq!(guess_type("0"), 1);
    }

    #[test]
    fn guess_type_number() {
        assert_eq!(guess_type("42"), 1);
        assert_eq!(guess_type("3.14"), 1);
        assert_eq!(guess_type("-7"), 1);
    }

    #[test]
    fn guess_type_string() {
        assert_eq!(guess_type("hello"), 0);
        assert_eq!(guess_type("postgres://localhost"), 0);
        assert_eq!(guess_type(""), 0);
    }

    // --- truncate_value ---

    #[test]
    fn truncate_short() {
        assert_eq!(truncate_value("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact() {
        assert_eq!(truncate_value("hello", 5), "hello");
    }

    #[test]
    fn truncate_long() {
        assert_eq!(truncate_value("hello world", 5), "hello...");
    }

    #[test]
    fn truncate_multibyte_utf8() {
        // Should not panic on multi-byte characters like emoji
        let result = truncate_value("hello \u{1F511} world", 7);
        assert_eq!(result, "hello \u{1F511}...");
    }

    // --- config_diffs ---

    #[test]
    fn config_diffs_identical() {
        let a = FileConfig {
            provider: Some("aws".into()),
            key_id: Some("alias/dotsec".into()),
            region: Some("us-east-1".into()),
            default_encrypt: Some(true),
        };
        assert!(config_diffs(&a, &a.clone()).is_empty());
    }

    #[test]
    fn config_diffs_detects_differences() {
        let a = FileConfig {
            provider: Some("aws".into()),
            key_id: Some("alias/key-a".into()),
            region: Some("us-east-1".into()),
            default_encrypt: Some(true),
        };
        let b = FileConfig {
            provider: Some("aws".into()),
            key_id: Some("alias/key-b".into()),
            region: Some("eu-west-1".into()),
            default_encrypt: Some(false),
        };
        let diffs = config_diffs(&a, &b);
        assert_eq!(diffs.len(), 3);
    }

    // --- build_config_directives ---

    #[test]
    fn build_config_full() {
        let config = FileConfig {
            provider: Some("aws".into()),
            key_id: Some("alias/dotsec".into()),
            region: Some("us-east-1".into()),
            default_encrypt: None,
        };
        let directives = build_config_directives(&config, true);
        assert_eq!(directives.len(), 4);
        assert!(matches!(&directives[3], Line::Directive { name: n, value: None } if n == "default-encrypt"));
    }

    #[test]
    fn build_config_empty() {
        let config = FileConfig::default();
        let directives = build_config_directives(&config, false);
        assert_eq!(directives.len(), 1);
        assert!(matches!(&directives[0], Line::Directive { name: n, value: None } if n == "default-plaintext"));
    }

    #[test]
    fn build_config_roundtrips() {
        let config = FileConfig {
            provider: Some("aws".into()),
            key_id: Some("alias/dotsec".into()),
            region: Some("us-east-1".into()),
            default_encrypt: None,
        };
        let mut directives = build_config_directives(&config, true);
        directives.push(dotenv::Line::Newline);
        let output = dotenv::lines_to_string(&directives);
        let parsed = dotenv::parse_dotenv(&output).unwrap();
        let parsed_config = dotenv::extract_file_config(&parsed);
        assert_eq!(parsed_config.provider.as_deref(), Some("aws"));
        assert_eq!(parsed_config.key_id.as_deref(), Some("alias/dotsec"));
        assert_eq!(parsed_config.region.as_deref(), Some("us-east-1"));
        assert_eq!(parsed_config.default_encrypt, Some(true));
    }

    // --- extract_schema_from_lines tests ---

    #[test]
    fn extract_schema_separates_directives() {
        // Input: a .sec file with inline schema directives
        let source = "# @type=string @format=url\nDB_URL=\"postgres://localhost\"\n\n# @type=number\nPORT=3000\n";
        let lines = dotenv::parse_dotenv(source).unwrap();
        let (stripped_lines, schema_entries) = extract_schema_from_lines(&lines);

        // Schema entries should have 2 entries with correct directives
        assert_eq!(schema_entries.len(), 2);
        assert_eq!(schema_entries[0].key, "DB_URL");
        assert!(schema_entries[0].directives.iter().any(|(n, _)| n == "type"));
        assert!(schema_entries[0].directives.iter().any(|(n, _)| n == "format"));
        assert_eq!(schema_entries[1].key, "PORT");
        assert!(schema_entries[1].directives.iter().any(|(n, _)| n == "type"));

        // Stripped lines should have Kv but no @type/@format directives
        let directive_count = stripped_lines.iter().filter(|l| {
            matches!(l, Line::Directive { name, .. } if name == "type" || name == "format")
        }).count();
        assert_eq!(directive_count, 0, "schema directives should be stripped");

        // But the KV lines should still be present
        let kv_count = stripped_lines.iter().filter(|l| matches!(l, Line::Kv { .. })).count();
        assert_eq!(kv_count, 2, "KV lines should be preserved");
    }

    #[test]
    fn extract_schema_preserves_file_level_directives() {
        // Input has file-level @provider=aws and @default-encrypt plus a schema directive @type=string
        let source = "# @provider=aws @default-encrypt\n\n# @type=string\nDB_URL=\"postgres://localhost\"\n";
        let lines = dotenv::parse_dotenv(source).unwrap();
        let (stripped_lines, schema_entries) = extract_schema_from_lines(&lines);

        // @provider is an env directive (not a schema directive), so it stays in stripped_lines
        let has_provider = stripped_lines.iter().any(|l| {
            matches!(l, Line::Directive { name, .. } if name == "provider")
        });
        assert!(has_provider, "provider directive should stay in stripped lines");

        // @default-encrypt is a SCHEMA_FILE_LEVEL_DIRECTIVE but it's also a file-level directive
        // that stays in the .sec for runtime use (extract_schema only strips per-key schema directives)
        let has_default_encrypt = stripped_lines.iter().any(|l| {
            matches!(l, Line::Directive { name, .. } if name == "default-encrypt")
        });
        assert!(has_default_encrypt, "default-encrypt should stay in stripped lines");

        // @type=string should be extracted into schema
        assert_eq!(schema_entries.len(), 1);
        assert!(schema_entries[0].directives.iter().any(|(n, _)| n == "type"));
    }

    #[test]
    fn extract_schema_handles_no_directives() {
        // Input has only bare key=value pairs
        let source = "FOO=bar\nBAZ=qux\n";
        let lines = dotenv::parse_dotenv(source).unwrap();
        let (stripped_lines, schema_entries) = extract_schema_from_lines(&lines);

        // stripped_lines should be the same as input (no directives to strip)
        let kv_count = stripped_lines.iter().filter(|l| matches!(l, Line::Kv { .. })).count();
        assert_eq!(kv_count, 2);

        // schema_entries should have entries but with empty directives
        assert_eq!(schema_entries.len(), 2);
        assert!(schema_entries[0].directives.is_empty());
        assert!(schema_entries[1].directives.is_empty());
    }

    #[test]
    fn strip_schema_directives_matches_extract() {
        let source = "# @type=string @format=url\nDB_URL=\"postgres://localhost\"\n\n# @type=number @min=0 @max=65535\nPORT=3000\n";
        let lines = dotenv::parse_dotenv(source).unwrap();

        let (extracted_stripped, _) = extract_schema_from_lines(&lines);
        let stripped = strip_schema_directives(&lines);

        // Both should produce identical stripped lines
        assert_eq!(extracted_stripped.len(), stripped.len(),
            "extracted stripped and strip_schema_directives should produce same length");
        let extracted_str = dotenv::lines_to_string(&extracted_stripped);
        let stripped_str = dotenv::lines_to_string(&stripped);
        assert_eq!(extracted_str, stripped_str,
            "both methods should produce identical output");
    }
}
