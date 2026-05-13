use clap::{Arg, Command};
use colored::Colorize;
use inquire::{Password, PasswordDisplayMode, Text};

use crate::cli::helpers::{self, with_progress};
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("set")
        .about("Add or update a variable in .sec")
        .arg(Arg::new("key").help("Variable name"))
        .arg(Arg::new("value").help("Variable value"))
        .arg(
            Arg::new("encrypt")
                .long("encrypt")
                .action(clap::ArgAction::SetTrue)
                .help("Mark variable for encryption"),
        )
        .arg(
            Arg::new("plaintext")
                .long("plaintext")
                .action(clap::ArgAction::SetTrue)
                .help("Mark variable as plaintext"),
        )
        .arg(
            Arg::new("type")
                .long("type")
                .value_name("TYPE")
                .help("Type directive (string, number, boolean, enum(...))"),
        )
        .arg(
            Arg::new("push")
                .long("push")
                .value_name("TARGET")
                .help("Push target (aws-ssm, aws-secrets-manager)"),
        )
        .arg(
            Arg::new("yes")
                .short('y')
                .long("yes")
                .action(clap::ArgAction::SetTrue)
                .help("Accept auto-detected type and encryption (skip directive prompts)"),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sub = match matches.subcommand_matches("set") {
        Some(m) => m,
        None => return Ok(()),
    };

    let sec_file = default_options.sec_file;
    let key = sub.get_one::<String>("key");
    let value = sub.get_one::<String>("value");
    let auto_yes = sub.get_flag("yes");

    let interactive = value.is_none() && !auto_yes;

    // Resolve key
    let key = match key {
        Some(k) => k.clone(),
        None => Text::new("Variable name?").prompt()?,
    };

    if key.is_empty() {
        return Err("Variable name cannot be empty".into());
    }

    // Auto-init: if .sec doesn't exist, create it with local provider
    let resolved_engine;
    let encryption_engine = if std::path::Path::new(sec_file).exists() {
        &default_options.encryption_engine
    } else {
        // Generate keypair and create .sec
        let key_file = format!("{}.key", sec_file);
        if !std::path::Path::new(&key_file).exists() {
            let (identity, _) = crypto::local::generate_keypair();
            dotsec::write_sec_file(&key_file, &format!("{}\n", identity))?;
            eprintln!("{} Created {}", "✓".green(), key_file);

            let gitignore_path = std::path::Path::new(sec_file)
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join(".gitignore");
            let has_key_pattern = std::fs::read_to_string(&gitignore_path)
                .map(|c| c.lines().any(|l| l.trim() == "*.key" || l.contains(".key")))
                .unwrap_or(false);
            if !has_key_pattern {
                eprintln!("{} Add *.key to .gitignore to avoid committing private keys", "⚠".yellow().bold());
            }
        }

        // Write initial .sec with header + local provider config
        let mut init_lines = dotsec::generate_header();
        init_lines.push(dotenv::Line::Newline);
        init_lines.extend(helpers::build_config_directives(
            &dotenv::FileConfig {
                provider: Some("local".to_string()),
                key_id: None,
                region: None,
                default_encrypt: Some(true),
            },
            true,
        ));
        init_lines.push(dotenv::Line::Newline);
        let output = dotenv::lines_to_string(&init_lines);
        dotsec::write_sec_file(sec_file, &output)?;
        eprintln!("{} Created {}", "✓".green(), sec_file);
        eprintln!("  → Commit {} to git", sec_file);
        eprintln!("  → Keep {}.key secret — share it with teammates over a secure channel", sec_file);

        resolved_engine = dotsec::EncryptionEngine::Local(dotsec::LocalEncryptionOptions {
            key_file: None,
        });
        &resolved_engine
    };

    // Discover schema
    let schema_path = dotenv::schema::discover_schema(
        sec_file,
        default_options.schema_path.as_deref(),
    )?;
    let mut schema = if let Some(ref path) = schema_path {
        let content = std::fs::read_to_string(path)?;
        Some(dotenv::parse_schema(&content)?)
    } else {
        None
    };
    let key_in_schema = schema.as_ref().is_some_and(|s| s.get(&key).is_some());

    // Read raw .sec lines (not decrypted) for the prompts — we may not need KMS at all
    let raw_lines = if std::path::Path::new(sec_file).exists() {
        let content = std::fs::read_to_string(sec_file)?;
        dotenv::parse_dotenv(&content)?
    } else {
        Vec::new()
    };

    // Check file-level encryption default from raw lines
    let file_default_encrypt = raw_lines.iter().any(|l| matches!(l, dotenv::Line::Directive { name: n, .. } if n == "default-encrypt"));
    // Find existing key in raw lines (value will be an opaque ID if encrypted, but we only need position)
    let existing_pos = raw_lines.iter().position(|l| matches!(l, dotenv::Line::Kv { key: k, .. } if k == &key));

    // Check if the existing variable was encrypted (has @encrypt directive or inherits from default)
    let old_was_encrypted = if let Some(kv_pos) = existing_pos {
        if key_in_schema {
            // When schema exists, check schema for encrypt directive
            schema.as_ref().unwrap().get(&key).unwrap().has_directive("encrypt") || file_default_encrypt
        } else {
            let dir_start = find_directive_start(&raw_lines, kv_pos);
            let has_explicit_encrypt = raw_lines[dir_start..kv_pos].iter()
                .any(|l| matches!(l, dotenv::Line::Directive { name: n, .. } if n == "encrypt"));
            let has_explicit_plaintext = raw_lines[dir_start..kv_pos].iter()
                .any(|l| matches!(l, dotenv::Line::Directive { name: n, .. } if n == "plaintext"));
            if has_explicit_encrypt { true }
            else if has_explicit_plaintext { false }
            else { file_default_encrypt }
        }
    } else {
        false
    };

    // For interactive value prompt on existing plaintext vars, show current value
    let current_plaintext_value = if !old_was_encrypted {
        existing_pos.and_then(|pos| {
            if let dotenv::Line::Kv { value: v, .. } = &raw_lines[pos] {
                Some(v.as_str())
            } else {
                None
            }
        })
    } else {
        None // Can't show encrypted value without KMS
    };

    // Resolve value — mask input for secret-looking keys
    let value = match value {
        Some(v) => v.clone(),
        None => {
            if helpers::looks_like_secret(&key) {
                Password::new("Value (hidden)?")
                    .with_display_mode(PasswordDisplayMode::Masked)
                    .without_confirmation()
                    .prompt()?
            } else {
                let mut prompt = Text::new("Value?");
                if let Some(current) = current_plaintext_value {
                    prompt = prompt.with_default(current);
                }
                prompt.prompt()?
            }
        }
    };

    // Validate value against schema constraints
    if let Some(ref schema) = schema {
        if let Some(schema_entry) = schema.get(&key) {
            let errors = dotenv::validate_value_against_constraints(&key, &value, schema_entry);
            let real_errors: Vec<_> = errors.iter()
                .filter(|e| e.severity == dotenv::Severity::Error)
                .collect();
            if !real_errors.is_empty() {
                for err in &real_errors {
                    eprintln!("  {} {}", "!".red().bold(), err);
                }
                return Err("Value violates schema constraints".into());
            }
            for warn in errors.iter().filter(|e| e.severity == dotenv::Severity::Warning) {
                eprintln!("  {} {}", "!".yellow().bold(), warn);
            }
        }
    }

    // Build directives for this variable
    let mut new_directives: Vec<dotenv::Line> = Vec::new();
    let mut schema_directives: Vec<(String, Option<String>)> = Vec::new();
    let mut new_is_encrypted = false;

    let has_encrypt_flag = sub.get_flag("encrypt");
    let has_plaintext_flag = sub.get_flag("plaintext");
    let type_arg = sub.get_one::<String>("type");
    let push_arg = sub.get_one::<String>("push");

    if key_in_schema {
        // Key already in schema — no directive prompts needed, just update value
        // Determine encryption from schema
        let schema_entry = schema.as_ref().unwrap().get(&key).unwrap();
        let has_schema_encrypt = schema_entry.has_directive("encrypt");
        let has_schema_plaintext = schema_entry.has_directive("plaintext");
        if has_schema_encrypt {
            new_is_encrypted = true;
        } else if has_schema_plaintext {
            new_is_encrypted = false;
        } else {
            new_is_encrypted = file_default_encrypt;
        }
        // No directives go inline in .sec
    } else if schema.is_some() {
        // Schema exists but key is new — prompt for directives (or auto-detect with -y), write to schema
        if interactive {
            new_directives = helpers::prompt_variable_directives(&key, &value, file_default_encrypt, None)?;
        } else if auto_yes {
            // Auto-detect directives like import -y
            let is_secret = helpers::looks_like_secret(&key);
            if file_default_encrypt {
                if !is_secret {
                    new_directives.push(dotenv::Line::Directive { name: "plaintext".to_string(), value: None });
                }
            } else if is_secret {
                new_directives.push(dotenv::Line::Directive { name: "encrypt".to_string(), value: None });
            }
            let type_name = match helpers::guess_type(&value) {
                1 => "number",
                2 => "boolean",
                _ => "string",
            };
            new_directives.push(dotenv::Line::Directive { name: "type".to_string(), value: Some(type_name.to_string()) });
        } else {
            if has_encrypt_flag {
                new_directives.push(dotenv::Line::Directive { name: "encrypt".to_string(), value: None });
            } else if has_plaintext_flag {
                new_directives.push(dotenv::Line::Directive { name: "plaintext".to_string(), value: None });
            }
            if let Some(t) = type_arg {
                new_directives.push(dotenv::Line::Directive { name: "type".to_string(), value: Some(t.clone()) });
            }
            if let Some(p) = push_arg {
                new_directives.push(dotenv::Line::Directive { name: "push".to_string(), value: Some(p.clone()) });
            }
        }

        // Determine encryption from the directives we just built
        let has_explicit_encrypt = new_directives.iter()
            .any(|l| matches!(l, dotenv::Line::Directive { name: n, .. } if n == "encrypt"));
        let has_explicit_plaintext = new_directives.iter()
            .any(|l| matches!(l, dotenv::Line::Directive { name: n, .. } if n == "plaintext"));
        if has_explicit_encrypt {
            new_is_encrypted = true;
        } else if has_explicit_plaintext {
            new_is_encrypted = false;
        } else {
            new_is_encrypted = file_default_encrypt;
        }

        // Move directives to schema, not inline in .sec
        for dir in &new_directives {
            if let dotenv::Line::Directive { name, value } = dir {
                schema_directives.push((name.clone(), value.clone()));
            }
        }
        new_directives.clear(); // Don't write directives inline in .sec

        // Add to schema and write back
        if let Some(ref mut s) = schema {
            s.insert(dotenv::SchemaEntry {
                directives: schema_directives,
                key: key.clone(),
            });
            let schema_output = dotenv::schema_to_string(s);
            dotsec::write_sec_file(schema_path.as_ref().unwrap(), &schema_output)?;
        }
    } else {
        // No schema — directives inline in .sec
        if interactive {
            new_directives = helpers::prompt_variable_directives(&key, &value, file_default_encrypt, None)?;

            let has_explicit_encrypt = new_directives.iter()
                .any(|l| matches!(l, dotenv::Line::Directive { name: n, .. } if n == "encrypt"));
            let has_explicit_plaintext = new_directives.iter()
                .any(|l| matches!(l, dotenv::Line::Directive { name: n, .. } if n == "plaintext"));
            if has_explicit_encrypt {
                new_is_encrypted = true;
            } else if has_explicit_plaintext {
                new_is_encrypted = false;
            } else {
                new_is_encrypted = file_default_encrypt;
            }
        } else if auto_yes && !has_encrypt_flag && !has_plaintext_flag && type_arg.is_none() {
            // Auto-detect directives like import -y
            let is_secret = helpers::looks_like_secret(&key);
            if file_default_encrypt {
                if !is_secret {
                    new_directives.push(dotenv::Line::Directive { name: "plaintext".to_string(), value: None });
                }
                new_is_encrypted = is_secret || file_default_encrypt;
            } else if is_secret {
                new_is_encrypted = true;
                new_directives.push(dotenv::Line::Directive { name: "encrypt".to_string(), value: None });
            } else {
                new_is_encrypted = false;
            }
            let type_name = match helpers::guess_type(&value) {
                1 => "number",
                2 => "boolean",
                _ => "string",
            };
            new_directives.push(dotenv::Line::Directive { name: "type".to_string(), value: Some(type_name.to_string()) });
        } else {
            if has_encrypt_flag {
                new_is_encrypted = true;
                new_directives.push(dotenv::Line::Directive { name: "encrypt".to_string(), value: None });
            } else if has_plaintext_flag {
                new_directives.push(dotenv::Line::Directive { name: "plaintext".to_string(), value: None });
            } else {
                new_is_encrypted = file_default_encrypt;
            }

            if let Some(t) = type_arg {
                new_directives.push(dotenv::Line::Directive { name: "type".to_string(), value: Some(t.clone()) });
            }

            if let Some(p) = push_arg {
                new_directives.push(dotenv::Line::Directive { name: "push".to_string(), value: Some(p.clone()) });
            }
        }
    }

    let needs_kms = new_is_encrypted || old_was_encrypted;

    if needs_kms {
        // Decrypt → modify → re-encrypt (full KMS round trip)
        let mut lines = with_progress("Decrypting...", dotsec::decrypt_sec_to_lines(sec_file, encryption_engine)).await?;

        let existing_pos = lines.iter().position(|l| matches!(l, dotenv::Line::Kv { key: k, .. } if k == &key));
        let kv_line = dotenv::Line::Kv { key: key.clone(), value, quote_type: dotenv::QuoteType::Double };
        let action;

        if let Some(kv_pos) = existing_pos {
            let directive_start = find_directive_start(&lines, kv_pos);
            lines.drain(directive_start..=kv_pos);

            let mut insert = new_directives;
            if !insert.is_empty() {
                insert.push(dotenv::Line::Newline);
            }
            insert.push(kv_line);
            for (i, line) in insert.into_iter().enumerate() {
                lines.insert(directive_start + i, line);
            }
            action = "Updated";
        } else {
            append_entry(&mut lines, new_directives, kv_line);
            action = "Added";
        }

        with_progress("Encrypting...", dotsec::encrypt_lines_to_sec(&lines, sec_file, encryption_engine)).await?;
        println!("{} {} {} in {}", "✓".green(), action, key.bold(), sec_file);
    } else {
        // Plaintext — modify raw .sec lines directly, no KMS needed
        let mut lines = raw_lines;
        let existing_pos = lines.iter().position(|l| matches!(l, dotenv::Line::Kv { key: k, .. } if k == &key));
        let kv_line = dotenv::Line::Kv { key: key.clone(), value, quote_type: dotenv::QuoteType::Double };
        let action;

        if let Some(kv_pos) = existing_pos {
            let directive_start = find_directive_start(&lines, kv_pos);
            lines.drain(directive_start..=kv_pos);

            let mut insert = new_directives;
            if !insert.is_empty() {
                insert.push(dotenv::Line::Newline);
            }
            insert.push(kv_line);
            for (i, line) in insert.into_iter().enumerate() {
                lines.insert(directive_start + i, line);
            }
            action = "Updated";
        } else {
            // Insert before __DOTSEC__ if it exists, otherwise append
            let dotsec_pos = find_dotsec_block_start(&lines);
            if let Some(pos) = dotsec_pos {
                // Insert before the __DOTSEC__ block
                let mut insert = vec![dotenv::Line::Newline];
                insert.extend(new_directives);
                insert.push(dotenv::Line::Newline);
                insert.push(kv_line);
                insert.push(dotenv::Line::Newline);
                for (i, line) in insert.into_iter().enumerate() {
                    lines.insert(pos + i, line);
                }
            } else {
                append_entry(&mut lines, new_directives, kv_line);
            }
            action = "Added";
        }

        let output = dotenv::lines_to_string(&lines);
        dotsec::write_sec_file(sec_file, &output)?;
        println!("{} {} {} in {}", "✓".green(), action, key.bold(), sec_file);
    }

    Ok(())
}

/// Find the index where directives for a KV at `kv_pos` start.
fn find_directive_start(lines: &[dotenv::Line], kv_pos: usize) -> usize {
    let mut start = kv_pos;
    while start > 0 {
        match &lines[start - 1] {
            dotenv::Line::Directive { .. } => start -= 1,
            dotenv::Line::Newline => {
                if start >= 2 {
                    if let dotenv::Line::Directive { .. } = &lines[start - 2] {
                        start -= 1;
                        continue;
                    }
                }
                break;
            }
            _ => break,
        }
    }
    start
}

/// Append a new entry (directives + KV) to the end of lines.
fn append_entry(lines: &mut Vec<dotenv::Line>, directives: Vec<dotenv::Line>, kv: dotenv::Line) {
    if !lines.is_empty() {
        let last_is_newline = matches!(lines.last(), Some(dotenv::Line::Newline));
        if !last_is_newline {
            lines.push(dotenv::Line::Newline);
        }
        lines.push(dotenv::Line::Newline);
    }

    if !directives.is_empty() {
        lines.extend(directives);
        lines.push(dotenv::Line::Newline);
    }
    lines.push(kv);
    lines.push(dotenv::Line::Newline);
}

/// Find the start of the __DOTSEC__ or __DOTSEC_KEY__ block (comment + KV).
/// Returns the position of the comment or the newline before the block.
fn find_dotsec_block_start(lines: &[dotenv::Line]) -> Option<usize> {
    // Find the __DOTSEC__ or __DOTSEC_KEY__ KV
    let dotsec_kv = lines.iter().position(|l| matches!(l, dotenv::Line::Kv { key: k, .. } if k == "__DOTSEC__" || k == "__DOTSEC_KEY__"))?;

    // Walk back to find the managed comment
    let mut start = dotsec_kv;
    while start > 0 {
        match &lines[start - 1] {
            dotenv::Line::Comment { text: c } if c.contains("do not edit the line below") => {
                start -= 1;
                // Also grab the newline before the comment
                if start > 0 && matches!(lines[start - 1], dotenv::Line::Newline) {
                    start -= 1;
                }
                break;
            }
            dotenv::Line::Newline => {
                start -= 1;
            }
            _ => break,
        }
    }
    Some(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::{Line, QuoteType};

    // --- find_directive_start ---

    #[test]
    fn find_directive_start_no_directives() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(find_directive_start(&lines, 0), 0);
    }

    #[test]
    fn find_directive_start_one_directive() {
        let lines = vec![
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Newline,
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(find_directive_start(&lines, 2), 0);
    }

    #[test]
    fn find_directive_start_multiple_directives() {
        let lines = vec![
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Directive { name: "type".into(), value: Some("string".into()) },
            Line::Newline,
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(find_directive_start(&lines, 3), 0);
    }

    #[test]
    fn find_directive_start_stops_at_comment() {
        let lines = vec![
            Line::Comment { text: "# some comment".into() },
            Line::Newline,
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Newline,
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(find_directive_start(&lines, 4), 2);
    }

    #[test]
    fn find_directive_start_stops_at_other_kv() {
        let lines = vec![
            Line::Kv { key: "OTHER".into(), value: "val".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Newline,
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Newline,
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
        ];
        assert_eq!(find_directive_start(&lines, 5), 3);
    }

    // --- find_dotsec_block_start ---

    #[test]
    fn find_dotsec_block_no_dotsec() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
            Line::Newline,
        ];
        assert_eq!(find_dotsec_block_start(&lines), None);
    }

    #[test]
    fn find_dotsec_block_with_comment() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Newline,
            Line::Comment { text: "# do not edit the line below, it is managed by dotsec".into() },
            Line::Newline,
            Line::Kv { key: "__DOTSEC__".into(), value: "blob".into(), quote_type: QuoteType::Double },
            Line::Newline,
        ];
        // Should find the newline before the comment (index 2)
        assert_eq!(find_dotsec_block_start(&lines), Some(2));
    }

    #[test]
    fn find_dotsec_block_without_comment() {
        let lines = vec![
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double },
            Line::Newline,
            Line::Newline,
            Line::Kv { key: "__DOTSEC__".into(), value: "blob".into(), quote_type: QuoteType::Double },
            Line::Newline,
        ];
        // Should walk back past newlines
        assert_eq!(find_dotsec_block_start(&lines), Some(1));
    }

    // --- append_entry ---

    #[test]
    fn append_entry_to_empty() {
        let mut lines: Vec<Line> = Vec::new();
        let kv = Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double };
        append_entry(&mut lines, vec![], kv);
        assert_eq!(lines.len(), 2); // KV + Newline
        assert!(matches!(&lines[0], Line::Kv { key: k, .. } if k == "FOO"));
        assert!(matches!(&lines[1], Line::Newline));
    }

    #[test]
    fn append_entry_with_directives() {
        let mut lines: Vec<Line> = Vec::new();
        let directives = vec![
            Line::Directive { name: "encrypt".into(), value: None },
            Line::Directive { name: "type".into(), value: Some("string".into()) },
        ];
        let kv = Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::Double };
        append_entry(&mut lines, directives, kv);
        // directives + newline + KV + newline
        assert_eq!(lines.len(), 5);
        assert!(matches!(&lines[0], Line::Directive { name: n, value: None } if n == "encrypt"));
        assert!(matches!(&lines[1], Line::Directive { name: n, value: Some(_) } if n == "type"));
        assert!(matches!(&lines[2], Line::Newline));
        assert!(matches!(&lines[3], Line::Kv { key: k, .. } if k == "FOO"));
        assert!(matches!(&lines[4], Line::Newline));
    }

    #[test]
    fn append_entry_adds_blank_line_separator() {
        let mut lines = vec![
            Line::Kv { key: "EXISTING".into(), value: "val".into(), quote_type: QuoteType::Double },
            Line::Newline,
        ];
        let kv = Line::Kv { key: "NEW".into(), value: "val".into(), quote_type: QuoteType::Double };
        append_entry(&mut lines, vec![], kv);
        // existing KV + newline + blank line + new KV + newline
        assert_eq!(lines.len(), 5);
        assert!(matches!(&lines[2], Line::Newline)); // blank separator
        assert!(matches!(&lines[3], Line::Kv { key: k, .. } if k == "NEW"));
    }

    #[test]
    fn append_entry_adds_newline_if_missing() {
        let mut lines = vec![
            Line::Kv { key: "EXISTING".into(), value: "val".into(), quote_type: QuoteType::Double },
        ];
        let kv = Line::Kv { key: "NEW".into(), value: "val".into(), quote_type: QuoteType::Double };
        append_entry(&mut lines, vec![], kv);
        // existing KV + added newline + blank line + new KV + newline
        assert_eq!(lines.len(), 5);
        assert!(matches!(&lines[1], Line::Newline)); // added
        assert!(matches!(&lines[2], Line::Newline)); // blank separator
    }

    // --- Schema validation integration tests ---

    #[test]
    fn set_value_rejected_by_schema_constraints() {
        // Create a SchemaEntry with @type=number @min=0 @max=100
        let schema_entry = dotenv::SchemaEntry {
            directives: vec![
                ("type".into(), Some("number".into())),
                ("min".into(), Some("0".into())),
                ("max".into(), Some("100".into())),
            ],
            key: "PORT".into(),
        };
        let errors = dotenv::validate_value_against_constraints("PORT", "999", &schema_entry);
        let real_errors: Vec<_> = errors.iter()
            .filter(|e| e.severity == dotenv::Severity::Error)
            .collect();
        assert!(!real_errors.is_empty(), "should reject value exceeding max");
        assert!(real_errors[0].message.contains("greater than maximum"));
    }

    #[test]
    fn set_value_accepted_by_schema_constraints() {
        let schema_entry = dotenv::SchemaEntry {
            directives: vec![
                ("type".into(), Some("number".into())),
                ("min".into(), Some("0".into())),
                ("max".into(), Some("100".into())),
            ],
            key: "PORT".into(),
        };
        let errors = dotenv::validate_value_against_constraints("PORT", "50", &schema_entry);
        let real_errors: Vec<_> = errors.iter()
            .filter(|e| e.severity == dotenv::Severity::Error)
            .collect();
        assert!(real_errors.is_empty(), "should accept valid value: {:?}", real_errors);
    }

    #[test]
    fn set_value_rejected_by_not_empty_constraint() {
        let schema_entry = dotenv::SchemaEntry {
            directives: vec![
                ("type".into(), Some("string".into())),
                ("not-empty".into(), None),
            ],
            key: "NAME".into(),
        };
        let errors = dotenv::validate_value_against_constraints("NAME", "", &schema_entry);
        let real_errors: Vec<_> = errors.iter()
            .filter(|e| e.severity == dotenv::Severity::Error)
            .collect();
        assert_eq!(real_errors.len(), 1);
        assert!(real_errors[0].message.contains("must not be empty"));
    }

    #[test]
    fn set_value_rejected_by_enum_constraint() {
        let schema_entry = dotenv::SchemaEntry {
            directives: vec![
                ("type".into(), Some("enum(\"dev\", \"prod\")".into())),
            ],
            key: "NODE_ENV".into(),
        };
        let errors = dotenv::validate_value_against_constraints("NODE_ENV", "staging", &schema_entry);
        let real_errors: Vec<_> = errors.iter()
            .filter(|e| e.severity == dotenv::Severity::Error)
            .collect();
        assert_eq!(real_errors.len(), 1);
        assert!(real_errors[0].message.contains("not in enum"));
    }

    #[test]
    fn set_value_deprecated_produces_warning() {
        let schema_entry = dotenv::SchemaEntry {
            directives: vec![
                ("type".into(), Some("string".into())),
                ("deprecated".into(), Some("Use NEW_KEY instead".into())),
            ],
            key: "OLD_KEY".into(),
        };
        let errors = dotenv::validate_value_against_constraints("OLD_KEY", "value", &schema_entry);
        let warnings: Vec<_> = errors.iter()
            .filter(|e| e.severity == dotenv::Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("deprecated"));
        assert!(warnings[0].message.contains("Use NEW_KEY instead"));
    }
}
