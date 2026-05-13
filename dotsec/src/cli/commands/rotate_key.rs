use base64::Engine as _;
use clap::Command;
use colored::Colorize;

use crate::cli::helpers::with_progress;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("rotate-key")
        .about("Generate a new DEK and re-encrypt all values")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("rotate-key").is_none() {
        return Ok(());
    }

    let sec_file = default_options.sec_file;
    let encryption_engine = &default_options.encryption_engine;

    // Decrypt all values with the old DEK
    let lines = with_progress(
        "Decrypting with old key...",
        dotsec::decrypt_sec_to_lines(sec_file, encryption_engine),
    )
    .await?;

    // Generate a new DEK and wrap it with the appropriate provider
    let (new_dek, new_wrapped_dek) = match encryption_engine {
        dotsec::EncryptionEngine::Aws(opts) => {
            let key_id = opts.key_id.as_deref().ok_or("AWS key_id is required")?;
            aws::generate_data_key(key_id, opts.region.as_deref()).await?
        }
        dotsec::EncryptionEngine::Local(opts) => {
            let private_key = crypto::local::load_private_key(sec_file, opts.key_file.as_deref())?;
            let recipient = crypto::local::recipient_from_identity(&private_key)?;
            let dek = crypto::generate_dek();
            let wrapped = crypto::local::wrap_dek(&dek, &recipient)?;
            (dek, wrapped)
        }
        dotsec::EncryptionEngine::None => return Err("Encryption engine is required".into()),
    };
    let new_wrapped_b64 =
        base64::engine::general_purpose::STANDARD.encode(&new_wrapped_dek);

    // Re-encrypt: build new lines with the new DEK
    let entries = dotenv::lines_to_entries(&lines);
    let mut sec_lines: Vec<dotenv::Line> = Vec::new();

    for line in &lines {
        match line {
            dotenv::Line::Kv { key, value, quote_type } => {
                let entry = entries.iter().find(|e| e.key == *key);
                let should_encrypt = entry.is_some_and(|e| e.has_directive("encrypt"));

                if should_encrypt {
                    let encrypted = crypto::encrypt_value(value, &new_dek, key)?;
                    sec_lines.push(dotenv::Line::Kv { key: key.clone(), value: encrypted, quote_type: quote_type.clone() });
                } else {
                    sec_lines.push(line.clone());
                }
            }
            other => sec_lines.push(other.clone()),
        }
    }

    // new_dek auto-zeroizes when dropped

    // Append new __DOTSEC_KEY__
    let last_is_newline = matches!(sec_lines.last(), Some(dotenv::Line::Newline));
    if !sec_lines.is_empty() && !last_is_newline {
        sec_lines.push(dotenv::Line::Newline);
    }
    sec_lines.push(dotenv::Line::Newline);
    sec_lines.push(dotenv::Line::Comment {
        text: "# do not edit the line below, it is managed by dotsec".to_string(),
    });
    sec_lines.push(dotenv::Line::Newline);
    sec_lines.push(dotenv::Line::Kv {
        key: "__DOTSEC_KEY__".to_string(),
        value: new_wrapped_b64,
        quote_type: dotenv::QuoteType::Double,
    });
    sec_lines.push(dotenv::Line::Newline);

    let output = dotenv::lines_to_string(&sec_lines);
    dotsec::write_sec_file(sec_file, &output)?;

    println!(
        "\n{} Key rotated — all values in {} re-encrypted with new DEK",
        "✓".green(),
        sec_file.bold()
    );

    Ok(())
}
