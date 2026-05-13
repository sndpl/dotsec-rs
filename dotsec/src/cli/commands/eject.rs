use clap::{arg, Command};
use colored::Colorize;

use crate::cli::helpers::{extract_schema_from_lines, with_progress};
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("extract-schema")
        .alias("eject")
        .about("Extract per-key directives from .sec into a dotsec.schema file")
        .arg(
            arg!(-o --output <FILE> "Output schema file path")
                .required(false)
                .default_value("dotsec.schema"),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(sub) = matches.subcommand_matches("extract-schema") {
        let sec_file = default_options.sec_file;
        let output = sub.get_one::<String>("output").unwrap();

        // Refuse if schema file already exists
        if std::path::Path::new(output).exists() {
            return Err(format!(
                "{} already exists. Delete it first or use --output to specify a different path.",
                output
            ).into());
        }

        // Parse the .sec file (decrypt if needed)
        let lines = with_progress(
            "Decrypting...",
            dotsec::decrypt_sec_to_lines(sec_file, &default_options.encryption_engine),
        )
        .await?;

        // Extract schema directives from lines
        let (stripped_lines, schema_entries) = extract_schema_from_lines(&lines);

        // Filter out entries with no directives from schema (bare keys with no constraints)
        let has_directives = schema_entries.iter().any(|e| !e.directives.is_empty());
        if !has_directives {
            println!(
                "{} No per-key directives found in {}. Nothing to eject.",
                "ℹ".blue(),
                sec_file
            );
            return Ok(());
        }
        let file_config_lines: Vec<_> = lines.iter().filter(|l| {
            matches!(l, dotenv::Line::Directive { name, .. } if dotenv::SCHEMA_FILE_LEVEL_DIRECTIVES.contains(&name.as_str()))
        }).collect();

        let mut schema_directives_for_file: Vec<(String, Option<String>)> = Vec::new();
        for line in &file_config_lines {
            if let dotenv::Line::Directive { name, value } = line {
                schema_directives_for_file.push((name.clone(), value.clone()));
            }
        }

        // Build the schema
        let mut schema = dotenv::Schema::default();
        schema.extend(schema_entries);

        // Write schema file
        let mut schema_output = String::new();
        if !schema_directives_for_file.is_empty() {
            schema_output.push_str("# ");
            for (i, (name, value)) in schema_directives_for_file.iter().enumerate() {
                if i > 0 {
                    schema_output.push(' ');
                }
                match value {
                    Some(v) => schema_output.push_str(&format!("@{}={}", name, v)),
                    None => schema_output.push_str(&format!("@{}", name)),
                }
            }
            schema_output.push_str("\n\n");
        }
        schema_output.push_str(&dotenv::schema_to_string(&schema));
        dotsec::write_sec_file(output, &schema_output)?;

        // Rewrite the .sec file without schema directives
        let new_content = dotenv::lines_to_string(&stripped_lines);
        // Re-encrypt if the file was encrypted
        if matches!(default_options.encryption_engine, dotsec::EncryptionEngine::Aws(_)) {
            let new_lines = dotenv::parse_dotenv(&new_content)?;
            dotsec::encrypt_lines_to_sec(&new_lines, sec_file, &default_options.encryption_engine)
                .await?;
        } else {
            dotsec::write_sec_file(sec_file, &new_content)?;
        }

        let entry_count = schema.iter().filter(|(_, e)| !e.directives.is_empty()).count();
        println!(
            "{} Extracted {} entries into {}",
            "✓".green(),
            entry_count,
            output
        );
        println!(
            "{} Stripped per-key directives from {}",
            "✓".green(),
            sec_file
        );
    }
    Ok(())
}
