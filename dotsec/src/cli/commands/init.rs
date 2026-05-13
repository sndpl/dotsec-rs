use clap::Command;
use colored::Colorize;

use crate::cli::helpers;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("init")
        .about("Initialize a .sec file with encryption config")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("init").is_none() {
        return Ok(());
    }

    let sec_file = default_options.sec_file;

    if std::path::Path::new(sec_file).exists() {
        println!("{} {} already exists, skipping.", "✓".green(), sec_file);
        return Ok(());
    }

    println!("\n{}", "Creating .sec file".bold());

    let config = helpers::prompt_config()?;

    // Validate KMS key alias if provider is AWS
    if config.provider.as_deref() == Some("aws") {
        if let Some(ref key_id) = config.key_id {
            if key_id.starts_with("alias/") {
                let region = config.region.as_deref();
                match aws::check_key_alias(key_id, region).await {
                    Ok(Some(arn)) => {
                        println!("{} Key found: {}", "✓".green(), arn.dimmed());
                    }
                    Ok(None) => {
                        let region_label = region.unwrap_or("default");
                        let create = inquire::Confirm::new(&format!(
                            "{} not found in {}. Create it?",
                            key_id, region_label
                        ))
                        .with_default(true)
                        .prompt()?;

                        if create {
                            let arn = aws::create_key_with_alias(key_id, region).await?;
                            println!("{} Created key: {}", "✓".green(), arn.dimmed());
                        } else {
                            println!(
                                "{} Continuing without key — you'll need to create it before encrypting.",
                                "!".yellow().bold()
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "{} Could not verify key: {}",
                            "!".yellow().bold(),
                            e.to_string().dimmed()
                        );
                        println!(
                            "{} Encryption/decryption operations may fail until this is resolved.",
                            "!".yellow().bold()
                        );
                    }
                }
            }
        }
    }

    // Generate keypair for local provider
    if config.provider.as_deref() == Some("local") {
        let key_file = format!("{}.key", sec_file);
        if std::path::Path::new(&key_file).exists() {
            println!("{} {} already exists, reusing existing keypair", "✓".green(), key_file);
        } else {
            let (identity, _) = crypto::local::generate_keypair();
            dotsec::write_sec_file(&key_file, &format!("{}\n", identity))?;
            println!("{} Created {}", "✓".green(), key_file);

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
    }

    let encrypt_all = helpers::resolve_encrypt_default(&config)?;
    let mut lines = dotsec::generate_header();
    lines.push(dotenv::Line::Newline);
    lines.extend(helpers::build_config_directives(&config, encrypt_all));
    lines.push(dotenv::Line::Newline);

    let output = dotenv::lines_to_string(&lines);
    dotsec::write_sec_file(sec_file, &output)?;
    println!("{} Created {}", "✓".green(), sec_file);
    println!(
        "\n{} Run {} to add variables.",
        "→".bold(),
        "dotsec set".cyan()
    );

    Ok(())
}
