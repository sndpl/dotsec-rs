use clap::{Arg, ArgAction, Command};
use colored::Colorize;

use crate::cli::helpers::with_progress;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("push")
        .about("Push variables with @push directives to AWS SSM and/or Secrets Manager")
        .arg(
            Arg::new("keys")
                .help("Specific variable names to push (default: all with @push)")
                .num_args(0..),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .action(ArgAction::SetTrue)
                .help("Show what would be pushed without actually pushing"),
        )
        .arg(
            Arg::new("yes")
                .short('y')
                .long("yes")
                .action(ArgAction::SetTrue)
                .help("Skip confirmation prompt"),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sub = match matches.subcommand_matches("push") {
        Some(m) => m,
        None => return Ok(()),
    };

    let sec_file = default_options.sec_file;
    let encryption_engine = &default_options.encryption_engine;
    let dry_run = sub.get_flag("dry-run");
    let auto_yes = sub.get_flag("yes");

    let filter_keys: Option<Vec<&str>> = sub
        .get_many::<String>("keys")
        .map(|vals| vals.map(|s| s.as_str()).collect());

    // Extract region from encryption engine
    let region = match encryption_engine {
        dotsec::EncryptionEngine::Aws(opts) => opts.region.as_deref(),
        dotsec::EncryptionEngine::Local(_) | dotsec::EncryptionEngine::None => None,
    };

    // Decrypt .sec
    let lines = with_progress(
        "Decrypting...",
        dotsec::decrypt_sec_to_lines(sec_file, encryption_engine),
    )
    .await?;

    let entries = dotenv::lines_to_entries(&lines);

    // Validate entries against schema and warn (non-blocking)
    if let Some(ref schema_path) = default_options.schema_path {
        let schema_content = std::fs::read_to_string(schema_path)?;
        let schema = dotenv::parse_schema(&schema_content)?;
        let validation_errors = dotenv::validate_entries_against_schema(&entries, &schema);
        if !validation_errors.is_empty() {
            let warning_count = validation_errors.len();
            eprintln!(
                "{} {} schema validation warning(s):",
                "⚠".yellow(),
                warning_count
            );
            for err in &validation_errors {
                eprintln!("  {} {}", "•".yellow(), err);
            }
            eprintln!();
        }
    }

    // Filter to entries with @push directives
    let push_entries: Vec<_> = entries
        .iter()
        .filter(|e| {
            if e.push_targets().is_empty() {
                return false;
            }
            match &filter_keys {
                Some(keys) => keys.contains(&e.key.as_str()),
                None => true,
            }
        })
        .collect();

    if push_entries.is_empty() {
        if filter_keys.is_some() {
            println!("No matching variables with @push directives found.");
        } else {
            println!("No variables with @push directives found.");
        }
        return Ok(());
    }

    // Build push plan
    let mut plan: Vec<PushAction> = Vec::new();

    for entry in &push_entries {
        let is_encrypted = entry.has_directive("encrypt");
        // lines_to_entries() already injects @encrypt when @default-encrypt is set

        for target in entry.push_targets() {
            match target {
                dotenv::PushTarget::AwsSsm(opts) => {
                    let path = opts
                        .path
                        .as_deref()
                        .unwrap_or(&entry.key)
                        .to_string();
                    validate_push_path(&path, &entry.key)?;
                    plan.push(PushAction {
                        key: entry.key.clone(),
                        value: entry.value.clone(),
                        target: "SSM".to_string(),
                        path,
                        secure: is_encrypted,
                    });
                }
                dotenv::PushTarget::AwsSecretsManager(opts) => {
                    let path = opts
                        .path
                        .as_deref()
                        .unwrap_or(&entry.key)
                        .to_string();
                    validate_push_path(&path, &entry.key)?;
                    plan.push(PushAction {
                        key: entry.key.clone(),
                        value: entry.value.clone(),
                        target: "SecretsManager".to_string(),
                        path,
                        secure: false, // SecretsManager handles its own encryption
                    });
                }
            }
        }
    }

    // Print plan
    println!();
    for action in &plan {
        let type_label = if action.target == "SSM" {
            if action.secure {
                "SecureString"
            } else {
                "String"
            }
        } else {
            "SecretString"
        };
        println!(
            "  {} {} → {} {} ({})",
            if dry_run { "○" } else { "●" }.dimmed(),
            action.key.bold(),
            action.target.cyan(),
            action.path.dimmed(),
            type_label.dimmed(),
        );
    }
    println!();

    if dry_run {
        println!(
            "{} Dry run: {} actions would be performed",
            "→".dimmed(),
            plan.len()
        );
        return Ok(());
    }

    if !auto_yes {
        let proceed = inquire::Confirm::new(&format!("Push {} values?", plan.len()))
            .with_default(false)
            .prompt()?;
        if !proceed {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Execute pushes
    let total = plan.len();
    let mut success = 0;
    let mut errors: Vec<(String, String)> = Vec::new();

    for (i, action) in plan.iter().enumerate() {
        let label = format!(
            "[{}/{}] Pushing {} → {} {}",
            i + 1,
            total,
            action.key,
            action.target,
            action.path
        );

        let result: Result<(), Box<dyn std::error::Error>> = if action.target == "SSM" {
            with_progress(
                &label,
                aws::push_to_ssm(&action.path, &action.value, action.secure, region),
            )
            .await
            .map_err(|e| e.into())
        } else {
            with_progress(
                &label,
                aws::push_to_secrets_manager(&action.path, &action.value, region),
            )
            .await
            .map_err(|e| e.into())
        };

        match result {
            Ok(()) => success += 1,
            Err(e) => {
                errors.push((action.key.clone(), e.to_string()));
            }
        }
    }

    // Summary
    println!();
    if errors.is_empty() {
        println!(
            "{} Pushed {} values successfully",
            "✓".green(),
            success
        );
    } else {
        println!(
            "{} Pushed {}/{} values ({} failed)",
            "!".yellow().bold(),
            success,
            total,
            errors.len()
        );
        for (key, err) in &errors {
            println!("  {} {}: {}", "✗".red(), key.bold(), err);
        }
    }

    if !errors.is_empty() {
        return Err(format!("{} of {} push operations failed", errors.len(), plan.len()).into());
    }

    Ok(())
}

struct PushAction {
    key: String,
    value: String,
    target: String,
    path: String,
    secure: bool,
}

impl Drop for PushAction {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
    }
}

fn validate_push_path(path: &str, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    if path.is_empty() {
        return Err(format!("push path for '{}' must not be empty", key).into());
    }
    if path.len() > 2048 {
        return Err(format!(
            "push path for '{}' exceeds maximum length of 2048 chars (got {})",
            key,
            path.len()
        )
        .into());
    }
    if path.split('/').any(|seg| seg == "..") {
        return Err(format!(
            "push path for '{}' must not contain '..' (path traversal)",
            key
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_path_rejects_empty() {
        assert!(validate_push_path("", "KEY").is_err());
    }

    #[test]
    fn push_path_rejects_traversal() {
        assert!(validate_push_path("/app/../etc/passwd", "KEY").is_err());
        assert!(validate_push_path("../secret", "KEY").is_err());
    }

    #[test]
    fn push_path_allows_double_dots_in_names() {
        assert!(validate_push_path("/app/v2..beta/config", "KEY").is_ok());
        assert!(validate_push_path("/app/my..param", "KEY").is_ok());
    }

    #[test]
    fn push_path_rejects_too_long() {
        let long = "/".repeat(2049);
        assert!(validate_push_path(&long, "KEY").is_err());
    }

    #[test]
    fn push_path_accepts_valid() {
        assert!(validate_push_path("/myapp/prod/DB_URL", "KEY").is_ok());
        assert!(validate_push_path("DB_URL", "KEY").is_ok());
    }

    #[test]
    fn push_path_at_length_limit_ok() {
        let path = "a".repeat(2048);
        assert!(validate_push_path(&path, "KEY").is_ok());
    }
}
