use self::commands::{create_command, diff, eject, export, format, header, import, init, license, migrate, push, remove_directives, rotate_key, run, schema, set, show, validate};
use crate::default_options::DefaultOptions;
use dotsec::EncryptionEngine;
use log::debug;
use std::error::Error;
use std::time::Duration;

pub mod commands;
pub mod helpers;

const BANNER: &str = r#"       __      __
  ____/ /___  / /_________  _____
 / __  / __ \/ __/ ___/ _ \/ ___/
/ /_/ / /_/ / /_(__  )  __/ /__
\__,_/\____/\__/____/\___/\___/"#;

async fn show_banner() {
    use chromakopia::{animate, presets};

    // Print ASCII art banner with static dark_n_stormy gradient
    println!("{}", presets::dark_n_stormy().multiline(BANNER));
    println!();

    // Animate tagline with mist glow below
    animate::Sequence::new("  Your .env, encrypted and version-controlled.")
        .glow(presets::mist(), Duration::from_secs(3))
        .fade_to_foreground(Duration::from_millis(500))
        .run(1.0)
        .await;

    println!();
    println!("  Run `dotsec --help` for usage.");
    println!();
}

pub async fn parse_args() -> Result<(), Box<dyn Error>> {
    let command = create_command();
    let matches = command.get_matches();

    if let Some(secs) = matches.get_one::<f64>("animation-delay").copied() {
        if secs > 0.0 && secs.is_finite() {
            helpers::set_animation_delay(Duration::from_secs_f64(secs));
        }
    }

    // No subcommand — show animated banner
    if matches.subcommand_name().is_none() {
        show_banner().await;
        return Ok(());
    }

    let is_license = matches.subcommand_matches("license").is_some();
    let is_init = matches.subcommand_matches("init").is_some();
    let is_import = matches.subcommand_matches("import").is_some();
    let is_migrate = matches.subcommand_matches("migrate").is_some();
    let is_diff = matches.subcommand_matches("diff").is_some();
    let is_eject = matches.subcommand_matches("extract-schema").is_some();
    let is_schema = matches.subcommand_matches("schema").is_some();
    let is_set = matches.subcommand_matches("set").is_some();
    let is_run_env = matches
        .subcommand_matches("run")
        .is_some_and(|m| m.contains_id("env-file") && m.get_one::<String>("env-file").is_some());

    // Resolve sec file from CLI arg or default
    let default_sec = ".sec".to_string();
    let sec_file = matches
        .get_one::<String>("sec-file")
        .unwrap_or(&default_sec);

    // Resolve schema path from CLI arg or discovery
    let explicit_schema = matches.get_one::<String>("schema").map(|s| s.as_str());
    let schema_path = dotenv::schema::discover_schema(sec_file, explicit_schema)?;
    debug!("schema_path: {:?}", schema_path);

    // Read config from .sec file directives (if it exists)
    let encryption_engine = if std::path::Path::new(sec_file).exists() {
        let content = std::fs::read_to_string(sec_file)?;
        let lines = dotenv::parse_dotenv(&content)?;
        let file_config = dotenv::extract_file_config(&lines);
        debug!("file_config from {}: {:?}", sec_file, file_config);
        EncryptionEngine::try_from(file_config)?
    } else if is_init || is_import || is_migrate || is_diff || is_eject || is_schema || is_run_env || is_set || is_license {
        debug!("{} does not exist yet or not needed, using defaults", sec_file);
        EncryptionEngine::None
    } else {
        return Err(format!("{} not found. Run `dotsec set KEY value` to create one, or `dotsec import` to migrate from .env.", sec_file).into());
    };

    debug!("sec_file: {}, engine: {:?}", sec_file, encryption_engine);

    let default_options = DefaultOptions {
        encryption_engine,
        sec_file,
        schema_path,
    };

    init::match_args(&matches, &default_options).await?;
    set::match_args(&matches, &default_options).await?;
    import::match_args(&matches, &default_options).await?;
    export::match_args(&matches, &default_options).await?;
    show::match_args(&matches, &default_options).await?;
    run::match_args(&matches, &default_options).await?;
    validate::match_args(&matches, &default_options).await?;
    diff::match_args(&matches, &default_options).await?;
    rotate_key::match_args(&matches, &default_options).await?;
    migrate::match_args(&matches, &default_options).await?;
    push::match_args(&matches, &default_options).await?;
    eject::match_args(&matches, &default_options).await?;
    format::match_args(&matches, &default_options).await?;
    header::match_args(&matches, &default_options).await?;
    remove_directives::match_args(&matches, &default_options).await?;
    schema::match_args(&matches, &default_options).await?;
    license::match_args(&matches, &default_options).await?;

    Ok(())
}
