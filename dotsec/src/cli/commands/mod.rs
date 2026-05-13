mod base;
pub mod diff;
pub mod eject;
pub mod export;
pub mod format;
pub mod header;
pub mod import;
pub mod init;
pub mod license;
pub mod migrate;
pub mod push;
pub mod remove_directives;
pub mod rotate_key;
pub mod schema;
pub mod run;
pub mod set;
pub mod show;
pub mod validate;

pub fn create_command() -> clap::Command {
    base::command()
        .subcommand(set::command())
        .subcommand(import::command())
        .subcommand(run::command())
        .subcommand(show::command())
        .subcommand(export::command())
        .subcommand(validate::command())
        .subcommand(diff::command())
        .subcommand(eject::command())
        .subcommand(schema::command())
        .subcommand(rotate_key::command())
        .subcommand(init::command())
        .subcommand(format::command())
        .subcommand(header::command())
        .subcommand(remove_directives::command())
        .subcommand(push::command())
        .subcommand(migrate::command())
        .subcommand(license::command())
        .arg_required_else_help(false)
}
