mod commands;
mod cli;

use clap::{Parser};
use crate::commands::control::{list_plugins, load_plugin, unload_plugin};
use cli::Cli;

pub fn run_command(cli: Cli) {
    match cli {
        Cli { load: Some(plugin), .. } => load_plugin(&plugin),
        Cli { unload: Some(plugin), .. } => unload_plugin(&plugin),
        Cli { list: true, .. } => list_plugins(),
        Cli { ip_allow: Some(ip), .. } => {
        },
        _ => eprintln!("No valid command. Use --help."),
    }
}

fn main() {
    let cli = Cli::parse();

    run_command(cli);
}
