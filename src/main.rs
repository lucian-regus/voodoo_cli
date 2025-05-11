mod commands;
mod cli;

use clap::{Parser};
use crate::commands::control::{list_plugins, load_plugin, unload_plugin};
use cli::Cli;
use crate::commands::database::{allow_ip, deny_ip, check_ip};

pub fn run_command(cli: Cli) {
    match cli {
        Cli { load: Some(plugin), .. } => load_plugin(&plugin),
        Cli { unload: Some(plugin), .. } => unload_plugin(&plugin),
        Cli { list: true, .. } => list_plugins(),
        Cli { allow_ip: Some(ip), .. } => allow_ip(&ip),
        Cli { deny_ip: Some(ip), .. } => deny_ip(&ip),
        Cli { check_ip: Some(ip), .. } => check_ip(&ip),
        
        _ => eprintln!("No valid command. Use --help."),
    }
}

fn main() {
    let cli = Cli::parse();

    run_command(cli);
}
