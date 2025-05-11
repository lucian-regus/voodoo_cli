use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "voodoo_cli", about = "CLI for Voodoo AV", version)]
pub struct Cli {
    #[arg(long)]
    pub load: Option<String>,

    #[arg(long)]
    pub unload: Option<String>,

    #[arg(long)]
    pub list: bool,

    #[arg(long = "ip-allow")]
    pub ip_allow: Option<String>,
}