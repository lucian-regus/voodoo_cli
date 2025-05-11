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

    #[arg(long = "check-ip")]
    pub check_ip:  Option<String>,

    #[arg(long = "deny-ip")]
    pub deny_ip:  Option<String>,

    #[arg(long = "allow-ip")]
    pub allow_ip: Option<String>,
}