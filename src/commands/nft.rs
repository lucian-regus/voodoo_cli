use postgres::{Client};
use std::fs::File;
use std::io::{Write, Result};
use std::process::Command;

const NFT_FILE_PATH: &str = "/etc/nftables.conf";
const NFT_TABLE_NAME: &str = "filter";
const NFT_SET_NAME: &str = "blacklisted_ips";
const NFT_CHAIN_NAME: &str = "output_chain";

fn fetch_blacklisted_ips(client: &mut Client) -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(rows) = client.query("SELECT ip_address FROM blacklisted_ip_addresses WHERE allowed_at IS NULL", &[]) {
        for row in rows {
            let ip: String = row.get(0);
            ips.push(ip);
        }
    }
    ips
}

fn generate_nft_file(ips: &[String]) -> Result<()> {
    let mut file = File::create(NFT_FILE_PATH)?;

    writeln!(file, "table inet {} {{", NFT_TABLE_NAME)?;
    writeln!(file, "\tset {} {{", NFT_SET_NAME)?;
    writeln!(file, "\t\ttype ipv4_addr;")?;
    writeln!(file, "\t\tflags interval;")?;

    if !ips.is_empty() {
        writeln!(file, "\t\telements = {{")?;
        for (i, ip) in ips.iter().enumerate() {
            let comma = if i < ips.len() - 1 { "," } else { "" };
            writeln!(file, "\t\t\t{}{}", ip, comma)?;
        }
        writeln!(file, "\t\t}};")?;
    } else {
        writeln!(file, "\t\telements = {{ }};")?;
    }

    writeln!(file, "\t}}\n")?;
    writeln!(file, "\tchain {} {{", NFT_CHAIN_NAME)?;
    writeln!(file, "\t\ttype filter hook output priority 0; policy accept;")?;
    writeln!(file, "\t\tip daddr @{} drop", NFT_SET_NAME)?;
    writeln!(file, "\t}}")?;
    writeln!(file, "}}")?;

    Ok(())
}

pub fn update_nft_ruleset(client: &mut Client) {
    let ips = fetch_blacklisted_ips(client);

    if let Err(e) = generate_nft_file(&ips) {
        eprintln!("Failed to write nftables file: {}", e);
        return;
    }

    let flush = Command::new("sudo")
        .arg("/usr/sbin/nft")
        .arg("flush")
        .arg("ruleset")
        .status();

    let apply = Command::new("sudo")
        .arg("/usr/sbin/nft")
        .arg("-f")
        .arg(NFT_FILE_PATH)
        .status();

    match (flush, apply) {
        (Ok(f), Ok(a)) if f.success() && a.success() => {
            println!("nftables ruleset updated successfully.");
        }
        _ => {
            eprintln!("Failed to apply nftables rules.");
        }
    }
}