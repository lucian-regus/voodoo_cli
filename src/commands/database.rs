use postgres::{Client, NoTls};
use chrono::NaiveDateTime;
use crate::commands::nft::update_nft_ruleset;

const DB_URL: &str = "host=localhost user=voodoo password=DA5VGLB1BWbB82wJ2pv3 dbname=voodoo_av";

pub fn allow_ip(ip: &str) {
    if let Ok(mut client) = Client::connect(DB_URL, NoTls) {
        let check = client.query_opt(
            "SELECT allowed_at FROM blacklisted_ip_addresses WHERE ip_address = $1",
            &[&ip],
        );

        match check {
            Ok(Some(row)) => {
                let allowed_set: Option<NaiveDateTime> = row.get(0);
                if allowed_set.is_some() {
                    println!("IP {} is already allowed.", ip);
                    return;
                }

                let update = client.execute(
                    "UPDATE blacklisted_ip_addresses
                     SET allowed_at = NOW()
                     WHERE ip_address = $1",
                    &[&ip],
                );

                match update {
                    Ok(rows) if rows > 0 => {
                        update_nft_ruleset(&mut client);

                        println!("IP {} allowed now.", ip)
                    },
                    Ok(_) => println!("IP {} not found in DB.", ip),
                    Err(e) => eprintln!("Update error: {}", e),
                }
            }

            Ok(None) => println!("IP {} not found in DB.", ip),
            Err(e) => eprintln!("Query error: {}", e),
        }
    } else {
        eprintln!("Failed to connect to DB.");
    }
}

pub fn deny_ip(ip: &str) {
    if let Ok(mut client) = Client::connect(DB_URL, NoTls) {
        let check = client.query_opt(
            "SELECT allowed_at FROM blacklisted_ip_addresses WHERE ip_address = $1",
            &[&ip],
        );

        match check {
            Ok(Some(row)) => {
                let allowed_set: Option<NaiveDateTime> = row.get(0);
                if allowed_set.is_none() {
                    println!("IP {} is already denied.", ip);
                    return;
                }

                let update = client.execute(
                    "UPDATE blacklisted_ip_addresses
                     SET allowed_at = NULL
                     WHERE ip_address = $1",
                    &[&ip],
                );

                match update {
                    Ok(rows) if rows > 0 => {
                        update_nft_ruleset(&mut client);
                        
                        println!("IP {} denied now.", ip)
                    },
                    Ok(_) => println!("IP {} not found in DB.", ip),
                    Err(e) => eprintln!("Update error: {}", e),
                }
            }
            Ok(None) => println!("IP {} not found in DB.", ip),
            Err(e) => eprintln!("Query error: {}", e),
        }
    } else {
        eprintln!("Failed to connect to DB.");
    }
}

pub fn check_ip(ip: &str) {
    if let Ok(mut client) = Client::connect(DB_URL, NoTls) {
        let check = client.query_opt(
            "SELECT allowed_at FROM blacklisted_ip_addresses WHERE ip_address = $1",
            &[&ip],
        );

        match check {
            Ok(Some(row)) => {
                let allowed_at: Option<NaiveDateTime> = row.get(0);

                let status = if allowed_at.is_some() {
                    "allowed"
                } else {
                    "denied"
                };

                println!("IP {} is {}", ip, status);
            },
            Ok(None) => println!("IP {} not found in DB.", ip),
            Err(e) => eprintln!("Query error: {}", e),
        }
    } else {
        eprintln!("Failed to connect to DB.");
    }
}