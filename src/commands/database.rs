use std::{fs, io};
use std::path::{Path, PathBuf};
use postgres::{Client, NoTls};
use chrono::NaiveDateTime;
use crate::commands::nft::update_nft_ruleset;

const DB_URL: &str = "host=localhost user=voodoo password=DA5VGLB1BWbB82wJ2pv3 dbname=voodoo_av";
const QUARANTINE_DIR: &str = "/var/lib/voodoo/quarantine/";

pub fn check_ip(ip: &str) {
    if let Ok(mut client) = Client::connect(DB_URL, NoTls) {
        let query_result = client.query_opt(
            "SELECT allowed_at FROM blacklisted_ip_addresses WHERE ip_address = $1",
            &[&ip],
        );

        match query_result {
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
pub fn allow_ip(ip: &str) {
    if let Ok(mut client) = Client::connect(DB_URL, NoTls) {
        let query_result = client.query_opt(
            "SELECT allowed_at FROM blacklisted_ip_addresses WHERE ip_address = $1",
            &[&ip],
        );

        match query_result {
            Ok(Some(row)) => {
                let allowed_at: Option<NaiveDateTime> = row.get(0);
                if allowed_at.is_some() {
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
        let query_result = client.query_opt(
            "SELECT allowed_at FROM blacklisted_ip_addresses WHERE ip_address = $1",
            &[&ip],
        );

        match query_result {
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

pub fn check_file(file: &str) {
    if let Ok(mut client) = Client::connect(DB_URL, NoTls) {
        let query_result = client.query(
            "SELECT id, old_name, original_path, detected_by, detected_at, allowed_at FROM malware_detection_log WHERE old_name = $1",
            &[&file],
        );

        match query_result {
            Ok(rows) => {
                if rows.is_empty() {
                    println!("File {} not found in DB.", file);
                } else {
                    println!(
                        "{:<4} | {:<30} | {:<20} | {:<26} | {:<7}",
                        "ID", "Full Path", "Detected By", "Detected At", "Status"
                    );
                    println!("{}", "-".repeat(99));
                    
                    for row in rows {
                        let id: i32 = row.get("id");
                        let old_name: String = row.get("old_name");
                        let original_path: String = row.get("original_path");
                        let detected_by: String = row.get("detected_by");
                        let detected_at: NaiveDateTime = row.get("detected_at");
                        let allowed_at: Option<NaiveDateTime> = row.get("allowed_at");

                        let status = if allowed_at.is_some() {
                            "allowed"
                        } else {
                            "denied"
                        };

                        println!(
                            "{:<4} | {:<30} | {:<20} | {:<26} | {:<7}",
                            id,
                            format!("{}/{}", original_path, old_name),
                            detected_by,
                            detected_at,
                            status
                        );
                    }
                }
            }
            Err(e) => eprintln!("Query error: {}", e),
        }
    } else {
        eprintln!("Failed to connect to DB.");
    }
}
pub fn allow_file(file_id: &i32){
    if let Ok(mut client) = Client::connect(DB_URL, NoTls) {
        let query_result = client.query_opt(
            "SELECT old_name, new_name, original_path, allowed_at FROM malware_detection_log WHERE id = $1",
            &[&file_id],
        );

        match query_result {
            Ok(Some(row)) => {
                let old_name: String = row.get("old_name");
                let original_path: String = row.get("original_path");
                let new_name: String = row.get("new_name");
                let allowed_at: Option<NaiveDateTime> = row.get("allowed_at");

                if allowed_at.is_some() {
                    println!("File {} is already allowed.", format!("{}/{}", original_path, old_name));
                    return;
                }

                let update_query_result = client.execute(
                    "UPDATE malware_detection_log
                     SET allowed_at = NOW()
                     WHERE id = $1",
                    &[&file_id],
                );

                match update_query_result {
                    Ok(rows) if rows > 0 => {
                        let original_path = format!("{}/{}", original_path, old_name);
                        let quarantine_path = format!("{}/{}", QUARANTINE_DIR, new_name);

                        match move_and_rename_file(&quarantine_path, &original_path) {
                            Ok(_) => println!("File {} allowed now.", format!("{}/{}", original_path, old_name)),
                            Err(e) => {
                                let _ = client.execute(
                                        "UPDATE malware_detection_log
                                        SET allowed_at = NULL
                                        WHERE id = $1",
                                        &[&file_id],
                                );
                                eprintln!("Failed to move file: {}", e)
                            },
                        }
                    },
                    Ok(_) => println!("No malware detection log entry found with ID {}.", file_id),
                    Err(e) => eprintln!("Update error: {}", e),
                }
            }

            Ok(None) => println!("No malware detection log entry found with ID {}.", file_id),
            Err(e) => eprintln!("Query error: {}", e),
        }
    } else {
        eprintln!("Failed to connect to DB.");
    }
}

fn move_and_rename_file(src: &str, dst: &str) -> io::Result<()> {
    let mut target_path = PathBuf::from(dst);

    if target_path.exists() {
        let original_stem = target_path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        let extension = target_path.extension().and_then(|e| e.to_str());
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));

        let mut counter = 1;
        loop {
            let mut new_name = format!("{}({})", original_stem, counter);
            if let Some(ext) = extension {
                new_name.push('.');
                new_name.push_str(ext);
            }

            let new_path = parent.join(new_name);

            if !new_path.exists() {
                target_path = new_path;
                break;
            }

            counter += 1;
        }
    }

    fs::rename(src, &target_path)?;
    Ok(())
}