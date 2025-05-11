use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const SOCKET_PATH: &str = "/tmp/voodoo.sock";

fn send_command(cmd: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)?;
    stream.write_all(cmd.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

pub fn load_plugin(name: &str) {
    match send_command(&format!("load {}\n", name)) {
        Ok(reply) => println!("{}", reply),
        Err(e) => eprintln!("Failed to load plugin: {}", e),
    }
}

pub fn unload_plugin(name: &str) {
    match send_command(&format!("unload {}\n", name)) {
        Ok(reply) => println!("{}", reply),
        Err(e) => eprintln!("Failed to unload plugin: {}", e),
    }
}

pub fn list_plugins() {
    match send_command("list\n") {
        Ok(reply) => println!("{}", reply),
        Err(e) => eprintln!("Failed to list plugins: {}", e),
    }
}