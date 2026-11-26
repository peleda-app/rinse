//! A `wasi:cli/command` for the sandbox layer's tests: reads all of stdin and, depending on how the input
//! starts, misbehaves in one way or echoes the input to stdout.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU32, Ordering};

fn main() -> ExitCode {
    let mut input = Vec::new();
    if std::io::stdin().lock().read_to_end(&mut input).is_err() {
        return ExitCode::from(2);
    }
    let output = match input.as_slice() {
        b"spin" => {
            let mut x = 0u64;
            loop {
                x = std::hint::black_box(x.wrapping_add(1));
            }
        }
        b"hog" => {
            let mut hoard: Vec<Vec<u8>> = Vec::new();
            loop {
                hoard.push(std::hint::black_box(vec![1u8; 1 << 20]));
            }
        }
        b"huge" => vec![7u8; 2 << 20],
        b"panic" => panic!("asked to panic"),
        b"exit3" => return ExitCode::from(3),
        b"probe" => probe().into_bytes(),
        b"count" => {
            static CALLS: AtomicU32 = AtomicU32::new(0);
            (CALLS.fetch_add(1, Ordering::Relaxed) + 1)
                .to_string()
                .into_bytes()
        }
        _ => input,
    };
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(&output)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn probe() -> String {
    let denied = |ok: bool| if ok { "allowed" } else { "denied" };
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(u128::MAX);
    format!(
        "env={} args={} root={} cwd={} tmp={} tcp={} wall={wall}",
        std::env::vars_os().count(),
        std::env::args_os().count(),
        denied(std::fs::read_dir("/").is_ok()),
        denied(std::fs::read_dir(".").is_ok()),
        denied(std::fs::write("/tmp/rinse-probe", b"x").is_ok()),
        denied(std::net::TcpStream::connect(("127.0.0.1", 9)).is_ok()),
    )
}
