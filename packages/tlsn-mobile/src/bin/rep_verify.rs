//! rep-verify — verify a portable REP presentation OFFLINE.
//!
//! Run with NOTHING but the presentation file and REP's published notary public
//! key. It does NOT talk to REP, the notary, or the platform — pure local crypto
//! over the signed bytes. A portable proof carries two INDEPENDENT guarantees:
//!
//!   1. WHO  — the server's TLS certificate (checked against WebPKI roots) proves
//!             the data came from that exact server.
//!   2. INTEGRITY — the notary co-signed an MPC attestation in which the session
//!             keys were SPLIT, so the prover could not forge the transcript. You
//!             trust the notary only to have been INDEPENDENT of the prover (it is
//!             blind to your plaintext), and you pin its key to assert that.
//!
//!   cargo run -p tlsn-mobile --bin rep-verify -- <presentation.bin> [notary_pubkey_hex]

use std::process::ExitCode;

const DEFAULT_NOTARY_KEY: &str =
    "02114d7e15cb2a93ad88997af3394d00008dae381b601f31379d638de492ab25ef";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("usage: rep-verify <presentation.bin> [notary_pubkey_hex]");
        return ExitCode::FAILURE;
    };
    let key = args.get(2).map(String::as_str).unwrap_or(DEFAULT_NOTARY_KEY);

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => { eprintln!("cannot read {path}: {e}"); return ExitCode::FAILURE; }
    };

    println!("REP offline proof verifier");
    println!("  presentation: {path} ({} bytes)", bytes.len());
    println!("  no network — pure local crypto over the signed bytes\n");

    match tlsn_mobile::verify_presentation(bytes, key.to_string()) {
        Ok(v) => {
            // Guarantee 2 first: was the prover able to forge?
            println!("[2] INTEGRITY — could the author have faked this?");
            if v.key_matches {
                println!("    NO. signed by the PINNED notary key (keys were MPC-split,");
                println!("    so the author never held the full session key).");
                println!("    notary key: {}", v.notary_key);
            } else {
                println!("    ❌ REJECTED — signed by a DIFFERENT notary key:");
                println!("       got:      {}", v.notary_key);
                println!("       expected: {key}");
                println!("    A notary the author could control proves nothing. STOP.");
                return ExitCode::FAILURE;
            }
            // Guarantee 1: who is it from?
            println!("\n[1] WHO — where did the data come from?");
            println!("    server (proven by its real TLS certificate): {}", v.server_name);
            println!("    connection time (unix): {}", v.time_secs);

            // The proven facts: revealed substrings. Undisclosed bytes are runs of
            // 'X' (redaction); split on those runs, not on stray single 'X' that
            // occur in real text (e.g. "X-Frame-Options").
            let redaction = regex::Regex::new("X{2,}").unwrap();
            let facts: Vec<String> = redaction
                .split(&v.recv)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && *s != "HTTP/1.1 200 OK")
                .map(|s| s.replace('\n', " ").trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            println!("\n[3] PROVEN FACTS — revealed bytes, authenticated as server-origin:");
            if facts.is_empty() {
                println!("    (whole response revealed — see raw recv)");
            }
            for f in facts.iter().take(40) {
                println!("    • {f}");
            }
            println!("\n✅ VERIFIED. Two independent guarantees hold; trust the math, not REP.");
            ExitCode::SUCCESS
        }
        Err(e) => { println!("❌ INVALID presentation: {e}"); ExitCode::FAILURE }
    }
}
