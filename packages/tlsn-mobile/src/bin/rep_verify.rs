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
//!   cargo run -p tlsn-mobile --bin rep-verify -- <presentation.bin> [notary_pubkey_hex] [--json]
//!
//! `--json` emits a single machine-readable object on stdout (nothing else) so a
//! relying party (rep-mcp issuance/verify) can bind a credential to the proof:
//!   {"key_matches":bool,"server_name":str,"time_secs":n,"notary_key":hex,
//!    "recv":str,"sent":str,"facts":[str]}
//! Exit code is SUCCESS iff the presentation verified AND the pinned key matched.

use std::process::ExitCode;

const DEFAULT_NOTARY_KEY: &str =
    "02114d7e15cb2a93ad88997af3394d00008dae381b601f31379d638de492ab25ef";

fn extract_facts(recv: &str) -> Vec<String> {
    // Undisclosed bytes are runs of 'X'; split on runs (>=2) so a stray single 'X'
    // in real text (e.g. "X-Frame-Options") is preserved.
    let redaction = regex::Regex::new("X{2,}").unwrap();
    redaction
        .split(recv)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "HTTP/1.1 200 OK")
        .map(|s| s.replace('\n', " ").trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");
    let positional: Vec<&String> = args.iter().skip(1).filter(|a| !a.starts_with("--")).collect();

    let Some(path) = positional.first() else {
        eprintln!("usage: rep-verify <presentation.bin> [notary_pubkey_hex] [--json]");
        return ExitCode::FAILURE;
    };
    let key = positional.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_NOTARY_KEY);

    let bytes = match std::fs::read(path.as_str()) {
        Ok(b) => b,
        Err(e) => { eprintln!("cannot read {path}: {e}"); return ExitCode::FAILURE; }
    };

    match tlsn_mobile::verify_presentation(bytes, key.to_string()) {
        Ok(v) => {
            let facts = extract_facts(&v.recv);
            if json {
                // Machine-readable: one JSON object, nothing else on stdout.
                let out = serde_json::json!({
                    "key_matches": v.key_matches,
                    "server_name": v.server_name,
                    "time_secs": v.time_secs,
                    "notary_key": v.notary_key,
                    "expected_key": key,
                    "recv": v.recv,
                    "sent": v.sent,
                    "facts": facts,
                });
                println!("{out}");
                return if v.key_matches { ExitCode::SUCCESS } else { ExitCode::FAILURE };
            }
            println!("REP offline proof verifier");
            println!("  presentation: {path} ({} bytes)", v.recv.len());
            println!("  no network — pure local crypto over the signed bytes\n");
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
        Err(e) => {
            if json { println!("{}", serde_json::json!({ "error": e.to_string() })); }
            else { println!("❌ INVALID presentation: {e}"); }
            ExitCode::FAILURE
        }
    }
}
