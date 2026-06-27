//! Server-side verification of a portable, notary-signed `Presentation`.
//!
//! This is the same logic as `tlsn-mobile::verify_presentation` (the offline
//! verifier the iOS app and the rep-verify CLI use), exposed over HTTP so the
//! Node chat gatekeeper can re-verify a proof a user submitted before granting
//! room access. The endpoint: WebPKI-checks the server cert chain, checks the
//! notary's secp256k1 signature against the embedded key, and reports whether
//! that key equals REP's pinned notary key. It returns the REVEALED transcript
//! (undisclosed bytes as 'X', body de-chunked + gunzipped) so the caller can
//! re-derive a predicate value from authenticated plaintext.
//!
//! POST /verify-presentation?key=<expected_notary_pubkey_hex>
//! body: raw presentation bytes (bincode)  ->  JSON VerifyResult

use axum::{body::Bytes, extract::Query, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tlsn::{
    attestation::{
        presentation::{Presentation, PresentationOutput},
        CryptoProvider,
    },
    connection::ServerName,
};

#[derive(Deserialize)]
pub struct VerifyQuery {
    /// REP's published notary pubkey (hex). The caller MUST reject results where
    /// `key_matches` is false: anyone can run a notary, so a valid signature
    /// alone proves nothing without pinning whose it is.
    pub key: String,
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub ok: bool,
    pub key_matches: bool,
    pub server_name: String,
    pub time_secs: u64,
    pub sent: String,
    pub recv: String,
    pub notary_key: String,
}

pub async fn verify_presentation_handler(
    Query(q): Query<VerifyQuery>,
    body: Bytes,
) -> Result<Json<VerifyResult>, (StatusCode, String)> {
    let presentation: Presentation = bincode::deserialize(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("deserialize presentation: {e}")))?;

    // Pin the notary key BEFORE trusting any verified contents.
    let vk = presentation.verifying_key();
    let notary_key = hex::encode(&vk.data);
    let key_matches = notary_key.eq_ignore_ascii_case(q.key.trim());

    // CryptoProvider::default() verifies the server cert chain against Mozilla
    // WebPKI roots, proving the data really came from that TLS server.
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation
        .verify(&CryptoProvider::default())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("presentation verify failed: {e}")))?;

    let server_name = match server_name {
        Some(ServerName::Dns(d)) => d.as_str().to_string(),
        _ => String::new(),
    };

    let (sent, recv) = match transcript {
        Some(mut t) => {
            t.set_unauthed(b'X'); // undisclosed bytes shown distinctly
            let sent = String::from_utf8_lossy(t.sent_unsafe()).to_string();
            let recv = decode_http_response(t.received_unsafe());
            (sent, recv)
        }
        None => (String::new(), String::new()),
    };

    Ok(Json(VerifyResult {
        ok: true,
        key_matches,
        server_name,
        time_secs: connection_info.time,
        sent,
        recv,
        notary_key,
    }))
}

/// Turn a raw HTTP/1.1 response into header + decoded-plaintext form. Handles
/// `Transfer-Encoding: chunked` (de-chunk) and `Content-Encoding: gzip` (gunzip).
/// Copied from tlsn-mobile so a verifier reproduces exactly what the device did.
fn decode_http_response(raw: &[u8]) -> String {
    let Some(idx) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return String::from_utf8_lossy(raw).to_string();
    };
    let headers = &raw[..idx];
    let body = &raw[idx + 4..];
    let headers_str = String::from_utf8_lossy(headers);
    let header_lc = headers_str.to_ascii_lowercase();
    let has = |k: &str, v: &str| header_lc.lines().any(|l| l.starts_with(k) && l.contains(v));

    let dechunked: Vec<u8> = if has("transfer-encoding:", "chunked") {
        let mut out = Vec::new();
        let mut rest = body;
        loop {
            let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") else { break };
            let size_hex = String::from_utf8_lossy(&rest[..nl]);
            let size =
                usize::from_str_radix(size_hex.trim().split(';').next().unwrap_or("").trim(), 16)
                    .unwrap_or(0);
            if size == 0 {
                break;
            }
            let start = nl + 2;
            let end = start + size;
            if end > rest.len() {
                break;
            }
            out.extend_from_slice(&rest[start..end]);
            rest = if end + 2 <= rest.len() { &rest[end + 2..] } else { &[] };
        }
        out
    } else {
        body.to_vec()
    };

    let decoded: Vec<u8> = if has("content-encoding:", "gzip") {
        use std::io::Read;
        let mut d = flate2::read::GzDecoder::new(&dechunked[..]);
        let mut out = Vec::new();
        match d.read_to_end(&mut out) {
            Ok(_) => out,
            Err(_) => return String::from_utf8_lossy(raw).to_string(),
        }
    } else {
        dechunked
    };

    format!("{}\r\n\r\n{}", headers_str, String::from_utf8_lossy(&decoded))
}
