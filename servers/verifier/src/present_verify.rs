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
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
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

#[derive(Deserialize)]
pub struct AttestQuery {
    /// Optional caller nonce, bound into the signed statement for freshness/anti-replay.
    pub nonce: Option<String>,
}

#[derive(Serialize)]
pub struct AttestResult {
    pub ok: bool,
    pub fact_digest: String, // blake3(presentation) hex = the anchor id the prover uses
    pub server_name: String,
    pub time_secs: u64,
    pub nonce: String,
    pub statement: String,   // exact utf-8 bytes that were signed
    pub signature: String,   // ECDSA secp256k1 (SHA-256) over statement, compact r||s hex (64 bytes)
    pub notary_key: String,  // the in-enclave notary pubkey (compressed hex)
    pub scheme: String,
}

/// FAST-PATH attestation. The notary re-signs a compact, domain-separated statement binding
/// blake3(presentation) so an agent can verify a proof with only secp256k1 + blake3 (no TLSN stack,
/// no third-party verifier). NOT an oracle: we sign ONLY a presentation that (a) verifies (WebPKI +
/// notary co-signature) and (b) was co-signed by THIS notary's own key, so a signature can never be
/// obtained for a fabricated fact. POST /attest-digest?nonce=<hex>  body: raw presentation bytes.
pub async fn attest_digest_handler(
    Query(q): Query<AttestQuery>,
    body: Bytes,
) -> Result<Json<AttestResult>, (StatusCode, String)> {
    // Our in-enclave signing key + its compressed pubkey.
    let key_hex = std::env::var("NOTARY_SIGNING_KEY")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "NOTARY_SIGNING_KEY not set".to_string()))?;
    let key_bytes = hex::decode(key_hex.trim())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("bad key hex: {e}")))?;
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "NOTARY_SIGNING_KEY must be 32 bytes".to_string()))?;
    let signing_key = SigningKey::from_bytes(&key_arr.into())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("bad signing key: {e}")))?;
    let our_pub = hex::encode(signing_key.verifying_key().to_encoded_point(true).as_bytes());

    // 1. deserialize + require the presentation was co-signed by OUR key (the anti-oracle gate).
    let presentation: Presentation = bincode::deserialize(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("deserialize presentation: {e}")))?;
    let pres_key = hex::encode(&presentation.verifying_key().data);
    if !pres_key.eq_ignore_ascii_case(&our_pub) {
        return Err((StatusCode::BAD_REQUEST, "presentation was not co-signed by this notary".to_string()));
    }

    // 2. it must actually verify (WebPKI cert chain + notary signature).
    let PresentationOutput { server_name, connection_info, .. } = presentation
        .verify(&CryptoProvider::default())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("presentation verify failed: {e}")))?;
    let server_name = match server_name {
        Some(ServerName::Dns(d)) => d.as_str().to_string(),
        _ => String::new(),
    };

    // 3. sign a domain-separated statement binding blake3(presentation) with the in-enclave key.
    let fact_digest = blake3::hash(&body).to_hex().to_string();
    let nonce = q.nonce.unwrap_or_default();
    let statement = format!(
        "REP-FACT-v1\n{}\n{}\n{}\n{}",
        fact_digest, server_name, connection_info.time, nonce
    );
    let sig: Signature = signing_key.sign(statement.as_bytes());

    Ok(Json(AttestResult {
        ok: true,
        fact_digest,
        server_name,
        time_secs: connection_info.time,
        nonce,
        statement,
        signature: hex::encode(sig.to_bytes()),
        notary_key: our_pub,
        scheme: "ecdsa-secp256k1-sha256; sig=compact-r||s hex (64B); verify over statement utf8-bytes"
            .to_string(),
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
