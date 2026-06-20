//! Notary mode: produce a portable, notary-signed `Presentation` (offline-
//! verifiable forever) instead of the interactive verifier reveal.
//!
//! sdk-core only exposes the interactive `reveal()` (verifier is the relying
//! party, nothing portable). This path uses the high-level `tlsn` prover +
//! attestation API directly to: run an MPC-TLS session with the notary, commit
//! the transcript, request a signed `Attestation`, and build a `Presentation`
//! that anyone can verify offline against the notary's public key + WebPKI.
//!
//! Attestation requires MPC mode (the notary stays blind to plaintext). Modelled
//! on tlsn `examples/attestation/{prove,present}.rs`.

use crate::{ws_io::WsIoAdapter, HttpRequest, ProverOptions, TlsnError};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use std::future::IntoFuture;
use tlsn::{
    attestation::{
        presentation::{Presentation, PresentationOutput},
        request::{Request as AttestationRequest, RequestConfig},
        Attestation, CryptoProvider,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::{HandshakeData, ServerName},
    prover::ProverOutput,
    transcript::TranscriptCommitConfig,
    webpki::RootCertStore,
    Session,
};
use tokio_tungstenite::connect_async;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::info;

fn cfg_err<E: std::fmt::Display>(e: E) -> TlsnError {
    TlsnError::ProofFailed(format!("config: {e}"))
}
fn conn_err<E: std::fmt::Display>(e: E) -> TlsnError {
    TlsnError::ConnectionFailed(format!("{e}"))
}
fn proof_err<E: std::fmt::Display>(e: E) -> TlsnError {
    TlsnError::ProofFailed(format!("{e}"))
}

/// Notarize `request` (MPC) and return a bincode-serialized `Presentation`.
pub async fn notarize_async(
    request: HttpRequest,
    options: ProverOptions,
) -> Result<Vec<u8>, TlsnError> {
    // Parse host + path from the target URL.
    let url = url::Url::parse(&request.url).map_err(|e| conn_err(format!("bad url: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| conn_err("no host in url"))?
        .to_string();
    let mut path = url.path().to_string();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }

    // Notary WebSocket session (the /notary endpoint signs the attestation).
    let v = url::Url::parse(&options.verifier_url)
        .map_err(|e| conn_err(format!("bad verifier url: {e}")))?;
    let ws_scheme = if v.scheme() == "https" { "wss" } else { "ws" };
    let notary_ws_url = format!(
        "{ws_scheme}://{}{}/notary?maxSentData={}&maxRecvData={}",
        v.host_str().unwrap_or("localhost"),
        v.port().map(|p| format!(":{p}")).unwrap_or_default(),
        options.max_sent_data,
        options.max_recv_data,
    );
    info!("notarize: connecting to notary {notary_ws_url}");
    let (ws, _) = connect_async(&notary_ws_url).await.map_err(conn_err)?;
    let session = Session::new(WsIoAdapter::new(ws)); // WsIoAdapter is futures::AsyncRead/Write
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // New MPC prover.
    let prover = handle
        .new_prover(ProverConfig::builder().build().map_err(cfg_err)?)
        .map_err(conn_err)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(options.max_sent_data as usize)
                .max_recv_data(options.max_recv_data as usize)
                .build()
                .map_err(cfg_err)?,
        )
        .await
        .map_err(conn_err)?;

    // TLS to the real server (residential IP = the device).
    let server_socket = tokio::net::TcpStream::connect((host.as_str(), 443))
        .await
        .map_err(|e| conn_err(format!("server connect {host}: {e}")))?;
    let (tls_connection, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(
                    host.as_str().try_into().map_err(|_| conn_err("bad server name"))?,
                ))
                .root_store(RootCertStore::mozilla())
                .build()
                .map_err(cfg_err)?,
            server_socket.compat(),
        )
        .map_err(conn_err)?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    // HTTP/1.1 over the proven TLS connection.
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .map_err(|e| conn_err(format!("http handshake: {e}")))?;
    tokio::spawn(connection);

    let mut req_builder = hyper::Request::builder()
        .uri(path)
        .method(request.method.as_str())
        .header("Host", host.as_str());
    for h in &request.headers {
        req_builder = req_builder.header(h.name.as_str(), h.value.as_str());
    }
    // Send the REAL request body (POST/PUT). Hardcoding an empty body dropped the
    // payload: Uber getOrderCount (35B POST body) hit a server error
    // ("n?.filter is not a function") so the MPC proof captured a FAILURE response
    // (value 0) while the proxy proof — which sends the body — got the real value.
    // Full with empty bytes is an empty body, so this also covers GET.
    let body_bytes = Bytes::from(request.body.clone().unwrap_or_default().into_bytes());
    let http_request = req_builder
        .body(Full::<Bytes>::new(body_bytes))
        .map_err(|e| conn_err(format!("build request: {e}")))?;
    let response = request_sender
        .send_request(http_request)
        .await
        .map_err(|e| conn_err(format!("send request: {e}")))?;
    info!("notarize: server responded {}", response.status());

    let mut prover = prover_task
        .await
        .map_err(|e| proof_err(format!("prover join: {e}")))?
        .map_err(conn_err)?;

    // Commit the RAW transcript as byte ranges. HttpTranscript::parse needs a
    // UTF-8 body, but the MPC response is gzipped (binary) so the HTTP committer
    // chokes ("invalid utf-8"). Commit raw ranges instead. Hash commitments are
    // per-range, so commit the request LINE separately from the request HEADERS —
    // that lets the presentation reveal the line (what was asked) while hiding the
    // headers (session cookies / auth). recv is committed whole and revealed whole.
    let sent_len = prover.transcript().sent().len();
    let recv_len = prover.transcript().received().len();
    info!(
        "notarize: transcript sizes sent={} recv={} (recv is the gzipped wire response)",
        sent_len, recv_len
    );
    let reqline_end = prover
        .transcript()
        .sent()
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(sent_len);
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    commit_builder.commit_sent(0..reqline_end).map_err(cfg_err)?;
    if reqline_end < sent_len {
        commit_builder.commit_sent(reqline_end..sent_len).map_err(cfg_err)?;
    }
    commit_builder.commit_recv(0..recv_len).map_err(cfg_err)?;
    let transcript_commit = commit_builder.build().map_err(cfg_err)?;

    let mut req_cfg_builder = RequestConfig::builder();
    req_cfg_builder.transcript_commit(transcript_commit);
    let request_config = req_cfg_builder.build().map_err(cfg_err)?;

    let mut prove_builder = ProveConfig::builder(prover.transcript());
    if let Some(c) = request_config.transcript_commit() {
        prove_builder.transcript_commit(c.clone());
    }
    let disclosure_config = prove_builder.build().map_err(cfg_err)?;

    info!("notarize: prove() starting (commit+prove over recv={recv_len}B)");
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await.map_err(conn_err)?;
    info!("notarize: prove() done");
    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await.map_err(conn_err)?;

    // Build the attestation request (binds to the server cert + commitments).
    let mut att_req_builder = AttestationRequest::builder(&request_config);
    att_req_builder
        .server_name(ServerName::Dns(
            host.as_str().try_into().map_err(|_| proof_err("bad server name"))?,
        ))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .ok_or_else(|| proof_err("no server cert chain"))?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .ok_or_else(|| proof_err("no server signature"))?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (att_request, secrets) = att_req_builder
        .build(&CryptoProvider::default())
        .map_err(proof_err)?;

    // Exchange with the notary over the reclaimed socket.
    handle.close();
    let mut socket = driver_task
        .await
        .map_err(|e| proof_err(format!("driver join: {e}")))?
        .map_err(conn_err)?;
    let request_bytes = bincode::serialize(&att_request).map_err(proof_err)?;
    // Length-prefixed exchange. A WebSocket has NO TCP half-close: socket.close()
    // tears down BOTH directions, so the old "write request -> close -> read_to_end
    // attestation" deadlocks (the notary can't write back; we can't read). Frame
    // each side with a u32 BE length and never close mid-exchange.
    let req_len = (request_bytes.len() as u32).to_be_bytes();
    socket.write_all(&req_len).await.map_err(conn_err)?;
    socket.write_all(&request_bytes).await.map_err(conn_err)?;
    socket.flush().await.map_err(conn_err)?;

    let mut att_len_buf = [0u8; 4];
    socket.read_exact(&mut att_len_buf).await.map_err(conn_err)?;
    let att_len = u32::from_be_bytes(att_len_buf) as usize;
    let mut attestation_bytes = vec![0u8; att_len];
    socket.read_exact(&mut attestation_bytes).await.map_err(conn_err)?;
    let _ = socket.close().await; // best-effort, AFTER the full exchange
    let attestation: Attestation = bincode::deserialize(&attestation_bytes).map_err(proof_err)?;

    // Check the attestation matches the prover's view.
    let provider = CryptoProvider::default();
    att_request.validate(&attestation, &provider).map_err(proof_err)?;

    // Build the Presentation with RAW ranges (HttpTranscript can't parse the
    // gzipped recv). Reveal the WHOLE response (the verifier decompresses it) and
    // ONLY the request line of the request — the session cookies / auth headers
    // stay redacted as 'X'. reqline_end / recv_len were computed at commit time.
    let mut pb = secrets.transcript_proof_builder();
    pb.reveal_sent(0..reqline_end).map_err(proof_err)?;
    pb.reveal_recv(0..recv_len).map_err(proof_err)?;
    let transcript_proof = pb.build().map_err(proof_err)?;

    let mut present_builder = attestation.presentation_builder(&provider);
    present_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation = present_builder.build().map_err(proof_err)?;

    let bytes = bincode::serialize(&presentation).map_err(proof_err)?;
    info!("notarize: presentation built ({} bytes)", bytes.len());
    Ok(bytes)
}

/// Result of verifying a notary-signed `Presentation` offline.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerifiedPresentation {
    /// The TLS server the data provably came from (e.g. "steamcommunity.com").
    pub server_name: String,
    /// Unix seconds at which the TLS connection was made (from the notary).
    pub time_secs: u64,
    /// Revealed request bytes; undisclosed bytes shown as 'X'.
    pub sent: String,
    /// Revealed response bytes; undisclosed bytes shown as 'X'.
    pub recv: String,
    /// Hex of the secp256k1 key that signed this attestation.
    pub notary_key: String,
    /// True iff `notary_key` equals the caller-pinned expected key.
    pub key_matches: bool,
}

/// Verify a notary-signed `Presentation` (bincode bytes) OFFLINE: WebPKI checks
/// the server cert chain, the notary's secp256k1 signature is checked against
/// the embedded key, and that key is compared to the one REP pins. No network,
/// no notary, no relying party in the loop — this is what makes the proof
/// portable and self-contained.
///
/// `expected_notary_key_hex` is REP's published notary pubkey. Callers MUST
/// reject results where `key_matches` is false: anyone can stand up a notary,
/// so a valid signature alone proves nothing without pinning whose it is.
#[uniffi::export]
pub fn verify_presentation(
    presentation_bytes: Vec<u8>,
    expected_notary_key_hex: String,
) -> Result<VerifiedPresentation, TlsnError> {
    let presentation: Presentation =
        bincode::deserialize(&presentation_bytes).map_err(proof_err)?;

    // Pin the notary key BEFORE trusting any of the verified contents.
    let vk = presentation.verifying_key();
    let notary_key = hex::encode(&vk.data);
    let key_matches = notary_key.eq_ignore_ascii_case(expected_notary_key_hex.trim());

    // CryptoProvider::default() verifies the server cert chain against Mozilla
    // WebPKI roots, so this proves the data really came from that TLS server.
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation
        .verify(&CryptoProvider::default())
        .map_err(|e| proof_err(format!("presentation verify failed: {e}")))?;

    let server_name = match server_name {
        Some(ServerName::Dns(d)) => d.as_str().to_string(),
        _ => String::new(),
    };

    let (sent, recv) = match transcript {
        Some(mut t) => {
            t.set_unauthed(b'X'); // mark undisclosed bytes distinctly
            let sent = String::from_utf8_lossy(t.sent_unsafe()).to_string();
            // The committed transcript is the RAW wire response. For MPC we request
            // Accept-Encoding: gzip so the committed bytes are small enough for the
            // device. Decompress here so the claim is extracted from plaintext — a
            // deterministic, lossless, independently-reproducible decode of exactly
            // what the server sent (any verifier can redo it). Non-gzip responses
            // pass through unchanged.
            let recv = decode_http_response(t.received_unsafe());
            (sent, recv)
        }
        None => (String::new(), String::new()),
    };

    info!(
        "verify_presentation: {} @ {}s, key_matches={}",
        server_name, connection_info.time, key_matches
    );
    Ok(VerifiedPresentation {
        server_name,
        time_secs: connection_info.time,
        sent,
        recv,
        notary_key,
        key_matches,
    })
}

/// Turn a raw HTTP/1.1 response (status line + headers + body, exactly as it came
/// off the wire) into header + decoded-plaintext form, so a JSONPath/regex claim
/// can be extracted. Handles `Transfer-Encoding: chunked` (de-chunk) and
/// `Content-Encoding: gzip` (decompress). Decoding is deterministic + lossless and
/// reproducible by ANY verifier — it does not change what was proven, only its
/// transport encoding. On ANY parse/decode failure it returns the raw bytes
/// (claim extraction then just fails and the MPC upgrade is skipped — never wrong).
fn decode_http_response(raw: &[u8]) -> String {
    let Some(idx) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return String::from_utf8_lossy(raw).to_string();
    };
    let headers = &raw[..idx];
    let body = &raw[idx + 4..];
    let headers_str = String::from_utf8_lossy(headers);
    let header_lc = headers_str.to_ascii_lowercase();
    let has = |k: &str, v: &str| {
        header_lc
            .lines()
            .any(|l| l.starts_with(k) && l.contains(v))
    };

    // 1. De-chunk if Transfer-Encoding: chunked.
    let dechunked: Vec<u8> = if has("transfer-encoding:", "chunked") {
        let mut out = Vec::new();
        let mut rest = body;
        loop {
            let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") else { break };
            let size_hex = String::from_utf8_lossy(&rest[..nl]);
            let size = usize::from_str_radix(
                size_hex.trim().split(';').next().unwrap_or("").trim(),
                16,
            )
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
            // skip the chunk data + its trailing CRLF
            rest = if end + 2 <= rest.len() { &rest[end + 2..] } else { &[] };
        }
        out
    } else {
        body.to_vec()
    };

    // 2. Gunzip if Content-Encoding: gzip.
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

    format!(
        "{}\r\n\r\n{}",
        headers_str,
        String::from_utf8_lossy(&decoded)
    )
}

#[cfg(test)]
mod fly_repro_tests {
    use super::*;
    use crate::{HttpHeader, HttpRequest, ProverOptions};

    /// Device-free repro of the MOBILE transport path (WsIoAdapter). Drives the
    /// real `notarize_async` against the deployed Fly notary through a local TLS
    /// bridge. The verifier's own test (ws_stream_tungstenite adapter) passes;
    /// if THIS fails with "context mux error" / "bytes remaining on stream", the
    /// custom WsIoAdapter is the bug. Run:
    ///   socat TCP-LISTEN:9444,fork,reuseaddr OPENSSL:rep-notary.fly.dev:443,verify=0,snihost=rep-notary.fly.dev &
    ///   FLY_BRIDGE=ws://127.0.0.1:9444 cargo test -p tlsn-mobile mobile_notarize_against_fly -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn mobile_notarize_against_fly() {
        let base = std::env::var("FLY_BRIDGE").unwrap_or_else(|_| "ws://127.0.0.1:9444".to_string());
        let request = HttpRequest {
            url: "https://raw.githubusercontent.com/tlsnotary/tlsn/ceadf458f6f75909eda013aa50108f9f94956188/crates/server-fixture/server/src/data/1kb.json".to_string(),
            method: "GET".to_string(),
            headers: vec![HttpHeader { name: "accept".into(), value: "application/json".into() }],
            body: None,
        };
        let options = ProverOptions {
            verifier_url: base,
            max_sent_data: 8192,
            max_recv_data: 16384,
            handlers: vec![],
            mode: None,
        };
        let res = notarize_async(request, options).await;
        match &res {
            Ok(bytes) => println!("[mobile-fly] ✅ notarize SUCCEEDED: {} presentation bytes", bytes.len()),
            Err(e) => println!("[mobile-fly] ❌ notarize FAILED: {}", e),
        }
        assert!(res.is_ok(), "mobile notarize_async failed: {:?}", res.err());
    }
}
