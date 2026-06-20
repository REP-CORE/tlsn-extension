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
use http_body_util::Empty;
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
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
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
    let http_request = req_builder
        .body(Empty::<Bytes>::new())
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

    // Commit to the full transcript (DefaultHttpCommitter), reveal a subset later.
    let transcript = HttpTranscript::parse(prover.transcript()).map_err(proof_err)?;
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default()
        .commit_transcript(&mut commit_builder, &transcript)
        .map_err(proof_err)?;
    let transcript_commit = commit_builder.build().map_err(cfg_err)?;

    let mut req_cfg_builder = RequestConfig::builder();
    req_cfg_builder.transcript_commit(transcript_commit);
    let request_config = req_cfg_builder.build().map_err(cfg_err)?;

    let mut prove_builder = ProveConfig::builder(prover.transcript());
    if let Some(c) = request_config.transcript_commit() {
        prove_builder.transcript_commit(c.clone());
    }
    let disclosure_config = prove_builder.build().map_err(cfg_err)?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await.map_err(conn_err)?;
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
    socket.write_all(&request_bytes).await.map_err(conn_err)?;
    socket.close().await.map_err(conn_err)?;
    let mut attestation_bytes = Vec::new();
    socket
        .read_to_end(&mut attestation_bytes)
        .await
        .map_err(conn_err)?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes).map_err(proof_err)?;

    // Check the attestation matches the prover's view.
    let provider = CryptoProvider::default();
    att_request.validate(&attestation, &provider).map_err(proof_err)?;

    // Build the Presentation: reveal the full response (the platform data has no
    // secrets) + the request structure with sensitive headers redacted.
    let http_t = HttpTranscript::parse(secrets.transcript()).map_err(proof_err)?;
    let mut pb = secrets.transcript_proof_builder();
    let req0 = &http_t.requests[0];
    pb.reveal_sent(req0.without_data()).map_err(proof_err)?;
    pb.reveal_sent(&req0.request.target).map_err(proof_err)?;
    for header in &req0.headers {
        let name = header.name.as_str();
        if name.eq_ignore_ascii_case("cookie")
            || name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("x-csrf-token")
        {
            pb.reveal_sent(header.without_value()).map_err(proof_err)?;
        } else {
            pb.reveal_sent(header).map_err(proof_err)?;
        }
    }
    let resp0 = &http_t.responses[0];
    pb.reveal_recv(resp0).map_err(proof_err)?;
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
            (
                String::from_utf8_lossy(t.sent_unsafe()).to_string(),
                String::from_utf8_lossy(t.received_unsafe()).to_string(),
            )
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
            max_sent_data: 4096,
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
