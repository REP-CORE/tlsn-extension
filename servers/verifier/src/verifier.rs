use crate::ws::TungsteniteStream;
use eyre::eyre;
use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tlsn::{
    attestation::{
        request::Request as AttestationRequest, signing::Secp256k1Signer, Attestation,
        AttestationConfig, CryptoProvider, Extension, InvalidExtension,
    },
    config::verifier::VerifierConfig,
    connection::{CertBinding, ConnectionInfo, DnsName, ServerName, TranscriptLength},
    transcript::{ContentType, PartialTranscript, TranscriptCommitment},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{RootCertStore, ServerCertVerifier},
    Session,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, info};

/// Core verifier logic that validates the TLS proof.
/// Supports both MPC and Proxy modes — the prover picks via its commit config.
///
/// `_proxy_socket_rx` is a leftover from the previous proxy plumbing
/// (`/proxy?sessionId=…`). The current `tlsn` API tunnels prover↔verifier proxy
/// traffic through the existing session multiplexer, so this channel is
/// unused. Kept on the signature to avoid rippling changes through `main.rs`
/// until that endpoint is removed.
pub async fn verifier<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    max_sent_data: usize,
    max_recv_data: usize,
    _proxy_socket_rx: Option<oneshot::Receiver<TungsteniteStream>>,
) -> Result<(DnsName, PartialTranscript, Vec<TranscriptCommitment>), eyre::ErrReport> {
    info!(
        "Starting verification with maxSentData={}, maxRecvData={}",
        max_sent_data, max_recv_data
    );

    // Create a session with the prover
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background
    let driver_task = tokio::spawn(async move {
        let result = driver.await;
        match &result {
            Ok(_) => tracing::info!("verifier session driver completed normally (mux closed)"),
            Err(e) => tracing::error!("verifier session driver error: {e}"),
        }
        result
    });

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()
        .map_err(|e| eyre!("Failed to build verifier config: {}", e))?;

    let verifier = handle
        .new_verifier(verifier_config)
        .map_err(|e| eyre!("Failed to create verifier: {}", e))?;

    info!("Starting TLS commitment protocol");

    // Run the commitment protocol — the prover's config tells us which mode.
    let verifier = match verifier
        .commit()
        .await
        .map_err(|e| eyre!("Commitment failed: {}", e))?
    {
        VerifierCommitStart::Mpc(verifier) => {
            let cfg = verifier.config();
            if cfg.max_sent_data() > max_sent_data {
                return Err(eyre!(
                    "Prover requested max_sent_data {} exceeds limit {}",
                    cfg.max_sent_data(),
                    max_sent_data
                ));
            }
            if cfg.max_recv_data() > max_recv_data {
                return Err(eyre!(
                    "Prover requested max_recv_data {} exceeds limit {}",
                    cfg.max_recv_data(),
                    max_recv_data
                ));
            }
            info!(
                "Accepting MPC TLS commitment with max_sent={}, max_recv={}",
                cfg.max_sent_data(),
                cfg.max_recv_data()
            );

            verifier
                .accept()
                .await
                .map_err(|e| eyre!("Accept failed: {}", e))?
                .run()
                .await
                .map_err(|e| eyre!("Run failed: {}", e))?
        }
        VerifierCommitStart::Proxy(verifier) => {
            let host = verifier.config().server_name().as_str().to_string();
            info!("Accepting Proxy TLS commitment for server: {}", host);

            let server_addr = format!("{}:443", host);
            let server_stream = tokio::net::TcpStream::connect(&server_addr)
                .await
                .map_err(|e| eyre!("Failed to connect to target server {}: {}", server_addr, e))?;
            info!("Connected to target server {}", server_addr);

            verifier
                .accept()
                .await
                .map_err(|e| eyre!("Accept failed: {}", e))?
                .run(server_stream.compat())
                .await
                .map_err(|e| eyre!("Run failed: {}", e))?
        }
    };

    info!("TLS connection complete, starting verification");

    // Verify the proof
    let verifier = verifier
        .verify()
        .await
        .map_err(|e| eyre!("Verification failed: {}", e))?;

    let (
        VerifierOutput {
            server_name,
            transcript,
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier
        .accept()
        .await
        .map_err(|e| eyre!("Accept verification failed: {}", e))?;

    // Close the verifier
    verifier
        .close()
        .await
        .map_err(|e| eyre!("Failed to close verifier: {}", e))?;

    // Close the session handle
    handle.close();

    // Wait for the driver to complete
    driver_task
        .await
        .map_err(|e| eyre!("Driver task failed: {}", e))?
        .map_err(|e| eyre!("Session driver error: {}", e))?;

    info!("verify() returned successfully");

    let server_name =
        server_name.ok_or_else(|| eyre!("prover should have revealed server name"))?;
    let transcript =
        transcript.ok_or_else(|| eyre!("prover should have revealed transcript data"))?;

    info!("server_name: {:?}", server_name);
    debug!("transcript: {:?}", &transcript);

    let sent = transcript.sent_unsafe().to_vec();
    let received = transcript.received_unsafe().to_vec();

    let ServerName::Dns(dns_name) = server_name;
    info!("Server name verified: {:?}", dns_name);

    info!("============================================");
    info!("Verification successful!");
    info!("============================================");

    info!("Sent data: {:?}", bytes_to_redacted_string(&sent, "\u{2588}")?);
    info!(
        "Received data: {:?}",
        bytes_to_redacted_string(&received, "\u{2588}")?
    );

    info!(
        "Hash commitments: {} (sent+recv)",
        transcript_commitments.len()
    );

    Ok((dns_name, transcript, transcript_commitments))
}

/// Compress long sequences of redacted emojis for better readability
#[allow(unused)]
fn compress_redacted_sequences(text: String) -> String {
    let re = regex::Regex::new(r"\u{2588}{5,}").unwrap();
    re.replace_all(&text, "\u{2588}\u{2026}\u{2588}").to_string()
}

/// Render redacted bytes as block characters.
fn bytes_to_redacted_string(bytes: &[u8], to: &str) -> Result<String, eyre::ErrReport> {
    Ok(String::from_utf8(bytes.to_vec())
        .map_err(|err| eyre!("Failed to parse bytes to redacted string: {err}"))?
        .replace('\0', to))
}

/// NOTARY mode: run the MPC-TLS commitment, then sign an `Attestation` over the
/// transcript commitments + connection info and send it to the prover, who
/// builds a portable, offline-verifiable `Presentation`. Unlike `verifier()`
/// (interactive — prover reveals plaintext to us), here the prover commits but
/// does NOT reveal, so the notary stays blind to the plaintext.
///
/// secp256k1 signing key from env `NOTARY_SIGNING_KEY` (32-byte hex). Works in
/// BOTH commitment modes — MPC (device connects) and Proxy (we connect + relay
/// ciphertext, faster, blind to plaintext but not to the server). Both arms
/// converge on the same `Committed` state, so the signing path below is
/// mode-agnostic. Modelled on tlsn `examples/attestation/prove.rs` (the notary
/// half), which rejects Proxy as an example choice — not a protocol limit.
pub async fn notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    max_sent_data: usize,
    max_recv_data: usize,
) -> Result<(), eyre::ErrReport> {
    info!(
        "Starting NOTARY (signed attestation) with maxSentData={}, maxRecvData={}",
        max_sent_data, max_recv_data
    );

    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    // The driver yields the underlying socket back when the session closes; we
    // reuse it for the raw attestation request/response exchange.
    let driver_task = tokio::spawn(async move { driver.await });

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()
        .map_err(|e| eyre!("Failed to build verifier config: {}", e))?;

    let verifier = handle
        .new_verifier(verifier_config)
        .map_err(|e| eyre!("Failed to create verifier: {}", e))?;

    let verifier = match verifier
        .commit()
        .await
        .map_err(|e| eyre!("Commitment failed: {}", e))?
    {
        VerifierCommitStart::Mpc(verifier) => {
            let cfg = verifier.config();
            if cfg.max_sent_data() > max_sent_data || cfg.max_recv_data() > max_recv_data {
                return Err(eyre!(
                    "Prover exceeds limits: sent {}/{}, recv {}/{}",
                    cfg.max_sent_data(),
                    max_sent_data,
                    cfg.max_recv_data(),
                    max_recv_data
                ));
            }
            info!(
                "Notary accepting MPC commitment (max_sent={}, max_recv={})",
                cfg.max_sent_data(),
                cfg.max_recv_data()
            );
            verifier
                .accept()
                .await
                .map_err(|e| eyre!("Accept failed: {}", e))?
                .run()
                .await
                .map_err(|e| eyre!("Run failed: {}", e))?
        }
        VerifierCommitStart::Proxy(verifier) => {
            // Proxy mode: WE open the TLS connection to the server and relay
            // ciphertext between prover and server. The prover still commits
            // and does NOT reveal, so we stay blind to the plaintext — the
            // attestation that comes out is identical to the MPC one. Mirrors
            // the interactive verifier's Proxy branch above.
            let host = verifier.config().server_name().as_str().to_string();
            info!("Notary accepting Proxy commitment for server: {}", host);

            let server_addr = format!("{}:443", host);
            let server_stream = tokio::net::TcpStream::connect(&server_addr)
                .await
                .map_err(|e| eyre!("Failed to connect to target server {}: {}", server_addr, e))?;
            info!("Notary connected to target server {}", server_addr);

            verifier
                .accept()
                .await
                .map_err(|e| eyre!("Accept failed: {}", e))?
                .run(server_stream.compat())
                .await
                .map_err(|e| eyre!("Run failed: {}", e))?
        }
    };

    // In notary mode the prover commits but does NOT reveal — take the
    // commitments + TLS metadata, never the plaintext.
    // REP: also take `server_name`. It is the name the NOTARY verified against
    // the server's certificate chain during the session — the same field the
    // interactive verifier reports — and is written under the signed root as
    // the `rep.host` extension so a circuit can pin the host without X.509.
    let (
        VerifierOutput {
            server_name,
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier
        .verify()
        .await
        .map_err(|e| eyre!("Verification failed: {}", e))?
        .accept()
        .await
        .map_err(|e| eyre!("Accept verification failed: {}", e))?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier
        .close()
        .await
        .map_err(|e| eyre!("Failed to close verifier: {}", e))?;

    let sent_len: usize = tls_transcript
        .sent()
        .iter()
        .filter_map(|r| {
            if let ContentType::ApplicationData = r.typ {
                Some(r.ciphertext.len())
            } else {
                None
            }
        })
        .sum();
    let recv_len: usize = tls_transcript
        .recv()
        .iter()
        .filter_map(|r| {
            if let ContentType::ApplicationData = r.typ {
                Some(r.ciphertext.len())
            } else {
                None
            }
        })
        .sum();

    handle.close();
    let mut socket = driver_task
        .await
        .map_err(|e| eyre!("Driver join failed: {}", e))?
        .map_err(|e| eyre!("Session driver error: {}", e))?;

    // Receive the attestation request from the prover. Length-prefixed (u32 BE),
    // NOT read_to_end: a WebSocket has no half-close, so the prover keeps the
    // connection open and frames the request by length. read_to_end would block
    // forever (no EOF) or, if the prover closed, kill our write-back below.
    let mut req_len_buf = [0u8; 4];
    socket
        .read_exact(&mut req_len_buf)
        .await
        .map_err(|e| eyre!("Failed to read attestation request length: {}", e))?;
    let req_len = u32::from_be_bytes(req_len_buf) as usize;
    let mut request_bytes = vec![0u8; req_len];
    socket
        .read_exact(&mut request_bytes)
        .await
        .map_err(|e| eyre!("Failed to read attestation request: {}", e))?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)
        .map_err(|e| eyre!("Failed to deserialize attestation request: {}", e))?;

    // Load the notary secp256k1 signing key.
    let key_hex =
        std::env::var("NOTARY_SIGNING_KEY").map_err(|_| eyre!("NOTARY_SIGNING_KEY env not set"))?;
    let key_bytes =
        hex::decode(key_hex.trim()).map_err(|e| eyre!("NOTARY_SIGNING_KEY not valid hex: {}", e))?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| eyre!("NOTARY_SIGNING_KEY must be 32 bytes"))?;
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&key_arr.into())
        .map_err(|e| eyre!("Invalid secp256k1 key: {}", e))?;
    let signer = Box::new(
        Secp256k1Signer::new(&signing_key.to_bytes())
            .map_err(|e| eyre!("Failed to build signer: {}", e))?,
    );
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    // REP: which host this session actually reached.
    //
    // In NOTARY mode the prover commits and never reveals, so `VerifierOutput`
    // carries no server name — the earlier code errored out here and no
    // attestation was ever produced ("notary did not establish a server name").
    // What the notary DOES hold is the certificate chain from the handshake it
    // took part in, which is the stronger source: it is what the server itself
    // presented. So the `rep.host` value the prover asks for is checked against
    // that chain below, in the extension validator. A prover asking for
    // `rep.host = www.booking.com` on a session with evil.example.com fails,
    // because evil's certificate does not cover that name.
    let revealed_host: Option<String> = match server_name {
        Some(ServerName::Dns(d)) => Some(d.as_str().to_string()),
        _ => None,
    };

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    // REP: the default validator rejects every extension. Admit exactly one —
    // `rep.host` — and only with the value THIS notary verified. A prover
    // requesting `rep.host = www.booking.com` on a session with evil.example.com
    // is refused here, before any attestation exists.
    {
        let revealed = revealed_host.clone();
        let chain: Vec<_> = tls_transcript.server_cert_chain().unwrap_or(&[]).to_vec();
        let time = tls_transcript.time();
        att_config_builder.extension_validator(move |exts: &[Extension]| {
            for e in exts {
                if e.id != b"rep.host" {
                    return Err(InvalidExtension::new("only rep.host is accepted"));
                }
                let host = std::str::from_utf8(&e.value)
                    .map_err(|_| InvalidExtension::new("rep.host is not utf-8"))?;
                // If the prover revealed the name, that observation decides.
                if let Some(observed) = revealed.as_deref() {
                    if host != observed {
                        return Err(InvalidExtension::new("rep.host does not match the notarised host"));
                    }
                    continue;
                }
                // Otherwise the certificate the server presented has to cover it.
                let (ee, intermediates) = chain
                    .split_first()
                    .ok_or_else(|| InvalidExtension::new("no server certificate in this session"))?;
                let name = DnsName::try_from(host)
                    .map_err(|_| InvalidExtension::new("rep.host is not a valid DNS name"))?;
                ServerCertVerifier::mozilla()
                    .verify_server_cert(ee, intermediates, &ServerName::Dns(name), time)
                    .map_err(|_| InvalidExtension::new("rep.host is not covered by the server certificate"))?;
            }
            Ok(())
        });
    }
    let att_config = att_config_builder
        .build()
        .map_err(|e| eyre!("Failed to build attestation config: {}", e))?;

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        return Err(eyre!("unsupported cert binding version"));
    };
    let mut builder = Attestation::builder(&att_config)
        .accept_request(request)
        .map_err(|e| eyre!("Failed to accept attestation request: {}", e))?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);
    // REP: bind the verified host under the signed root. When the prover revealed
    // the name, the notary states it itself. When it did not (notary mode: commit,
    // never reveal), the prover's REQUESTED `rep.host` already rides in the
    // attestation via accept_request — and the validator above only let it through
    // after checking it against the certificate the server presented. Adding it
    // again here would duplicate the leaf.
    if let Some(host) = revealed_host {
        builder.extension(Extension { id: b"rep.host".to_vec(), value: host.into_bytes() });
    }
    let attestation = builder
        .build(&provider)
        .map_err(|e| eyre!("Failed to build attestation: {}", e))?;

    let attestation_bytes =
        bincode::serialize(&attestation).map_err(|e| eyre!("Failed to serialize attestation: {}", e))?;
    // Length-prefixed write back (matches the prover's length-prefixed read).
    let att_len = (attestation_bytes.len() as u32).to_be_bytes();
    socket
        .write_all(&att_len)
        .await
        .map_err(|e| eyre!("Failed to send attestation length: {}", e))?;
    socket
        .write_all(&attestation_bytes)
        .await
        .map_err(|e| eyre!("Failed to send attestation: {}", e))?;
    socket
        .flush()
        .await
        .map_err(|e| eyre!("Failed to flush attestation: {}", e))?;
    let _ = socket.close().await; // best-effort, AFTER the full write

    info!(
        "Notary: signed attestation sent ({} bytes)",
        attestation_bytes.len()
    );
    Ok(())
}
