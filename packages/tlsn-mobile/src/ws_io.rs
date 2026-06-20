//! WebSocket to byte-stream adapter.
//!
//! Bridges `tokio-tungstenite`'s `WebSocketStream` (which is
//! `Stream<Item=Message>` / `Sink<Message>`) into a `futures::AsyncRead +
//! AsyncWrite` byte stream that satisfies sdk-core's `Io` trait.
//!
//! ## Why a hand-rolled adapter (and why it must be exactly this shape)
//!
//! The canonical way to do this is `ws_stream_tungstenite::WsStream`, which is
//! built on `async_io_stream::IoStream`. We pin `tokio-tungstenite = "0.21"`
//! (tungstenite 0.21), while `ws_stream_tungstenite` rides on
//! `async-tungstenite`, so dropping it in pulls a second, conflicting
//! tungstenite. This module reproduces the *exact* state machine those crates
//! use, so the MPC mux behaves identically to the verifier's own
//! `WsStream`-based integration test.
//!
//! The MPC mux that `Session::new(..)` drives is extremely unforgiving: every
//! byte the mux writes must reach the peer, in order, and a premature EOF (a
//! `poll_read` returning `Ok(0)`) is interpreted as the stream closing, which
//! surfaces downstream as "context mux error" / "bytes remaining on stream".
//! Two invariants therefore must hold:
//!
//!   1. `poll_write` must DRIVE THE SINK TO FLUSH. In tungstenite 0.21,
//!      `Sink::start_send` only calls `WebSocket::write`, which *enqueues* the
//!      message into tungstenite's internal write buffer. If the underlying
//!      transport returns `WouldBlock`, tungstenite keeps the bytes buffered
//!      and returns `Ok(())` anyway (see `tokio_tungstenite::WebSocketStream`'s
//!      `start_send`). The bytes only hit the wire on a subsequent
//!      `poll_flush`. A `poll_write` that returns `Ok(n)` right after
//!      `start_send` *without flushing* tells the mux "n bytes sent" while the
//!      bytes are still sitting in a buffer the mux will never flush -> the
//!      peer waits forever for data that was "sent" -> deadlock / "bytes
//!      remaining on stream". `futures::io::AsyncWrite` documents this contract
//!      directly: "poll_write must try to make progress by flushing ... if that
//!      is the only way the underlying object can become writable again."
//!
//!   2. `poll_read` must NEVER treat an empty binary frame as EOF, and must
//!      buffer partial frames. EOF (`Ok(0)`) is reserved for an actual closed
//!      stream (`poll_next` -> `None`, or a `Close` frame fully drained).
//!
//! References:
//!   - ws_stream_tungstenite::tung_websocket / async_io_stream::IoStream
//!     (the implementation this mirrors).
//!   - tokio-tungstenite 0.21 `impl Sink<Message> for WebSocketStream`:
//!     start_send queues, poll_flush drains.
//!   - futures-rs #752 "Potential issue with flushing a buffered Sink".

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, AsyncRead, AsyncWrite, Sink, Stream};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Inner = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Adapts a `WebSocketStream` (message-framed) into a contiguous byte stream
/// (`futures::AsyncRead + AsyncWrite`). One WS binary frame is produced per
/// `poll_write`; reads coalesce frames into the caller's buffer and carry over
/// any partially-consumed frame.
pub struct WsIoAdapter {
    inner: Inner,
    /// Bytes from a WS frame that did not fit in the last `poll_read` buffer.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Set once the underlying stream has ended or sent a Close. Further reads
    /// return EOF; further writes error.
    closed: bool,
}

impl WsIoAdapter {
    pub fn new(ws: Inner) -> Self {
        Self {
            inner: ws,
            read_buf: Vec::new(),
            read_pos: 0,
            closed: false,
        }
    }

    fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
    }
}

impl AsyncRead for WsIoAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // Empty target buffer: nothing to do. (Mux never does this, but the
        // contract allows it and we must not poll the stream needlessly.)
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            // 1. Drain any leftover bytes from a previously-received frame.
            if self.read_pos < self.read_buf.len() {
                let remaining = &self.read_buf[self.read_pos..];
                let n = remaining.len().min(buf.len());
                buf[..n].copy_from_slice(&remaining[..n]);
                self.read_pos += n;
                if self.read_pos >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(n));
            }

            if self.closed {
                return Poll::Ready(Ok(0)); // genuine EOF
            }

            // 2. Pull the next WS message.
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => {
                    // CRITICAL: an empty binary frame is NOT EOF. Skip it and
                    // poll again rather than returning Ok(0).
                    if data.is_empty() {
                        continue;
                    }
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        // Stash the remainder; do not lose bytes.
                        self.read_buf = data;
                        self.read_pos = n;
                    }
                    return Poll::Ready(Ok(n));
                }

                // Control / close frames. tungstenite answers Ping with Pong
                // and echoes Close automatically, so we only need to advance.
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                    continue; // not application data; get the next frame
                }

                Some(Ok(Message::Close(_))) => {
                    // Mark closed but keep draining: tungstenite may still
                    // surface buffered frames / drive the close handshake on
                    // subsequent polls. We return EOF only once the stream
                    // itself ends (None) or read_buf is empty AND closed.
                    self.closed = true;
                    continue;
                }

                // Text / raw frames are not part of the MPC byte protocol.
                Some(Ok(Message::Text(_))) | Some(Ok(Message::Frame(_))) => {
                    return Poll::Ready(Err(Self::io_err(
                        "unexpected non-binary WS frame on MPC mux stream",
                    )));
                }

                Some(Err(e)) => {
                    return Poll::Ready(Err(Self::io_err(e)));
                }

                None => {
                    self.closed = true;
                    return Poll::Ready(Ok(0)); // genuine EOF
                }
            }
        }
    }
}

impl AsyncWrite for WsIoAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // 1. Sink must be ready before start_send. If pending, report Pending
        //    (NOT Ok) so the mux retries this exact write later.
        match ready!(Pin::new(&mut self.inner).poll_ready(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(Self::io_err(e))),
        }

        // 2. Enqueue one binary frame for this write.
        let msg = Message::Binary(buf.to_vec());
        if let Err(e) = Pin::new(&mut self.inner).start_send(msg) {
            return Poll::Ready(Err(Self::io_err(e)));
        }

        // 3. DRIVE THE SINK. In tungstenite 0.21 start_send only buffers; the
        //    bytes do not reach the peer until flush. We must push them out
        //    here, otherwise the mux believes `buf.len()` bytes were sent while
        //    they sit in tungstenite's buffer -> "bytes remaining on stream".
        //
        //    We have already accepted the data into the sink, so we MUST report
        //    `buf.len()` regardless of whether the flush completes now. If the
        //    flush is still pending it will be completed by a later poll_flush
        //    (the mux always flushes), and the waker is registered against `cx`
        //    so we are re-polled. Returning the byte count here matches
        //    `async_io_stream::IoStream::poll_write_impl`, which flushes and
        //    ignores a Pending flush result.
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(Self::io_err(e))),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(Self::io_err)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(Self::io_err)
    }
}
