//! TLS 1.3 server (stage 2): the real `picoserve` HTTP app behind HTTPS.
//!
//! The device mints its own CA + server certificate on first boot
//! (`pm_core::pki`) and keeps them in the `tls` partition; later boots reload
//! the stored material. The serving path wraps the unbuffered `rustls`
//! connection in a [`picoserve::io::Socket`] so the same router that answers
//! plaintext HTTP on port 80 is also served over TLS on port 443.
//!
//! `rustls-rustcrypto` provides the crypto (no C toolchain); the `getrandom`
//! crate has no Xtensa backend, so `rand_core`'s `OsRng` — used for ECDSA
//! nonces and the ECDHE key — is backed by the hardware TRNG below.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use embassy_net::Stack;
use embassy_net::tcp::TcpSocket;
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex as Cs;
use esp_storage::FlashStorage;
use getrandom::register_custom_getrandom;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::UnbufferedServerConnection;
use rustls::time_provider::TimeProvider;
use rustls::unbuffered::{ConnectionState, UnbufferedStatus};
use rustls::{ServerConfig, version};

/// Port the HTTPS server listens on.
const TLS_PORT: u16 = 443;
/// Ciphertext staging for inbound TLS records. Must hold one full record
/// (16 KiB payload + framing/tag overhead).
const TLS_IN_BYTES: usize = 18 * 1024;
/// Ciphertext/plaintext staging for a single outgoing record.
const TLS_OUT_BYTES: usize = 18 * 1024;
/// Largest plaintext accepted into one TLS record (`rustls` fragment limit).
const TLS_MAX_PLAINTEXT: usize = 16 * 1024;
/// Socket buffers for the accepted TCP connection.
const TCP_RX_BYTES: usize = 2048;
const TCP_TX_BYTES: usize = 2048;
/// Size of the request scratch buffer used by `picoserve`.
const HTTP_BUFFER_BYTES: usize = 2048;

/// One TLS listener per allowed HTTP session.
pub const TLS_TASK_POOL_SIZE: usize = crate::http::MAX_SESSIONS;

/// I/O error type for the TLS-backed socket.
#[derive(Debug)]
pub struct TlsError;

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("tls i/o error")
    }
}

impl core::error::Error for TlsError {}

impl picoserve::io::Error for TlsError {
    fn kind(&self) -> picoserve::io::ErrorKind {
        picoserve::io::ErrorKind::Other
    }
}

/// What the caller must do after one `process_tls_records` step.
enum Step {
    /// Call `process_tls_records` again.
    Continue,
    /// Write `outgoing[..n]` to the peer, then continue.
    Flush(usize),
    /// Write `outgoing[..n]` to the peer, then return `Ok(take)`.
    Wrote(usize),
    /// Read more ciphertext from the peer.
    NeedRead,
    /// The peer cleanly closed the connection.
    Eof,
    /// Unrecoverable error.
    Fail,
    /// Nothing more to do.
    Done,
}

/// A buffered TLS 1.3 stream over a TCP socket, driven by the unbuffered
/// `rustls` state machine.
///
/// `incoming` holds ciphertext read from the peer; `plain` holds decrypted
/// application data not yet handed to the HTTP layer; `outgoing` stages
/// encoded handshake records and encrypted application data.
struct TlsStream<'s> {
    conn: UnbufferedServerConnection,
    socket: TcpSocket<'s>,
    incoming: Vec<u8>,
    in_start: usize,
    in_end: usize,
    outgoing: Vec<u8>,
    plain: VecDeque<u8>,
}

/// Writes the whole slice to the socket, looping over partial writes.
async fn write_all(socket: &mut TcpSocket<'_>, mut buf: &[u8]) -> Result<(), TlsError> {
    while !buf.is_empty() {
        let n = socket.write(buf).await.map_err(|_| TlsError)?;
        if n == 0 {
            return Err(TlsError);
        }
        buf = &buf[n..];
    }
    Ok(())
}

impl<'s> TlsStream<'s> {
    fn new(conn: UnbufferedServerConnection, socket: TcpSocket<'s>) -> Self {
        Self {
            conn,
            socket,
            incoming: vec![0u8; TLS_IN_BYTES],
            in_start: 0,
            in_end: 0,
            outgoing: vec![0u8; TLS_OUT_BYTES],
            plain: VecDeque::new(),
        }
    }

    /// Shifts unconsumed ciphertext to the front of the buffer.
    fn compact(&mut self) {
        if self.in_start > 0 {
            self.incoming.copy_within(self.in_start..self.in_end, 0);
            self.in_end -= self.in_start;
            self.in_start = 0;
        }
    }

    /// Reads more ciphertext from the peer. Returns the number of bytes read
    /// (0 on clean EOF).
    async fn fill_incoming(&mut self) -> Result<usize, TlsError> {
        self.compact();
        if self.in_end == self.incoming.len() {
            // A single TLS record larger than the buffer cannot be framed.
            return Err(TlsError);
        }
        let n = self
            .socket
            .read(&mut self.incoming[self.in_end..])
            .await
            .map_err(|_| TlsError)?;
        self.in_end += n;
        Ok(n)
    }

    /// Decrypts and returns the next available application-data bytes.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            if !self.plain.is_empty() {
                let n = buf.len().min(self.plain.len());
                for slot in &mut buf[..n] {
                    *slot = self.plain.pop_front().unwrap_or(0);
                }
                return Ok(n);
            }

            let mut discard;
            let mut step = Step::Continue;
            {
                let UnbufferedStatus { discard: d, state } = self
                    .conn
                    .process_tls_records(&mut self.incoming[self.in_start..self.in_end]);
                discard = d;

                match state {
                    Ok(ConnectionState::ReadTraffic(mut traffic)) => {
                        while let Some(record) = traffic.next_record() {
                            match record {
                                Ok(record) => {
                                    discard += record.discard;
                                    self.plain.extend(record.payload.iter().copied());
                                }
                                Err(e) => {
                                    log::warn!("tls: decrypt error: {e}");
                                    step = Step::Fail;
                                }
                            }
                        }
                    }
                    Ok(ConnectionState::EncodeTlsData(mut encoder)) => {
                        match encoder.encode(&mut self.outgoing) {
                            Ok(n) => step = Step::Flush(n),
                            Err(e) => {
                                log::warn!("tls: encode error: {e}");
                                step = Step::Fail;
                            }
                        }
                    }
                    Ok(ConnectionState::TransmitTlsData(tx)) => tx.done(),
                    Ok(ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_)) => {
                        step = Step::NeedRead;
                    }
                    Ok(ConnectionState::PeerClosed | ConnectionState::Closed) => step = Step::Eof,
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("tls: handshake error: {e}");
                        step = Step::Fail;
                    }
                }
            }
            self.in_start += discard;

            match step {
                Step::Continue | Step::Wrote(_) | Step::Done => {}
                Step::Flush(n) => {
                    write_all(&mut self.socket, &self.outgoing[..n]).await?;
                }
                Step::NeedRead => {
                    if self.fill_incoming().await? == 0 {
                        return Ok(0);
                    }
                }
                Step::Eof => return Ok(0),
                Step::Fail => return Err(TlsError),
            }
        }
    }

    /// Encrypts and sends up to one record of `buf`, returning how many plaintext
    /// bytes were consumed.
    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let take = buf.len().min(TLS_MAX_PLAINTEXT);

        loop {
            let mut discard;
            let mut step = Step::Continue;
            {
                let UnbufferedStatus { discard: d, state } = self
                    .conn
                    .process_tls_records(&mut self.incoming[self.in_start..self.in_end]);
                discard = d;

                match state {
                    Ok(ConnectionState::WriteTraffic(mut traffic)) => {
                        match traffic.encrypt(&buf[..take], &mut self.outgoing) {
                            Ok(n) => step = Step::Wrote(n),
                            Err(e) => {
                                log::warn!("tls: encrypt error: {e}");
                                step = Step::Fail;
                            }
                        }
                    }
                    Ok(ConnectionState::EncodeTlsData(mut encoder)) => {
                        match encoder.encode(&mut self.outgoing) {
                            Ok(n) => step = Step::Flush(n),
                            Err(e) => {
                                log::warn!("tls: encode error: {e}");
                                step = Step::Fail;
                            }
                        }
                    }
                    Ok(ConnectionState::TransmitTlsData(tx)) => tx.done(),
                    Ok(ConnectionState::ReadTraffic(mut traffic)) => {
                        while let Some(record) = traffic.next_record() {
                            if let Ok(record) = record {
                                discard += record.discard;
                                self.plain.extend(record.payload.iter().copied());
                            }
                        }
                    }
                    Ok(ConnectionState::BlockedHandshake) => {
                        step = Step::NeedRead;
                    }
                    Ok(ConnectionState::PeerClosed | ConnectionState::Closed) => step = Step::Fail,
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("tls: error: {e}");
                        step = Step::Fail;
                    }
                }
            }
            self.in_start += discard;

            match step {
                Step::Wrote(n) => {
                    write_all(&mut self.socket, &self.outgoing[..n]).await?;
                    return Ok(take);
                }
                Step::Flush(n) => {
                    write_all(&mut self.socket, &self.outgoing[..n]).await?;
                }
                Step::Continue => {}
                Step::NeedRead => {
                    if self.fill_incoming().await? == 0 {
                        return Err(TlsError);
                    }
                }
                Step::Eof | Step::Fail | Step::Done => return Err(TlsError),
            }
        }
    }

    async fn flush(&mut self) -> Result<(), TlsError> {
        self.socket.flush().await.map_err(|_| TlsError)
    }

    /// Sends a TLS `close_notify`, flushes and closes the socket.
    async fn shutdown(mut self) {
        let mut sent = false;
        for _ in 0..8 {
            let discard;
            let step;
            {
                let UnbufferedStatus { discard: d, state } = self
                    .conn
                    .process_tls_records(&mut self.incoming[self.in_start..self.in_end]);
                discard = d;

                match state {
                    Ok(ConnectionState::WriteTraffic(mut traffic)) => {
                        match traffic.queue_close_notify(&mut self.outgoing) {
                            Ok(n) => {
                                step = Step::Flush(n);
                                sent = true;
                            }
                            Err(_) => step = Step::Done,
                        }
                    }
                    Ok(ConnectionState::EncodeTlsData(mut encoder)) => {
                        match encoder.encode(&mut self.outgoing) {
                            Ok(n) => step = Step::Flush(n),
                            Err(_) => step = Step::Done,
                        }
                    }
                    Ok(ConnectionState::TransmitTlsData(tx)) => {
                        tx.done();
                        step = Step::Continue;
                    }
                    _ => step = Step::Done,
                }
            }
            self.in_start += discard;

            match step {
                Step::Flush(n) => {
                    let _ = write_all(&mut self.socket, &self.outgoing[..n]).await;
                    if sent {
                        break;
                    }
                }
                Step::Continue => {}
                _ => break,
            }
        }

        // Wait until the final bytes are ACKed; dropping the socket earlier makes
        // the stack emit RST and the client loses the response.
        let _ = self.socket.flush().await;
        self.socket.close();
    }
}

/// Read half of the TLS-backed socket.
struct TlsReadHalf<'a, 's> {
    stream: &'a RefCell<TlsStream<'s>>,
}

/// Write half of the TLS-backed socket.
struct TlsWriteHalf<'a, 's> {
    stream: &'a RefCell<TlsStream<'s>>,
}

impl picoserve::io::ErrorType for TlsReadHalf<'_, '_> {
    type Error = TlsError;
}

#[allow(
    clippy::await_holding_refcell_ref,
    reason = "picoserve drives one half at a time; the borrow is uncontended"
)]
impl picoserve::io::Read for TlsReadHalf<'_, '_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        self.stream.borrow_mut().read(buf).await
    }
}

impl picoserve::io::ErrorType for TlsWriteHalf<'_, '_> {
    type Error = TlsError;
}

#[allow(
    clippy::await_holding_refcell_ref,
    reason = "picoserve drives one half at a time, so the borrow is uncontended"
)]
impl picoserve::io::Write for TlsWriteHalf<'_, '_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        self.stream.borrow_mut().write(buf).await
    }

    async fn flush(&mut self) -> Result<(), TlsError> {
        self.stream.borrow_mut().flush().await
    }
}

/// A [`picoserve`] connection backed by TLS. The read and write halves share the
/// single `rustls` state machine; `picoserve` only ever drives one half at a
/// time, so the interior mutability is uncontended.
struct TlsSocket<'s> {
    stream: RefCell<TlsStream<'s>>,
}

impl<'s> picoserve::io::Socket<picoserve::EmbassyRuntime> for TlsSocket<'s> {
    type Error = TlsError;
    type ReadHalf<'a>
        = TlsReadHalf<'a, 's>
    where
        's: 'a;
    type WriteHalf<'a>
        = TlsWriteHalf<'a, 's>
    where
        's: 'a;

    fn split(&mut self) -> (Self::ReadHalf<'_>, Self::WriteHalf<'_>) {
        let stream: &RefCell<TlsStream<'s>> = &self.stream;
        (TlsReadHalf { stream }, TlsWriteHalf { stream })
    }

    async fn abort<T: picoserve::Timer<picoserve::EmbassyRuntime>>(
        self,
        _timeouts: &picoserve::Timeouts,
        _timer: &mut T,
    ) -> Result<(), picoserve::Error<TlsError>> {
        let mut stream = self.stream.into_inner();
        TcpSocket::abort(&mut stream.socket);
        Ok(())
    }

    async fn shutdown<T: picoserve::Timer<picoserve::EmbassyRuntime>>(
        self,
        _timeouts: &picoserve::Timeouts,
        _timer: &mut T,
    ) -> Result<(), picoserve::Error<TlsError>> {
        self.stream.into_inner().shutdown().await;
        Ok(())
    }
}

/// Hardware `getrandom` backend (see module docs).
#[allow(
    clippy::unnecessary_wraps,
    reason = "signature is mandated by getrandom::register_custom_getrandom!"
)]
fn esp_getrandom_fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    esp_hal::rng::Rng::new().read(buf);
    Ok(())
}
register_custom_getrandom!(esp_getrandom_fill);

/// Fixed wall clock. The device has no RTC, and the server only consults this
/// for session tickets (disabled) and client-certificate validity (none), so a
/// constant instant is sufficient.
#[derive(Debug)]
struct BootTime;

impl TimeProvider for BootTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
            1_700_000_000,
        )))
    }
}

/// DER of the root CA in use, published once at boot so the HTTP layer can hand
/// it to browsers through `/ca.pem`, `/ca.crt` and `/api/pki/info`. Empty until
/// [`load_or_generate`] runs.
static CA_CERT_DER: BlockingMutex<Cs, RefCell<Vec<u8>>> =
    BlockingMutex::new(RefCell::new(Vec::new()));

/// Publishes the root CA DER for the certificate-install endpoints.
pub fn set_ca_cert(der: &[u8]) {
    CA_CERT_DER.lock(|cell| {
        *cell.borrow_mut() = der.to_vec();
    });
}

/// Returns a copy of the root CA DER, or `None` when no material was loaded.
#[must_use]
pub fn ca_cert_der() -> Option<Vec<u8>> {
    CA_CERT_DER.lock(|cell| {
        let der = cell.borrow();
        if der.is_empty() {
            None
        } else {
            Some(der.clone())
        }
    })
}

/// Loads the stored certificate material from the `tls` partition, or mints a
/// fresh CA + server pair and stores it when the region is empty/corrupt.
///
/// The partition is read whole; [`pki::TlsMaterial::decode`] ignores the erased
/// `0xFF` slack past the container, so a truncated or absent container simply
/// reports `None` and triggers regeneration.
///
/// [`pki::TlsMaterial::decode`]: pm_core::pki::TlsMaterial::decode
pub fn load_or_generate(
    flash: &mut FlashStorage<'static>,
    base: u32,
    size: usize,
) -> Result<pm_core::pki::TlsMaterial, &'static str> {
    let mut buf = vec![0u8; size];
    if flash.read(base, &mut buf).is_ok()
        && let Some(material) = pm_core::pki::TlsMaterial::decode(&buf)
    {
        log::info!("tls: loaded stored certificate material");
        set_ca_cert(&material.ca_cert_der);
        return Ok(material);
    }

    log::info!("tls: no stored material, minting a CA and server certificate");
    let params = pm_core::pki::IssuerParams {
        ca_cn: pm_core::config::TLS_CA_CN,
        leaf_cn: pm_core::config::TLS_LEAF_CN,
        san_ip: crate::GW_IP.octets(),
        not_before: pm_core::config::TLS_VALID_FROM_UNIX,
        not_after: pm_core::config::TLS_VALID_UNTIL_UNIX,
    };
    let material = pm_core::pki::generate(&params, &mut crate::hw::EspRng::new())
        .map_err(|_| "certificate generation failed")?;
    persist(flash, base, size, &material.encode())?;
    log::info!("tls: certificate material generated and stored");
    set_ca_cert(&material.ca_cert_der);
    Ok(material)
}

/// Erases the `tls` region and writes `blob` with NOR semantics.
///
/// `erase` needs sector-aligned bounds and `write_nor` needs word-aligned
/// bounds, so the blob is padded to a word with erased (`0xFF`) bytes.
fn persist(
    flash: &mut FlashStorage<'static>,
    base: u32,
    size: usize,
    blob: &[u8],
) -> Result<(), &'static str> {
    if blob.len() > size {
        return Err("certificate material exceeds the tls partition");
    }

    flash
        .erase(base, base + size as u32)
        .map_err(|_| "failed to erase the tls partition")?;

    let word = FlashStorage::WORD_SIZE as usize;
    let mut padded = blob.to_vec();
    let remainder = padded.len() % word;
    if remainder != 0 {
        padded.resize(padded.len() + (word - remainder), 0xFF);
    }

    flash
        .write_nor(base, &padded)
        .map_err(|_| "failed to write the tls partition")
}

/// Builds a TLS 1.3-only server config with no client auth and the given leaf.
pub fn build_config(
    material: &pm_core::pki::TlsMaterial,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let cert_chain = vec![CertificateDer::from(material.leaf_cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.leaf_key_der.clone()));
    ServerConfig::builder_with_details(provider, Arc::new(BootTime))
        .with_protocol_versions(&[&version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map(Arc::new)
}

/// Accepts TLS connections on port 443 and serves the `picoserve` app over each.
#[embassy_executor::task(pool_size = TLS_TASK_POOL_SIZE)]
pub async fn tls_task(
    app: &'static picoserve::Router<crate::AppRouter>,
    stack: Stack<'static>,
    config: Arc<ServerConfig>,
) -> ! {
    let mut rx = vec![0u8; TCP_RX_BYTES];
    let mut tx = vec![0u8; TCP_TX_BYTES];
    let mut http_buffer = [0u8; HTTP_BUFFER_BYTES];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        if socket.accept(TLS_PORT).await.is_err() {
            continue;
        }

        let connection = match UnbufferedServerConnection::new(config.clone()) {
            Ok(connection) => connection,
            Err(e) => {
                log::warn!("tls: connection init error: {e}");
                socket.close();
                continue;
            }
        };

        let tls_socket = TlsSocket {
            stream: RefCell::new(TlsStream::new(connection, socket)),
        };

        let _ = picoserve::Server::new(app, &crate::SERVER_CONFIG, &mut http_buffer)
            .serve(tls_socket)
            .await;
    }
}
