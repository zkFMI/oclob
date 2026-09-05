//! Read-only, fixed-record TLS feed. Server has only the redacted publication
//! directory and its own TLS identity. Readers need a CA and pinned endpoint,
//! not corporate credentials, a settlement key or an encrypted journal.
use crate::market_network::{read_record, write_record, MarketEndpoint};
use crate::network::{certificate_fingerprint, load_owner_private_key, ClusterPublicConfig};
use crate::public_depth::{read, FinalizedPublicBook};
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};
use serde::{Deserialize, Serialize};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

const REQUEST_BYTES: usize = 1024;
const RESPONSE_BYTES: usize = 128 * 1024;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u16,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u16,
    book: Option<FinalizedPublicBook>,
}

pub fn serve(
    listener: TcpListener,
    certificate: &Path,
    key: &Path,
    path: &Path,
    cluster: &ClusterPublicConfig,
) -> Result<(), String> {
    let tls = tls_context(certificate, key)?;
    for tcp in listener.incoming().flatten() {
        let _ = exchange(tcp, &tls, path, cluster);
    }
    Ok(())
}
pub(crate) fn tls_context(certificate: &Path, key: &Path) -> Result<SslAcceptor, String> {
    let mut tls = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).map_err(err)?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(err)?;
    tls.set_certificate_chain_file(certificate).map_err(err)?;
    let private_key = load_owner_private_key(key).map_err(err)?;
    tls.set_private_key(&private_key).map_err(err)?;
    tls.check_private_key().map_err(err)?;
    // This is a separate read-only listener; the financial intake remains mTLS.
    tls.set_verify(SslVerifyMode::NONE);
    Ok(tls.build())
}
pub(crate) fn exchange(
    tcp: TcpStream,
    tls: &SslAcceptor,
    path: &Path,
    cluster: &ClusterPublicConfig,
) -> Result<(), String> {
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(err)?;
    tcp.set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(err)?;
    let mut stream = tls
        .accept(tcp)
        .map_err(|_| "public depth TLS handshake failed")?;
    let request: Request = read_record(&mut stream, REQUEST_BYTES)?;
    if request.version != 1 {
        return Err("public depth request version invalid".into());
    }
    let book = read(path)?;
    if let Some(book) = &book {
        book.verify(cluster, crate::market_runtime::now()?, 0)?;
    }
    write_record(&mut stream, &Response { version: 1, book }, RESPONSE_BYTES)
}
pub fn fetch(
    endpoint: &MarketEndpoint,
    ca: &Path,
    cluster: &ClusterPublicConfig,
    minimum_sequence: u64,
) -> Result<FinalizedPublicBook, String> {
    if endpoint.host.is_empty()
        || endpoint.port == 0
        || endpoint.server_name.is_empty()
        || endpoint.certificate_sha256 == [0; 32]
    {
        return Err("public depth endpoint invalid".into());
    }
    let mut tls = SslConnector::builder(SslMethod::tls_client()).map_err(err)?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(err)?;
    tls.set_ca_file(ca).map_err(err)?;
    tls.set_verify(SslVerifyMode::PEER);
    let address = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(err)?
        .next()
        .ok_or("public depth DNS address absent")?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(3)).map_err(err)?;
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(err)?;
    tcp.set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(err)?;
    let mut stream = tls
        .build()
        .connect(&endpoint.server_name, tcp)
        .map_err(|_| "public depth TLS handshake failed")?;
    let peer = stream
        .ssl()
        .peer_certificate()
        .ok_or("public depth TLS peer absent")?;
    if certificate_fingerprint(&peer.to_der().map_err(err)?) != endpoint.certificate_sha256 {
        return Err("public depth TLS pin mismatch".into());
    }
    write_record(&mut stream, &Request { version: 1 }, REQUEST_BYTES)?;
    let response: Response = read_record(&mut stream, RESPONSE_BYTES)?;
    if response.version != 1 {
        return Err("public depth response version invalid".into());
    }
    let book = response.book.ok_or("no finalized public book yet")?;
    book.verify(cluster, crate::market_runtime::now()?, minimum_sequence)?;
    Ok(book)
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
