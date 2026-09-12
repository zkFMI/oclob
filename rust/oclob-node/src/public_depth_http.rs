//! Read-only HTTP adapter for the authenticated public TLS feed. No financial
//! methods, disk publication access, corporate credentials, or stale cache.
//! HTTP framing is provided by tiny_http 0.12.0 (MIT OR Apache-2.0), not a
//! project-owned parser: https://github.com/tiny-http/tiny-http.
use crate::market_network::MarketEndpoint;
use crate::network::ClusterPublicConfig;
use crate::public_depth::FinalizedPublicBook;
use crate::public_depth_network::fetch;
use std::net::SocketAddr;
use std::path::Path;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

pub fn serve(
    address: SocketAddr,
    endpoint: &MarketEndpoint,
    ca: &Path,
    cluster: &ClusterPublicConfig,
) -> Result<(), String> {
    let server = Server::http(address).map_err(|e| e.to_string())?;
    for request in server.incoming_requests() {
        respond(request, endpoint, ca, cluster);
    }
    Ok(())
}

fn minimum_sequence(url: &str) -> Result<Option<u64>, ()> {
    if url == "/v1/book" {
        return Ok(Some(0));
    }
    let Some((path, query)) = url.split_once('?') else {
        return Ok(None);
    };
    if path != "/v1/book" {
        return Ok(None);
    }
    let value = query.strip_prefix("minimum_sequence=").ok_or(())?;
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|v| v.is_ascii_digit()) {
        return Err(());
    }
    value.parse().map(Some).map_err(|_| ())
}

// Decimal strings preserve the full u64 range in browsers. This is a display
// projection AFTER signature/finality verification, not a second source of truth.
fn browser_view(book: &FinalizedPublicBook) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "market": book.market_id,
        "sequence": book.sequence.to_string(),
        "round": hex::encode(book.round_id),
        "levels": book.levels.iter().map(|level| serde_json::json!({
            "side": level.side, "price": level.price.to_string(),
            "quantity": level.quantity.to_string()
        })).collect::<Vec<_>>(),
        "nodes": book.attestations.iter().map(|attestation| serde_json::json!({
            "party": attestation.party,
            "signer": hex::encode(attestation.signer),
            "issued_at": attestation.issued_at.to_string(),
            "valid_until": attestation.valid_until.to_string(),
            "settlement_required": attestation.settlement_required,
        })).collect::<Vec<_>>(),
        "finality": book.finality_receipts.iter().map(|receipt| serde_json::json!({
            "party": receipt.party,
            "height": receipt.canonical_height.to_string(),
            "receipt": hex::encode(receipt.canonical_receipt_digest),
        })).collect::<Vec<_>>()
    })
}

fn static_asset(url: &str) -> Option<(&'static str, &'static [u8])> {
    match url.split('?').next()? {
        "/" => Some((
            "text/html; charset=utf-8",
            include_bytes!("../../../oclob_demo/static/native.html"),
        )),
        "/react-flow.js" => Some((
            "text/javascript; charset=utf-8",
            include_bytes!("../../../oclob_demo/static/react-flow.js"),
        )),
        "/react-flow.css" => Some((
            "text/css; charset=utf-8",
            include_bytes!("../../../oclob_demo/static/react-flow.css"),
        )),
        _ => None,
    }
}

fn respond(request: Request, endpoint: &MarketEndpoint, ca: &Path, cluster: &ClusterPublicConfig) {
    let no_body = request.body_length().unwrap_or(0) == 0
        && !request
            .headers()
            .iter()
            .any(|h| h.field.equiv("Transfer-Encoding"));
    if request.method() == &Method::Get && no_body {
        if let Some((content_type, bytes)) = static_asset(request.url()) {
            let mut response = Response::from_data(bytes);
            for (name, value) in [
                ("Content-Type", content_type), ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
                ("Referrer-Policy", "no-referrer"),
            ] { response.add_header(Header::from_bytes(name, value).expect("static header")); }
            let _ = request.respond(response);
            return;
        }
    }
    let view = request.url() == "/v1/book/view" || request.url().starts_with("/v1/book/view?");
    let canonical_url = if view {
        request.url().replacen("/v1/book/view", "/v1/book", 1)
    } else {
        request.url().to_owned()
    };
    let (status, body) = if request.method() != &Method::Get {
        (405, r#"{"error":"method_not_allowed"}"#.to_owned())
    } else if request.body_length().unwrap_or(0) != 0
        || request
            .headers()
            .iter()
            .any(|h| h.field.equiv("Transfer-Encoding"))
    {
        (400, r#"{"error":"request_body_not_allowed"}"#.to_owned())
    } else {
        match minimum_sequence(&canonical_url) {
            Err(()) => (400, r#"{"error":"invalid_minimum_sequence"}"#.to_owned()),
            Ok(None) => (404, r#"{"error":"not_found"}"#.to_owned()),
            Ok(Some(minimum)) => match fetch(endpoint, ca, cluster, minimum).and_then(|book| {
                if view {
                    serde_json::to_string(&browser_view(&book))
                } else {
                    serde_json::to_string(&book)
                }
                .map_err(|e| e.to_string())
            }) {
                Ok(body) => (200, format!("{body}\n")),
                // No endpoint details, private configuration, or substituted
                // empty/stale book in a failure response.
                Err(_) => (503, r#"{"error":"verified_book_unavailable"}"#.to_owned()),
            },
        }
    };
    let mut response = Response::from_string(body).with_status_code(StatusCode(status));
    for (name, value) in [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Connection", "close"),
    ] {
        response.add_header(Header::from_bytes(name, value).expect("static header"));
    }
    if status == 405 {
        response.add_header(Header::from_bytes("Allow", "GET").expect("static header"));
    }
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    fn minimum_sequence_is_strict_and_lossless() {
        assert_eq!(minimum_sequence("/v1/book"), Ok(Some(0)));
        assert_eq!(
            minimum_sequence("/v1/book?minimum_sequence=18446744073709551615"),
            Ok(Some(u64::MAX))
        );
        for query in [
            "",
            "minimum_sequence=",
            "minimum_sequence=-1",
            "minimum_sequence=+1",
            "minimum_sequence=1.0",
            "minimum_sequence=18446744073709551616",
            "minimum_sequence=%31",
            "minimum_sequence=1&minimum_sequence=0",
            "minimum_sequence=1&extra=2",
            "unknown=0",
        ] {
            assert_eq!(minimum_sequence(&format!("/v1/book?{query}")), Err(()));
        }
        assert_eq!(minimum_sequence("/v1/book/"), Ok(None));
        assert_eq!(minimum_sequence("/v1/orders?minimum_sequence=0"), Ok(None));
    }

    // Wire-level HTTP unit tests only. Empty synthetic configuration and an
    // invalid endpoint deliberately cannot supply a financial/public snapshot.
    fn request_wire(wire: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = Server::from_listener(listener, None).unwrap();
        let worker = std::thread::spawn(move || {
            let request = server
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            let cluster = ClusterPublicConfig {
                version: 3,
                deployment_crypto_policy: crate::deployment_policy::test_policy(),
                market_id: "unit-only".into(),
                program: "oclob_match_v1".into(),
                settlement_release_threshold: 3,
                nodes: Vec::new(),
            };
            let endpoint = MarketEndpoint {
                host: String::new(),
                port: 0,
                server_name: String::new(),
                certificate_sha256: [0; 32],
            };
            respond(
                request,
                &endpoint,
                Path::new("/unit-only-missing-ca"),
                &cluster,
            );
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(wire.as_bytes()).unwrap();
        let mut result = String::new();
        client.read_to_string(&mut result).unwrap();
        worker.join().unwrap();
        result
    }

    #[test]
    fn http_failures_are_json_uncached_and_do_not_expose_upstream_errors() {
        for (target, code, message) in [
            ("/v1/book", 503, "verified_book_unavailable"),
            ("/unknown", 404, "not_found"),
            (
                "/v1/book?minimum_sequence=bad",
                400,
                "invalid_minimum_sequence",
            ),
        ] {
            let response = request_wire(&format!(
                "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            ));
            assert!(response.starts_with(&format!("HTTP/1.1 {code}")));
            let (headers, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(headers
                .to_ascii_lowercase()
                .contains("cache-control: no-store"));
            assert!(headers
                .to_ascii_lowercase()
                .contains("content-type: application/json"));
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(body).unwrap(),
                serde_json::json!({"error":message})
            );
            assert!(!response.contains("unit-only-missing-ca"));
        }
    }

    #[test]
    fn http_rejects_financial_methods_and_get_bodies() {
        let post = request_wire("POST /v1/book HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        assert!(post.starts_with("HTTP/1.1 405"));
        assert!(post.to_ascii_lowercase().contains("allow: get"));
        let body = request_wire("GET /v1/book HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx");
        assert!(body.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn native_shell_is_same_origin_allowlisted_and_not_legacy_state() {
        let shell =
            request_wire("GET /?lang=ja HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert!(shell.starts_with("HTTP/1.1 200"));
        assert!(shell.contains("id=\"native-root\""));
        assert!(!shell.contains("/app.js"));
        assert!(shell
            .to_ascii_lowercase()
            .contains("frame-ancestors 'none'"));
        assert!(static_asset("/react-flow.js").is_some());
        assert!(static_asset("/react-flow.css").is_some());
        assert!(static_asset("/../Cargo.toml").is_none());
        assert!(static_asset("/api/state").is_none());
        for path in ["/v1/book/view", "/v1/book/view?minimum_sequence=4"] {
            let response = request_wire(&format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            ));
            assert!(response.starts_with("HTTP/1.1 503"));
        }
    }

    #[test]
    fn browser_projection_encodes_integers_without_javascript_rounding() {
        // Serialization unit fixture, deliberately not a signed/valid book.
        // Production calls browser_view only after fetch verifies the source.
        let book = FinalizedPublicBook {
            version: 1,
            market_id: "unit-only".into(),
            sequence: u64::MAX,
            round_id: [1; 32],
            levels: vec![oclob_core::MpcPriceLevel {
                side: oclob_core::Side::Sell,
                price: 101,
                quantity: 30,
            }],
            attestations: Vec::new(),
            finality_receipts: Vec::new(),
        };
        let view = browser_view(&book);
        assert_eq!(view["sequence"], "18446744073709551615");
        assert_eq!(view["levels"][0]["price"], "101");
        assert_eq!(view["levels"][0]["quantity"], "30");
        assert_eq!(view["levels"][0]["side"], "sell");
        assert!(view.get("private_state_sha256").is_none());
    }
}
