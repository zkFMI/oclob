use oclob_node::market_network::MarketEndpoint;
use oclob_node::network::ClusterPublicConfig;
use oclob_node::public_depth_network::{fetch, serve};
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

fn main() {
    if let Err(e) = run() {
        eprintln!("public book unavailable: {e}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let cluster: ClusterPublicConfig =
        serde_json::from_slice(&std::fs::read("/public/cluster.json").map_err(err)?)
            .map_err(err)?;
    cluster.validate().map_err(err)?;
    let endpoint: MarketEndpoint =
        serde_json::from_slice(&std::fs::read("/public/book-endpoint.json").map_err(err)?)
            .map_err(err)?;
    if args.len() == 2 && args[0] == "--http" {
        return oclob_node::public_depth_http::serve(
            args[1].parse().map_err(err)?,
            &endpoint,
            Path::new("/public/ca.pem"),
            &cluster,
        );
    }
    if args.len() == 2 && args[0] == "--get" {
        // Client mode loads no private identity or journal, even transiently.
        let minimum = args[1].parse().map_err(err)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match fetch(&endpoint, Path::new("/public/ca.pem"), &cluster, minimum) {
                Ok(book) => {
                    println!("{}", serde_json::to_string(&book).map_err(err)?);
                    return Ok(());
                }
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }
    if !args.is_empty() {
        return Err("usage: oclob-public-book [--get MINIMUM_SEQUENCE | --http IP:PORT]".into());
    }
    serve(
        TcpListener::bind(("0.0.0.0", endpoint.port)).map_err(err)?,
        Path::new("/book-identity/tls.pem"),
        Path::new("/book-identity/tls-key.pem"),
        Path::new("/market-public/current.json"),
        &cluster,
    )
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
