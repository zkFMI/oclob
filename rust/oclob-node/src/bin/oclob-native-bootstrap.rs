//! Pin a real resident-node DKG before either corporate process reserves funds.
use oclob_node::network::{ClientIdentityConfig, ClusterPublicConfig};
use oclob_settlement::collaborative::setup_frost;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;
use zkpi_committee::node_service::client_ssl_context;
use zkpi_committee::proof_client::ProofPartyTlsClient;

fn main() {
    if let Err(error) = run() {
        eprintln!("native bootstrap failed: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: oclob-native-bootstrap CLUSTER IDENTITY PUBLIC-OUTPUT".into());
    }
    let cluster: ClusterPublicConfig = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    let identity: ClientIdentityConfig = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    cluster.validate()?;
    identity.validate()?;
    let tls = client_ssl_context(
        identity.tls_certificate,
        identity.tls_private_key,
        identity.tls_ca,
    )?;
    let mut parties = cluster
        .nodes
        .iter()
        .map(|node| {
            ProofPartyTlsClient::new(
                &node.host,
                node.proof_port,
                tls.clone(),
                &node.server_name,
                Duration::from_secs(120),
            )
        })
        .collect::<Vec<_>>();
    let session: [u8; 32] = Sha256::new()
        .chain_update(b"OCLOB:NATIVE:DKG:v1")
        .chain_update(cluster.market_id.as_bytes())
        .finalize()
        .into();
    let public = setup_frost(&mut parties, session)?;
    let pq_committee = zkpi_committee::frost_coordinator::read_pq_committee(&mut parties, &public)?;
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(&args[2])?;
    output.write_all(&public.serialize()?)?;
    output.sync_all()?;
    let mut pq_output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(std::path::Path::new(&args[2]).with_extension("pq.json"))?;
    pq_output.write_all(&serde_json::to_vec(&pq_committee)?)?;
    pq_output.sync_all()?;
    println!("native committee established by seven resident proof nodes");
    Ok(())
}
