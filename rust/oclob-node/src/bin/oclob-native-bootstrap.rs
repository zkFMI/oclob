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
    cluster.validate()?;
    let output_path = std::path::Path::new(&args[2]);
    let pq_output_path = output_path.with_extension("pq.json");
    let marker = oclob_node::deployment_policy::marker_next_to(output_path)?;
    oclob_node::deployment_policy::initialize_fresh_state(
        &marker,
        &cluster.deployment_crypto_policy,
        &[output_path, &pq_output_path],
    )?;
    for path in [output_path, pq_output_path.as_path()] {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(format!(
                    "existing committee state at {}; explicit migration is required",
                    path.display()
                )
                .into())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    oclob_node::deployment_policy::require_proof_backend(
        &cluster.deployment_crypto_policy,
        zkfmi_crypto::mode::ProofSecurity::Classical,
    )?;
    let identity: ClientIdentityConfig = serde_json::from_slice(&std::fs::read(&args[1])?)?;
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
        .chain_update(cluster.deployment_crypto_policy.encode()?)
        .chain_update(cluster.market_id.as_bytes())
        .finalize()
        .into();
    let public = setup_frost(&mut parties, session)?;
    let pq_committee = zkpi_committee::frost_coordinator::read_pq_committee(&mut parties, &public)?;
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(output_path)?;
    output.write_all(&public.serialize()?)?;
    output.sync_all()?;
    let mut pq_output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(pq_output_path)?;
    pq_output.write_all(&serde_json::to_vec(&pq_committee)?)?;
    pq_output.sync_all()?;
    println!("native committee established by seven resident proof nodes");
    Ok(())
}
