//! Authenticated corporate service; issuer and market keys are not loaded.
use oclob_node::corporate::CorporateNativeConfig;
use oclob_node::corporate_api::{
    self, CorporateApi, CorporateApiConfig, CorporateRequest, CorporateResponse,
};
use oclob_node::corporate_dispatch::NativeCorporateDispatch;
use oclob_node::corporate_journal::NativeCorporateJournal;
use oclob_node::network::{
    load_secret_32, server_tls_context, ClientIdentityConfig, ClusterPublicConfig,
};
use serde::de::DeserializeOwned;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn main() {
    if run().is_err() {
        eprintln!("corporate API failed; inspect private corporate configuration");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let service: CorporateApiConfig = read(&env_path("OCLOB_CORPORATE_API_CONFIG")?, false)?;
    let identity: ClientIdentityConfig = read(Path::new("/identity/client.json"), true)?;
    identity.validate().map_err(|e| e.to_string())?;
    if !args.is_empty() {
        if !(args.len() == 1 || args.len() == 2 && args[0] == "--expect-locked") {
            return Err("invalid arguments".into());
        }
        let request = match args[0].as_str() {
            "--status" | "--ping" | "--expect-denied" => CorporateRequest::QueueStatus,
            "--wallet" | "--expect-locked" => CorporateRequest::WalletSnapshot,
            _ => return Err("invalid arguments".into()),
        };
        let response = corporate_api::call(&service.endpoint, &identity, &request);
        if args[0] == "--expect-denied" {
            if response.is_ok() {
                return Err("unauthorized access succeeded".into());
            }
            println!("{}", serde_json::json!({"access_denied":true}));
            return Ok(());
        }
        let response = response?;
        if matches!(response, CorporateResponse::Rejected) {
            return Err("request rejected".into());
        }
        if args[0] == "--ping" {
            if !matches!(response, CorporateResponse::Queue { .. }) {
                return Err("unexpected response".into());
            }
            println!("{}", serde_json::json!({"ready":true}));
            return Ok(());
        }
        if args[0] == "--expect-locked" {
            let expected = args
                .get(1)
                .ok_or("expected amount missing")?
                .parse::<u128>()
                .map_err(|_| "invalid expected amount")?
                .to_string();
            let CorporateResponse::Wallet { snapshot } = response else {
                return Err("unexpected response".into());
            };
            let asset = snapshot["facility"]["asset_id"]
                .as_str()
                .ok_or("asset missing")?;
            let own = snapshot["assets"]
                .as_array()
                .ok_or("assets missing")?
                .iter()
                .find(|a| a["asset_id"] == asset)
                .ok_or("own asset missing")?;
            if own["locked"] != expected
                || snapshot["facility"]["held"] != expected
                || snapshot["scope"] != "canonical_notes_and_reservation_heads"
            {
                return Err(
                    "canonical locked amount differs from expected current remainder".into(),
                );
            }
            println!(
                "{}",
                serde_json::json!({"wallet_lock_matches_expected":true})
            );
            return Ok(());
        }
        println!(
            "{}",
            serde_json::to_string(&response).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let cluster: ClusterPublicConfig = read(Path::new("/public/cluster.json"), false)?;
    cluster.validate().map_err(|e| e.to_string())?;
    let journal_path = env_path("OCLOB_CORPORATE_JOURNAL")?;
    let policy_marker = oclob_node::deployment_policy::marker_next_to(&journal_path)?;
    oclob_node::deployment_policy::require_existing_state(
        &policy_marker,
        &cluster.deployment_crypto_policy,
    )?;
    oclob_node::deployment_policy::require_proof_backend(
        &cluster.deployment_crypto_policy,
        zkfmi_crypto::mode::ProofSecurity::Classical,
    )?;
    let config: CorporateNativeConfig = read(&env_path("OCLOB_NATIVE_RESERVATION_CONFIG")?, true)?;
    config.require_deployment_policy(&cluster)?;
    NativeCorporateJournal::preflight_open(&journal_path, &config, &cluster)?;
    let secret =
        load_secret_32(env_path("OCLOB_CORPORATE_JOURNAL_KEY")?).map_err(|e| e.to_string())?;
    let journal = NativeCorporateJournal::open(&journal_path, &secret, &config, &cluster)?;
    let queue =
        NativeCorporateDispatch::open(journal_path.with_file_name("dispatch.enc"), &secret)?;
    let tls = server_tls_context(
        "/identity/api-tls.pem",
        "/identity/api-tls-key.pem",
        "/public/ca.pem",
    )
    .map_err(|e| e.to_string())?;
    let listener =
        TcpListener::bind(("0.0.0.0", service.endpoint.port)).map_err(|e| e.to_string())?;
    corporate_api::serve(
        listener,
        tls,
        service,
        CorporateApi {
            config,
            cluster,
            identity,
            journal,
            queue,
        },
    )
}
fn env_path(name: &str) -> Result<PathBuf, String> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} missing"))
}
fn read<T: DeserializeOwned>(path: &Path, private: bool) -> Result<T, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "input unavailable")?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.len() == 0
        || meta.len() > 1024 * 1024
        || private && meta.permissions().mode() & 0o077 != 0
    {
        return Err("unsafe input".into());
    }
    serde_json::from_slice(&fs::read(path).map_err(|_| "input unavailable")?)
        .map_err(|_| "malformed input".into())
}
