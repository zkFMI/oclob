use std::{collections::BTreeMap, sync::Arc};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    keys: BTreeMap<u16, String>,
    policy: oclob_ordering::CommitteePolicy,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("vmid") if args.len() == 1 => {
            println!("{}", defmi_avalanche_vm::id::vm_id());
            return Ok(());
        }
        Some("version") if args.len() == 1 => {
            println!("oclob-avalanche-vm/0.1.0");
            return Ok(());
        }
        Some("genesis") => {
            let value = |flag: &str| {
                args.windows(2)
                    .find(|p| p[0] == flag)
                    .map(|p| p[1].as_str())
            };
            let input = value("--config").ok_or("genesis requires --config FILE")?;
            let raw = std::fs::read(input).map_err(|e| e.to_string())?;
            if raw.len() > 1024 * 1024 {
                return Err("genesis config exceeds its bound".into());
            }
            let config: defmi_avalanche_vm::genesis::GenesisConfig =
                serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            let encoded = config.into_genesis()?.encode()?;
            if let Some(output) = value("--out").filter(|p| *p != "-") {
                std::fs::write(output, encoded).map_err(|e| e.to_string())?;
            } else {
                use std::io::Write;
                std::io::stdout()
                    .write_all(&encoded)
                    .map_err(|e| e.to_string())?;
            }
            return Ok(());
        }
        Some(_) => return Err("unknown OCLOB VM command".into()),
        None => {}
    }
    // Validator deployment configuration, not transaction-supplied trust keys.
    let path = std::env::var("OCLOB_OPTIMISTIC_VERIFIER_CONFIG")
        .map_err(|_| "OCLOB_OPTIMISTIC_VERIFIER_CONFIG is required")?;
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    if raw.is_empty() || raw.len() > 1024 * 1024 {
        return Err("OCLOB verifier config exceeds its bound".into());
    }
    let config: Config = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let keys = config
        .keys
        .into_iter()
        .map(|(id, raw)| {
            let raw: [u8; 32] = hex::decode(raw)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "OCLOB key fingerprint is not 32 bytes")?;
            Ok((
                id,
                oclob_core::application_crypto::VerifyingKey::from_bytes(&raw)
                    .map_err(|e| e.to_string())?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let runtime = oclob_avalanche_vm::OclobRuntime::new(keys, config.policy)?;
    defmi_avalanche_vm::serve(defmi_avalanche_vm::QommVm::with_application(Arc::new(
        runtime,
    )))
    .await
}
