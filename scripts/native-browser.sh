#!/usr/bin/env bash
# Five native validators and the browser. Run through make remote-test.
set -euo pipefail
umask 077
: "${OCLOB_QUEUE_PASSPHRASE:?Supply a development-only outbox passphrase}"
out="${1:?usage: native-browser.sh NEW_ABSOLUTE_STATE_DIRECTORY}"
server="${OCLOB_SERVER_BIN:-/var/cache/oclob/target/release/oclob-server}"
vm="${OCLOB_VM_BIN:-/var/cache/oclob/target/release/oclob-avalanche-vm}"
runner="${AVALANCHE_NETWORK_RUNNER:-/usr/local/bin/avalanche-network-runner}"
avalanchego="${AVALANCHEGO_BIN:-/usr/local/bin/avalanchego}"
port="${OCLOB_HTTP_PORT:-18814}"
runner_port="${OCLOB_RUNNER_PORT:-18818}"
gateway_port="${OCLOB_RUNNER_GATEWAY_PORT:-18819}"
[[ "$out" = /* && "$vm" = /* ]] || { echo "Use absolute state and VM paths" >&2; exit 2; }
[[ ! -e "$out" ]] || { echo "Preserve the existing state; choose a new isolated session" >&2; exit 2; }
mkdir -m 700 -p "$out/plugins" "$out/network-logs" "$out/network-data"
vm_id="$("$vm" vmid)"
printf '#!/usr/bin/env bash\nexport OCLOB_OPTIMISTIC_VERIFIER_CONFIG=%q\nexec %q "$@"\n' "$out/verifier.json" "$vm" > "$out/plugins/$vm_id"
chmod 700 "$out/plugins/$vm_id"
export OCLOB_OPTIMISTIC_VERIFIER_CONFIG="$out/verifier.json"
export OCLOB_PUBLIC_DEVELOPMENT_NATIVE=1
endpoint="127.0.0.1:$runner_port"
server_pid=""
runner_pid=""
cleanup() {
  local result=$?
  if [[ "$result" != 0 && -f "$out/native-client.log" ]]; then
    tail -20 "$out/native-client.log" >&2
  fi
  if [[ -n "$runner_pid" ]] && kill -0 "$runner_pid" 2>/dev/null; then
    "$runner" control stop --endpoint="$endpoint" --request-timeout=30s >>"$out/network-logs/stop.log" 2>&1 || true
    kill -TERM "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$server" --host 127.0.0.1 --port "$port" --state-dir "$out" >"$out/native-client.log" 2>&1 &
server_pid=$!
for _ in {1..300}; do
  [[ -f "$out/genesis.bin" ]] && break
  kill -0 "$server_pid" || { cat "$out/native-client.log"; exit 1; }
  sleep 0.1
done
[[ -f "$out/genesis.bin" ]] || { echo "Native genesis was not prepared" >&2; exit 1; }
if "$runner" control rpc_version --endpoint="$endpoint" --request-timeout=2s >/dev/null 2>&1; then
  echo "Runner port is already in use; choose another OCLOB_RUNNER_PORT" >&2
  exit 2
fi
"$runner" server --port=":$runner_port" --grpc-gateway-port=":$gateway_port" --log-dir="$out/network-logs" >"$out/network-logs/server.log" 2>&1 &
runner_pid=$!
for _ in {1..100}; do
  "$runner" control rpc_version --endpoint="$endpoint" >/dev/null 2>&1 && break
  kill -0 "$runner_pid" || { cat "$out/network-logs/server.log"; exit 1; }
  sleep 0.1
done
spec="[{\"vm_name\":\"defmivm\",\"genesis\":\"$out/genesis.bin\"}]"
"$runner" control start --endpoint="$endpoint" --request-timeout=5m --avalanchego-path="$avalanchego" \
  --plugin-dir="$out/plugins" --root-data-dir="$out/network-data" --network-id=1337 --num-nodes=5 \
  --dynamic-ports --reassign-ports-if-used --blockchain-specs="$spec" >"$out/network-logs/start.log" 2>&1
"$runner" control wait-for-healthy --endpoint="$endpoint" --request-timeout=5m >"$out/network-logs/healthy.log" 2>&1
"$runner" control list-blockchains --endpoint="$endpoint" >"$out/network-logs/chains.log" 2>&1
"$runner" control uris --endpoint="$endpoint" >"$out/network-logs/uris.log" 2>&1
# Rust parses the runner records and validates exactly five validator URLs.
printf "Native browser: http://127.0.0.1:%s/ (see native-client.log for readiness)\n" "$port"
wait "$server_pid"
