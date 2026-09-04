REMOTE_TEST_HOST ?= omenx_ubuntu_zerotier
REMOTE_TEST_ALLOWED_HOSTS := omenx_ubuntu_zerotier softbank-l40s
REMOTE_TEST_REUSE_IMAGE ?= 0
REMOTE_TEST_IMAGE ?= oclob-test:rust-1.97.1-mpspdz-9d809599
REMOTE_TEST_CARGO_JOBS ?= 16
REMOTE_TEST_COMMAND ?= cargo test --workspace --release -j $(REMOTE_TEST_CARGO_JOBS)
REMOTE_TEST_EXPORTS ?=

.PHONY: remote-test remote-distributed-e2e remote-avalanche-e2e release-gate

remote-test:
	@case " $(REMOTE_TEST_ALLOWED_HOSTS) " in \
	  *" $(REMOTE_TEST_HOST) "*) ;; \
	  *) echo "REMOTE_TEST_HOST must be one of: $(REMOTE_TEST_ALLOWED_HOSTS)" >&2; exit 2 ;; \
	esac
	@case "$(REMOTE_TEST_REUSE_IMAGE)" in 0|1) ;; *) echo "REMOTE_TEST_REUSE_IMAGE must be 0 or 1" >&2; exit 2 ;; esac
	@set -eu; \
	remote_dir="$$(ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" 'mktemp -d /tmp/oclob-remote-test.XXXXXX')"; \
	case "$$remote_dir" in /tmp/oclob-remote-test.*) ;; *) echo "refusing unsafe remote directory: $$remote_dir" >&2; exit 2 ;; esac; \
	cleanup() { ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" "rm -rf -- '$$remote_dir'" >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT INT TERM; \
	rsync -a --compress --exclude '.git/' --exclude 'target/' --exclude 'artifacts/*.json' --exclude 'oclob_demo/react-flow/node_modules/' ./ "$(REMOTE_TEST_HOST):$$remote_dir/oclob/"; \
	ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" \
	  "set -eu; \
	   find '$$remote_dir/oclob/rust' -type f -name '*.rs' -exec touch -- {} +; \
	   touch '$$remote_dir/oclob/Cargo.toml' '$$remote_dir/oclob/Cargo.lock'; \
	   if [ '$(REMOTE_TEST_REUSE_IMAGE)' = 1 ]; then docker image inspect '$(REMOTE_TEST_IMAGE)' >/dev/null; \
	   else docker build --pull --network host --file '$$remote_dir/oclob/docker/Dockerfile' --target oclob-test --tag '$(REMOTE_TEST_IMAGE)' '$$remote_dir/oclob'; fi; \
	   docker run --rm --init --network host \
	     --mount type=bind,src='$$remote_dir/oclob',dst=/workspace \
	     --mount type=volume,src=oclob-cargo-registry,dst=/usr/local/cargo/registry \
	     --mount type=volume,src=oclob-cargo-git,dst=/usr/local/cargo/git \
	     --mount type=volume,src=oclob-npm-cache,dst=/root/.npm \
	     --mount type=volume,src=oclob-target,dst=/var/cache/oclob/target \
	     --env CARGO_TARGET_DIR=/var/cache/oclob/target \
	     --env NPM_CONFIG_CACHE=/root/.npm \
	     --workdir /workspace '$(REMOTE_TEST_IMAGE)' sh -c '$(REMOTE_TEST_COMMAND)'"; \
	for relative in $(REMOTE_TEST_EXPORTS); do \
	  case "$$relative" in ""|/*|*..*) echo "refusing unsafe export path: $$relative" >&2; exit 2 ;; esac; \
	  test -f "$$relative" || { echo "export destination must already be a file: $$relative" >&2; exit 2; }; \
	  rsync -a --compress "$(REMOTE_TEST_HOST):$$remote_dir/oclob/$$relative" "$$relative"; \
	done

remote-distributed-e2e:
	@case " $(REMOTE_TEST_ALLOWED_HOSTS) " in \
	  *" $(REMOTE_TEST_HOST) "*) ;; \
	  *) echo "REMOTE_TEST_HOST must be one of: $(REMOTE_TEST_ALLOWED_HOSTS)" >&2; exit 2 ;; \
	esac
	@set -eu; \
	remote_dir="$$(ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" 'mktemp -d /tmp/oclob-distributed.XXXXXX')"; \
	case "$$remote_dir" in /tmp/oclob-distributed.*) ;; *) echo "refusing unsafe remote directory: $$remote_dir" >&2; exit 2 ;; esac; \
	image="oclob-cluster:$$(git rev-parse --short=12 HEAD)-$$(date +%s)"; \
	cleanup() { \
	  ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" "set +e; if [ -f '$$remote_dir/oclob/deploy/docker-compose.distributed.yml' ]; then OCLOB_RUNTIME_DIR='$$remote_dir/oclob/.runtime' OCLOB_SOURCE_DIR='$$remote_dir/oclob' OCLOB_CLUSTER_IMAGE='$$image' OCLOB_UID=10001 OCLOB_GID=\$$(id -g) docker compose -f '$$remote_dir/oclob/deploy/docker-compose.distributed.yml' down --remove-orphans >/dev/null 2>&1; fi; rm -rf -- '$$remote_dir'" >/dev/null 2>&1 || true; \
	}; \
	trap cleanup EXIT INT TERM; \
	rsync -a --compress --exclude '.git/' --exclude 'target/' --exclude '.runtime/' --exclude 'oclob_demo/react-flow/node_modules/' ./ "$(REMOTE_TEST_HOST):$$remote_dir/oclob/"; \
	ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" "set -eu; \
	  gid=\$$(id -g); container_uid=10001; runtime='$$remote_dir/oclob/.runtime'; \
	  install -d -m 0770 \"\$$runtime\" \"\$$runtime/state\" \"\$$runtime/handoff\"; \
	  for party in 0 1 2 3 4 5 6; do install -d -m 0770 \"\$$runtime/state/node-\$$party\"; done; \
	  built=0; \
	  for build_attempt in 1 2 3; do \
	    if docker build --network host --file '$$remote_dir/oclob/docker/Dockerfile' --target oclob-cluster --tag '$$image' '$$remote_dir/oclob'; then built=1; break; fi; \
	    [ \"\$$build_attempt\" -eq 3 ] || sleep 3; \
	  done; \
	  [ \"\$$built\" -eq 1 ] || { echo 'OCLOB cluster image build failed after three attempts' >&2; exit 1; }; \
	  docker run --rm --user \"\$$container_uid:\$$gid\" --mount type=bind,src=\"\$$runtime\",dst=/runtime '$$image' oclob-lab-provision --out /runtime/cluster; \
	  export OCLOB_RUNTIME_DIR=\"\$$runtime\" OCLOB_SOURCE_DIR='$$remote_dir/oclob' OCLOB_CLUSTER_IMAGE='$$image' OCLOB_UID=\"\$$container_uid\" OCLOB_GID=\"\$$gid\"; \
	  compose='docker compose -f $$remote_dir/oclob/deploy/docker-compose.distributed.yml'; \
	  \$$compose config --quiet; \
	  \$$compose up -d node-0 node-1 node-2 node-3 node-4 node-5 node-6; \
	  for attempt in \$$(seq 1 60); do \
	    healthy=0; \
	    for service in node-0 node-1 node-2 node-3 node-4 node-5 node-6; do \
	      container_id=\$$(\$$compose ps -q \"\$$service\"); \
	      [ -n \"\$$container_id\" ] || continue; \
	      health=\$$(docker inspect --format='{{.State.Health.Status}}' \"\$$container_id\" 2>/dev/null || true); \
	      [ \"\$$health\" = healthy ] && healthy=\$$((healthy + 1)); \
	    done; \
	    [ \"\$$healthy\" -eq 7 ] && break; \
	    [ \"\$$attempt\" -eq 60 ] && { \$$compose ps; \$$compose logs --no-color; exit 1; }; \
	    sleep 1; \
	  done; \
	  \$$compose run --rm maker >\"\$$runtime/handoff/maker.log\" 2>&1 & maker_pid=\$$!; \
	  \$$compose run --rm taker >\"\$$runtime/handoff/taker.log\" 2>&1 & taker_pid=\$$!; \
	  wait \$$maker_pid; wait \$$taker_pid; \
	  \$$compose run --rm coordinator | tee \"\$$runtime/handoff/coordinator.log\"; \
	  test -s \"\$$runtime/handoff/oclob_distributed_e2e.json\"; \
	  cp \"\$$runtime/handoff/oclob_distributed_e2e.json\" '$$remote_dir/oclob/artifacts/oclob_distributed_e2e.json'; \
	  \$$compose ps; \
	  \$$compose down --remove-orphans"; \
	rsync -a --compress "$(REMOTE_TEST_HOST):$$remote_dir/oclob/artifacts/oclob_distributed_e2e.json" artifacts/oclob_distributed_e2e.json

remote-avalanche-e2e:
	@case " $(REMOTE_TEST_ALLOWED_HOSTS) " in \
	  *" $(REMOTE_TEST_HOST) "*) ;; \
	  *) echo "REMOTE_TEST_HOST must be one of: $(REMOTE_TEST_ALLOWED_HOSTS)" >&2; exit 2 ;; \
	esac
	@set -eu; \
	remote_dir="$$(ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" 'mktemp -d /tmp/oclob-avalanche.XXXXXX')"; \
	case "$$remote_dir" in /tmp/oclob-avalanche.*) ;; *) echo "refusing unsafe remote directory: $$remote_dir" >&2; exit 2 ;; esac; \
	image="oclob-avalanche:$$(git rev-parse --short=12 HEAD)-$$(date +%s)"; \
	cleanup() { ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" "rm -rf -- '$$remote_dir'" >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT INT TERM; \
	rsync -a --compress --exclude '.git/' --exclude 'target/' --exclude '.runtime/' --exclude 'oclob_demo/react-flow/node_modules/' ./ "$(REMOTE_TEST_HOST):$$remote_dir/oclob/"; \
	ssh -o BatchMode=yes "$(REMOTE_TEST_HOST)" "set -eu; \
	  install -d -m 0777 '$$remote_dir/out'; \
	  built=0; \
	  for build_attempt in 1 2 3; do \
	    if docker build --network host --file '$$remote_dir/oclob/docker/Dockerfile' --target oclob-avalanche-acceptance --tag '$$image' '$$remote_dir/oclob'; then built=1; break; fi; \
	    [ \"\$$build_attempt\" -eq 3 ] || sleep 3; \
	  done; \
	  [ \"\$$built\" -eq 1 ] || { echo 'OCLOB Avalanche image build failed after three attempts' >&2; exit 1; }; \
	  docker run --rm --init --network host --mount type=bind,src='$$remote_dir/out',dst=/out '$$image'; \
	  test -s '$$remote_dir/out/oclob_avalanche_acceptance.json'; \
	  cp '$$remote_dir/out/oclob_avalanche_acceptance.json' '$$remote_dir/oclob/artifacts/oclob_avalanche_acceptance.json'"; \
	rsync -a --compress "$(REMOTE_TEST_HOST):$$remote_dir/oclob/artifacts/oclob_avalanche_acceptance.json" artifacts/oclob_avalanche_acceptance.json

release-gate:
	$(MAKE) remote-test \
	  REMOTE_TEST_HOST='$(REMOTE_TEST_HOST)' \
	  REMOTE_TEST_REUSE_IMAGE='$(REMOTE_TEST_REUSE_IMAGE)' \
	  REMOTE_TEST_IMAGE='$(REMOTE_TEST_IMAGE)' \
	  REMOTE_TEST_EXPORTS='artifacts/oclob_rough_e2e.json oclob_demo/static/react-flow.js oclob_demo/static/react-flow.css' \
	  REMOTE_TEST_COMMAND='cargo fmt --all -- --check && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo clippy --workspace --all-targets -- -D warnings && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo test --workspace --release -j $(REMOTE_TEST_CARGO_JOBS) && cd oclob_demo/react-flow && npm ci --no-audit --no-fund && npm run build && node --check ../static/app.js && cd ../.. && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo run --release -p oclob-demo --bin oclob-demo -- --contract research/oclob_contract.json --manifest research/manifests/oclob_rough_e2e.json --receipt artifacts/oclob_rough_e2e.json --ledger /tmp/oclob-experiment-ledger.jsonl --mp-spdz-root /opt/MP-SPDZ'
