REMOTE_TEST_HOST ?= omenx_ubuntu_zerotier
REMOTE_TEST_SSH_OPTIONS ?= -o BatchMode=yes
REMOTE_TEST_ALLOWED_HOSTS := omenx_ubuntu_zerotier softbank-l40s
REMOTE_TEST_REUSE_IMAGE ?= 0
REMOTE_TEST_IMAGE ?= oclob-test:rust-1.97.1-mpspdz-9d809599
REMOTE_TEST_CARGO_JOBS ?= 16
REMOTE_TEST_COMMAND ?= cargo test --workspace --release -j $(REMOTE_TEST_CARGO_JOBS)
REMOTE_TEST_EXPORTS ?=
NATIVE_RECOVERY ?= 0
NATIVE_WALLET ?= 0
NATIVE_FINALITY ?= 0
NATIVE_MULTIFILL ?= 0
NATIVE_CYCLE ?= 0
NATIVE_LIFECYCLE ?= 0
NATIVE_WORKER ?= 0
NATIVE_EXPIRY ?= 0
NATIVE_DEFERRED ?= 0
NATIVE_MARKET ?= 0
NATIVE_DEPTH ?= 0
NATIVE_HTTP ?= 0
NATIVE_BROWSER ?= 0
NATIVE_CORPORATE_API ?= 0
NATIVE_HTTP_MANIFEST ?= /research/manifests/oclob_native_http_001.json
NATIVE_DEPTH_MANIFEST ?= /research/manifests/oclob_native_depth_001.json
NATIVE_WORKER_MANIFEST ?= /research/manifests/oclob_native_worker_006.json

.PHONY: remote-test remote-distributed-e2e remote-avalanche-e2e remote-integrated-e2e release-gate

remote-test:
	@case " $(REMOTE_TEST_ALLOWED_HOSTS) " in \
	  *" $(REMOTE_TEST_HOST) "*) ;; \
	  *) echo "REMOTE_TEST_HOST must be one of: $(REMOTE_TEST_ALLOWED_HOSTS)" >&2; exit 2 ;; \
	esac
	@case "$(REMOTE_TEST_REUSE_IMAGE)" in 0|1) ;; *) echo "REMOTE_TEST_REUSE_IMAGE must be 0 or 1" >&2; exit 2 ;; esac
	@set -eu; \
	remote_dir="$$(ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" 'mktemp -d /tmp/oclob-remote-test.XXXXXX')"; \
	case "$$remote_dir" in /tmp/oclob-remote-test.*) ;; *) echo "refusing unsafe remote directory: $$remote_dir" >&2; exit 2 ;; esac; \
	cleanup() { ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" "rm -rf -- '$$remote_dir'" >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT INT TERM; \
	rsync -a --compress -e "ssh $(REMOTE_TEST_SSH_OPTIONS)" --exclude '.git/' --exclude 'target/' --exclude 'artifacts/*.json' --exclude 'oclob_demo/react-flow/node_modules/' ./ "$(REMOTE_TEST_HOST):$$remote_dir/oclob/"; \
	ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" \
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
	  rsync -a --compress -e "ssh $(REMOTE_TEST_SSH_OPTIONS)" "$(REMOTE_TEST_HOST):$$remote_dir/oclob/$$relative" "$$relative"; \
	done

remote-distributed-e2e: export RSYNC_RSH = ssh $(REMOTE_TEST_SSH_OPTIONS)
remote-distributed-e2e:
	@case " $(REMOTE_TEST_ALLOWED_HOSTS) " in \
	  *" $(REMOTE_TEST_HOST) "*) ;; \
	  *) echo "REMOTE_TEST_HOST must be one of: $(REMOTE_TEST_ALLOWED_HOSTS)" >&2; exit 2 ;; \
	esac
	@set -eu; \
	remote_dir="$$(ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" 'mktemp -d /tmp/oclob-distributed.XXXXXX')"; \
	case "$$remote_dir" in /tmp/oclob-distributed.*) ;; *) echo "refusing unsafe remote directory: $$remote_dir" >&2; exit 2 ;; esac; \
	image="oclob-cluster:$$(git rev-parse --short=12 HEAD)-$$(date +%s)"; \
	cleanup() { \
	  ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" "set +e; if [ -f '$$remote_dir/oclob/deploy/docker-compose.distributed.yml' ]; then OCLOB_RUNTIME_DIR='$$remote_dir/oclob/.runtime' OCLOB_SOURCE_DIR='$$remote_dir/oclob' OCLOB_CLUSTER_IMAGE='$$image' OCLOB_UID=10001 OCLOB_GID=\$$(id -g) docker compose -f '$$remote_dir/oclob/deploy/docker-compose.distributed.yml' down --remove-orphans >/dev/null 2>&1; fi; rm -rf -- '$$remote_dir'" >/dev/null 2>&1 || true; \
	}; \
	trap cleanup EXIT INT TERM; \
	rsync -a --compress --exclude '.git/' --exclude 'target/' --exclude '.runtime/' --exclude 'oclob_demo/react-flow/node_modules/' ./ "$(REMOTE_TEST_HOST):$$remote_dir/oclob/"; \
	ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" "set -eu; \
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

remote-avalanche-e2e: export RSYNC_RSH = ssh $(REMOTE_TEST_SSH_OPTIONS)
remote-avalanche-e2e:
	@case " $(REMOTE_TEST_ALLOWED_HOSTS) " in \
	  *" $(REMOTE_TEST_HOST) "*) ;; \
	  *) echo "REMOTE_TEST_HOST must be one of: $(REMOTE_TEST_ALLOWED_HOSTS)" >&2; exit 2 ;; \
	esac
	@set -eu; \
	remote_dir="$$(ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" 'mktemp -d /tmp/oclob-avalanche.XXXXXX')"; \
	case "$$remote_dir" in /tmp/oclob-avalanche.*) ;; *) echo "refusing unsafe remote directory: $$remote_dir" >&2; exit 2 ;; esac; \
	image="oclob-avalanche:$$(git rev-parse --short=12 HEAD)-$$(date +%s)"; \
	cleanup() { ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" "rm -rf -- '$$remote_dir'" >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT INT TERM; \
	rsync -a --compress --exclude '.git/' --exclude 'target/' --exclude '.runtime/' --exclude 'oclob_demo/react-flow/node_modules/' ./ "$(REMOTE_TEST_HOST):$$remote_dir/oclob/"; \
	ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" "set -eu; \
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

remote-integrated-e2e: export RSYNC_RSH = ssh $(REMOTE_TEST_SSH_OPTIONS)
remote-integrated-e2e:
	@case " $(REMOTE_TEST_ALLOWED_HOSTS) " in \
	  *" $(REMOTE_TEST_HOST) "*) ;; \
	  *) echo "REMOTE_TEST_HOST must be one of: $(REMOTE_TEST_ALLOWED_HOSTS)" >&2; exit 2 ;; \
	esac
	@set -eu; \
	remote_dir="$$(ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" 'mktemp -d /tmp/oclob-integrated.XXXXXX')"; \
	case "$$remote_dir" in /tmp/oclob-integrated.*) ;; *) echo "refusing unsafe remote directory: $$remote_dir" >&2; exit 2 ;; esac; \
	cluster_image="oclob-cluster:$$(git rev-parse --short=12 HEAD)-$$(date +%s)"; \
	avalanche_image="oclob-integrated:$$(git rev-parse --short=12 HEAD)-$$(date +%s)"; \
	cleanup() { \
	  ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" "set +e; if [ -f '$$remote_dir/oclob/deploy/docker-compose.distributed.yml' ]; then OCLOB_RUNTIME_DIR='$$remote_dir/oclob/.runtime' OCLOB_SOURCE_DIR='$$remote_dir/oclob' OCLOB_CLUSTER_IMAGE='$$cluster_image' OCLOB_AVALANCHE_IMAGE='$$avalanche_image' OCLOB_UID=10001 OCLOB_GID=\$$(id -g) docker compose -f '$$remote_dir/oclob/deploy/docker-compose.distributed.yml' down --remove-orphans >/dev/null 2>&1; fi; rm -rf -- '$$remote_dir'" >/dev/null 2>&1 || true; \
	}; \
	trap cleanup EXIT INT TERM; \
	rsync -a --compress --exclude '.git/' --exclude 'target/' --exclude '.runtime/' --exclude 'oclob_demo/react-flow/node_modules/' ./ "$(REMOTE_TEST_HOST):$$remote_dir/oclob/"; \
	ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" "set -eu; \
	  gid=\$$(id -g); container_uid=10001; runtime='$$remote_dir/oclob/.runtime'; \
	  install -d -m 0770 \"\$$runtime\" \"\$$runtime/state\" \"\$$runtime/handoff\" \"\$$runtime/out\"; \
	  for party in 0 1 2 3 4 5 6; do install -d -m 0770 \"\$$runtime/state/node-\$$party\"; done; \
	  cluster_built=0; \
	  for build_attempt in 1 2 3; do \
	    if docker build --network host --file '$$remote_dir/oclob/docker/Dockerfile' --target oclob-cluster --tag '$$cluster_image' '$$remote_dir/oclob'; then cluster_built=1; break; fi; \
	    [ "\$$build_attempt" -eq 3 ] || sleep 3; \
	  done; \
	  [ "\$$cluster_built" -eq 1 ] || { echo 'OCLOB integrated cluster image build failed after three attempts' >&2; exit 1; }; \
	  avalanche_built=0; \
	  for build_attempt in 1 2 3; do \
	    if docker build --network host --file '$$remote_dir/oclob/docker/Dockerfile' --target oclob-avalanche-acceptance --tag '$$avalanche_image' '$$remote_dir/oclob'; then avalanche_built=1; break; fi; \
	    [ "\$$build_attempt" -eq 3 ] || sleep 3; \
	  done; \
	  [ "\$$avalanche_built" -eq 1 ] || { echo 'OCLOB integrated Avalanche image build failed after three attempts' >&2; exit 1; }; \
	  docker run --rm --user \"\$$container_uid:\$$gid\" --mount type=bind,src=\"\$$runtime\",dst=/runtime '$$cluster_image' oclob-lab-provision --out /runtime/cluster; \
	  export OCLOB_RUNTIME_DIR=\"\$$runtime\" OCLOB_SOURCE_DIR='$$remote_dir/oclob' OCLOB_CLUSTER_IMAGE='$$cluster_image' OCLOB_AVALANCHE_IMAGE='$$avalanche_image' OCLOB_UID=\"\$$container_uid\" OCLOB_GID=\"\$$gid\"; \
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
	  test -s \"\$$runtime/handoff/maker-capability.json\"; \
	  test -s \"\$$runtime/handoff/taker-capability.json\"; \
	  \$$compose run --rm settlement | tee \"\$$runtime/handoff/settlement.log\"; \
	  test -s \"\$$runtime/out/oclob_distributed_avalanche_acceptance.json\"; \
	  cp \"\$$runtime/out/oclob_distributed_avalanche_acceptance.json\" '$$remote_dir/oclob/artifacts/oclob_distributed_avalanche_acceptance.json'; \
	  \$$compose down --remove-orphans"; \
	rsync -a --compress "$(REMOTE_TEST_HOST):$$remote_dir/oclob/artifacts/oclob_distributed_avalanche_acceptance.json" artifacts/oclob_distributed_avalanche_acceptance.json

.PHONY: remote-native-e2e
.PHONY: remote-native-e2e remote-native-recovery-e2e remote-native-wallet-e2e
.PHONY: remote-native-finality-e2e
remote-native-finality-e2e:
	$(MAKE) remote-native-e2e NATIVE_WALLET=1 NATIVE_FINALITY=1
.PHONY: remote-native-multifill-e2e
remote-native-multifill-e2e:
	$(MAKE) remote-native-e2e NATIVE_MULTIFILL=1
.PHONY: remote-native-cycle-e2e
remote-native-cycle-e2e:
	$(MAKE) remote-native-e2e NATIVE_MULTIFILL=1 NATIVE_WALLET=1 NATIVE_CYCLE=1
.PHONY: remote-native-lifecycle-e2e
remote-native-lifecycle-e2e:
	$(MAKE) remote-native-e2e NATIVE_MULTIFILL=1 NATIVE_WALLET=1 NATIVE_CYCLE=1 NATIVE_LIFECYCLE=1
.PHONY: remote-native-worker-e2e
remote-native-worker-e2e:
	$(MAKE) remote-native-e2e NATIVE_MULTIFILL=1 NATIVE_WALLET=1 NATIVE_CYCLE=1 NATIVE_LIFECYCLE=1 NATIVE_WORKER=1
.PHONY: remote-native-expiry-e2e
remote-native-expiry-e2e:
	$(MAKE) remote-native-e2e NATIVE_EXPIRY=1
.PHONY: remote-native-deferred-e2e
remote-native-deferred-e2e:
	$(MAKE) remote-native-e2e NATIVE_DEFERRED=1 NATIVE_MULTIFILL=1
.PHONY: remote-native-market-e2e
remote-native-market-e2e:
	$(MAKE) remote-native-e2e NATIVE_MARKET=1
.PHONY: remote-native-http-e2e
remote-native-http-e2e:
	$(MAKE) remote-native-depth-e2e NATIVE_HTTP=1
.PHONY: remote-native-depth-e2e
remote-native-depth-e2e:
	$(MAKE) remote-native-e2e NATIVE_MARKET=1 NATIVE_DEPTH=1
remote-native-wallet-e2e:
	$(MAKE) remote-native-e2e NATIVE_WALLET=1
remote-native-recovery-e2e:
	$(MAKE) remote-native-e2e NATIVE_RECOVERY=1

remote-native-e2e: export RSYNC_RSH = ssh $(REMOTE_TEST_SSH_OPTIONS)
remote-native-e2e:
	@case " $(REMOTE_TEST_ALLOWED_HOSTS) " in *" $(REMOTE_TEST_HOST) "*) ;; *) echo 'unapproved test host' >&2; exit 2 ;; esac
	@case '$(NATIVE_RECOVERY)' in 0|1) ;; *) echo 'NATIVE_RECOVERY must be 0 or 1' >&2; exit 2 ;; esac
	@case '$(NATIVE_HTTP):$(NATIVE_DEPTH)' in 0:*|1:1) ;; *) echo 'HTTP depth requires native depth' >&2; exit 2 ;; esac
	@case '$(NATIVE_BROWSER):$(NATIVE_HTTP)' in 0:*|1:1) ;; *) echo 'native browser requires HTTP depth' >&2; exit 2 ;; esac
	@case '$(NATIVE_CORPORATE_API):$(NATIVE_HTTP)' in 0:*|1:1) ;; *) echo 'corporate API acceptance requires HTTP depth' >&2; exit 2 ;; esac
	@case '$(NATIVE_DEPTH):$(NATIVE_MARKET)' in 0:*|1:1) ;; *) echo 'public depth requires native market' >&2; exit 2 ;; esac
	@case '$(NATIVE_MARKET):$(NATIVE_RECOVERY):$(NATIVE_MULTIFILL):$(NATIVE_WALLET):$(NATIVE_EXPIRY):$(NATIVE_DEFERRED)' in 0:*|1:0:0:0:0:0) ;; *) echo 'resident market uses its separate acceptance contract' >&2; exit 2 ;; esac
	@case '$(NATIVE_WALLET):$(NATIVE_RECOVERY)' in 0:0|0:1|1:0) ;; *) echo 'choose one native acceptance variant' >&2; exit 2 ;; esac
	@case '$(NATIVE_FINALITY):$(NATIVE_WALLET)' in 0:0|0:1|1:1) ;; *) echo 'native finality acceptance requires wallet reuse' >&2; exit 2 ;; esac
	@case '$(NATIVE_LIFECYCLE):$(NATIVE_CYCLE)' in 0:*|1:1) ;; *) echo 'lifecycle requires the continuing cycle' >&2; exit 2 ;; esac
	@case '$(NATIVE_WORKER):$(NATIVE_LIFECYCLE)' in 0:*|1:1) ;; *) echo 'worker requires the full lifecycle' >&2; exit 2 ;; esac
	@case '$(NATIVE_DEFERRED):$(NATIVE_MULTIFILL):$(NATIVE_WALLET):$(NATIVE_WORKER):$(NATIVE_EXPIRY):$(NATIVE_RECOVERY)' in 0:*|1:1:0:0:0:0) ;; *) echo 'deferred intake requires its two-fill acceptance' >&2; exit 2 ;; esac
	@case '$(NATIVE_EXPIRY):$(NATIVE_RECOVERY):$(NATIVE_MULTIFILL):$(NATIVE_WALLET):$(NATIVE_WORKER)' in 0:*|1:0:0:0:0) ;; *) echo 'queued expiry uses its separate acceptance contract' >&2; exit 2 ;; esac
	@case '$(NATIVE_MULTIFILL):$(NATIVE_WALLET):$(NATIVE_RECOVERY):$(NATIVE_FINALITY):$(NATIVE_CYCLE)' in 0:*:*:*:0|1:0:0:0:0|1:1:0:0:1) ;; *) echo 'choose one native acceptance variant' >&2; exit 2 ;; esac
	@set -eu; \
	remote_dir="$$(ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" 'mktemp -d /tmp/oclob-native.XXXXXX')"; \
	case "$$remote_dir" in /tmp/oclob-native.*) ;; *) exit 2 ;; esac; \
	printf 'Native run directory: %s\n' "$$remote_dir"; \
	rsync -a --compress --exclude '.git/' --exclude 'target/' --exclude '.runtime/' --exclude 'oclob_demo/react-flow/node_modules/' ./ "$(REMOTE_TEST_HOST):$$remote_dir/oclob/"; \
	ssh $(REMOTE_TEST_SSH_OPTIONS) "$(REMOTE_TEST_HOST)" "set -eu; \
	  runtime='$$remote_dir/runtime'; install -d -m 0770 \"\$$runtime\" \"\$$runtime/state\" \"\$$runtime/handoff\" \"\$$runtime/out\"; \
	  for party in 0 1 2 3 4 5 6; do install -d -m 0770 \"\$$runtime/state/node-\$$party\"; done; \
	  export OCLOB_RUNTIME_DIR=\"\$$runtime\" OCLOB_SOURCE_DIR='$$remote_dir/oclob' OCLOB_UID=10001 OCLOB_GID=\$$(id -g); \
	  export OCLOB_CLUSTER_IMAGE='oclob-native-cluster:local' OCLOB_AVALANCHE_IMAGE='oclob-native-avalanche:local'; \
	  export COMPOSE_PROJECT_NAME='oclob-native-$$(date +%s)'; \
	  if [ '$(NATIVE_RECOVERY)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_recovery_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_recovery_001.json; fi; \
	  export OCLOB_NATIVE_WALLET='$(NATIVE_WALLET)'; \
	  if [ '$(NATIVE_MULTIFILL)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_multifill_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_multifill_002.json; fi; \
	  if [ '$(NATIVE_WALLET)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_wallet_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_wallet_003.json; fi; \
	  if [ '$(NATIVE_FINALITY)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_finality_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_finality_002.json; fi; \
	  if [ '$(NATIVE_CYCLE)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_cycle_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_cycle_006.json; fi; \
	  if [ '$(NATIVE_LIFECYCLE)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_lifecycle_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_lifecycle_004.json; fi; \
	  if [ '$(NATIVE_WORKER)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_worker_contract.json OCLOB_NATIVE_MANIFEST='$(NATIVE_WORKER_MANIFEST)'; fi; \
	  if [ '$(NATIVE_EXPIRY)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_expiry_fenced_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_expiry_003.json; fi; \
	  if [ '$(NATIVE_DEFERRED)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_deferred_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_deferred_003.json; fi; \
	  if [ '$(NATIVE_MARKET)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_market_contract.json OCLOB_NATIVE_MANIFEST=/research/manifests/oclob_native_market_002.json OCLOB_MARKET_CONFIG=/public/market.json; fi; \
	  if [ '$(NATIVE_DEPTH)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_depth_contract.json OCLOB_NATIVE_MANIFEST='$(NATIVE_DEPTH_MANIFEST)'; fi; \
	  if [ '$(NATIVE_HTTP)' = 1 ]; then export OCLOB_NATIVE_CONTRACT=/research/oclob_native_http_contract.json OCLOB_NATIVE_MANIFEST='$(NATIVE_HTTP_MANIFEST)'; fi; \
	  compose='docker compose -f $$remote_dir/oclob/deploy/docker-compose.distributed.yml -f $$remote_dir/oclob/deploy/docker-compose.native.yml'; \
	  if [ '$(NATIVE_BROWSER)' = 1 ]; then compose=\"\$$compose -f $$remote_dir/oclob/deploy/docker-compose.native-browser.yml\"; fi; \
	  if [ '$(NATIVE_CORPORATE_API)' = 1 ]; then compose=\"\$$compose -f $$remote_dir/oclob/deploy/docker-compose.corporate-api.yml\"; fi; \
	  cleanup() { \$$compose logs --no-color > '$$remote_dir/containers.log' 2>&1 || true; \$$compose down --remove-orphans >/dev/null 2>&1 || true; }; \
	  trap cleanup EXIT INT TERM; \
	  docker build --network host -f '$$remote_dir/oclob/docker/Dockerfile' --target oclob-cluster -t \"\$$OCLOB_CLUSTER_IMAGE\" '$$remote_dir/oclob'; \
	  docker build --network host -f '$$remote_dir/oclob/docker/Dockerfile' --target oclob-avalanche-acceptance -t \"\$$OCLOB_AVALANCHE_IMAGE\" '$$remote_dir/oclob'; \
	  docker run --rm --user \"\$$OCLOB_UID:\$$OCLOB_GID\" --mount type=bind,src=\"\$$runtime\",dst=/runtime \"\$$OCLOB_CLUSTER_IMAGE\" oclob-lab-provision --out /runtime/cluster; \
	  \$$compose config --quiet; \
	  \$$compose up -d --wait --wait-timeout 180 node-0 node-1 node-2 node-3 node-4 node-5 node-6; \
	  \$$compose run --rm native-bootstrap; \
	  \$$compose up -d --wait --wait-timeout 600 defmi; \
	  defmi_container=\$$(\$$compose ps -q defmi); [ -n \"\$$defmi_container\" ]; \
	  if [ '$(NATIVE_MARKET)' = 1 ]; then \
	    \$$compose run --rm market-worker oclob-market-worker --initialize; \
	    export OCLOB_MARKET_CRASH_AFTER_CANONICAL=1; \
	    \$$compose up -d market-worker maker-worker taker-worker public-book; \
	    if [ '$(NATIVE_CORPORATE_API)' = 1 ]; then \$$compose up -d --wait maker-api taker-api; \$$compose run --rm maker sh -c 'umask 077; oclob-corporate-api --wallet > /corporate/api-wallet-before.json'; \$$compose run --rm taker sh -c 'umask 077; oclob-corporate-api --wallet > /corporate/api-wallet-before.json'; \$$compose run --rm -e OCLOB_CORPORATE_API_CONFIG=/public/taker-api.json maker oclob-corporate-api --expect-denied; \$$compose run --rm -e OCLOB_CORPORATE_API_CONFIG=/public/maker-api.json taker oclob-corporate-api --expect-denied; fi; \
	    if [ '$(NATIVE_HTTP)' = 1 ]; then \$$compose up -d --wait book-api; \$$compose run --rm book-reader curl --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}\\n' http://book-api:9880/v1/book > \"\$$runtime/handoff/http-statuses.txt\"; fi; \
	    if [ '$(NATIVE_BROWSER)' = 1 ]; then printf 'BROWSER_EMPTY_READY %s\\n' '$$remote_dir'; for browser_wait in \$$(seq 1 90); do [ ! -f '$$remote_dir/browser-empty-continue' ] || break; sleep 1; done; fi; \
	    first_market=\$$(\$$compose ps -q market-worker); [ -n \"\$$first_market\" ]; \
	    docker inspect --format '{{.Id}}' \"\$$first_market\" > \"\$$runtime/handoff/market-processes.txt\"; \
	    high=market-high-order.json; low=market-low-order.json; buy=multifill-order.json; total=3; \
	    if [ '$(NATIVE_DEPTH)' = 1 ]; then high=depth-high-order.json; low=depth-low1-order.json; buy=depth-buy-order.json; total=4; fi; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=authorized -e OCLOB_CORPORATE_REQUEST_ID=native-market-high -e OCLOB_CORPORATE_ORDER_FILE=/corporate/\$$high maker; \
	    \$$compose run --rm market-worker oclob-market-worker --wait-rounds 1; \
	    if [ '$(NATIVE_DEPTH)' = 1 ]; then \$$compose run --rm book-reader oclob-public-book --get 1 > \"\$$runtime/handoff/depth-1.json\"; if [ '$(NATIVE_HTTP)' = 1 ]; then \$$compose run --rm book-reader curl --fail --silent --show-error --max-time 10 'http://book-api:9880/v1/book?minimum_sequence=1' > \"\$$runtime/handoff/http-depth-1.json\"; cmp \"\$$runtime/handoff/depth-1.json\" \"\$$runtime/handoff/http-depth-1.json\"; fi; fi; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=authorized -e OCLOB_CORPORATE_REQUEST_ID=native-market-low -e OCLOB_CORPORATE_ORDER_FILE=/corporate/\$$low maker; \
	    \$$compose run --rm market-worker oclob-market-worker --wait-rounds 2; \
	    if [ '$(NATIVE_DEPTH)' = 1 ]; then \
	      \$$compose run --rm book-reader oclob-public-book --get 2 > \"\$$runtime/handoff/depth-2.json\"; if [ '$(NATIVE_HTTP)' = 1 ]; then \$$compose run --rm book-reader curl --fail --silent --show-error --max-time 10 'http://book-api:9880/v1/book?minimum_sequence=2' > \"\$$runtime/handoff/http-depth-2.json\"; cmp \"\$$runtime/handoff/depth-2.json\" \"\$$runtime/handoff/http-depth-2.json\"; fi; \
	      \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=authorized -e OCLOB_CORPORATE_REQUEST_ID=native-depth-low2 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/depth-low2-order.json maker; \
	      \$$compose run --rm market-worker oclob-market-worker --wait-rounds 3; \
	      \$$compose run --rm book-reader oclob-public-book --get 3 > \"\$$runtime/handoff/depth-3.json\"; if [ '$(NATIVE_HTTP)' = 1 ]; then \$$compose run --rm book-reader curl --fail --silent --show-error --max-time 10 'http://book-api:9880/v1/book?minimum_sequence=3' > \"\$$runtime/handoff/http-depth-3.json\"; cmp \"\$$runtime/handoff/depth-3.json\" \"\$$runtime/handoff/http-depth-3.json\"; fi; \
	    fi; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=authorized -e OCLOB_CORPORATE_REQUEST_ID=native-market-buy -e OCLOB_CORPORATE_ORDER_FILE=/corporate/\$$buy taker; \
	    stopped=\$$(timeout 360 docker wait \"\$$first_market\"); [ \"\$$stopped\" = 75 ]; \
	    printf '%s\n' \"\$$stopped\" > \"\$$runtime/handoff/market-crash-exit.txt\"; \
	    if [ '$(NATIVE_DEPTH)' = 1 ]; then \$$compose run --rm book-reader oclob-public-book --get 3 > \"\$$runtime/handoff/depth-before-finality.json\"; if [ '$(NATIVE_HTTP)' = 1 ]; then \$$compose run --rm book-reader curl --fail --silent --show-error --max-time 10 'http://book-api:9880/v1/book?minimum_sequence=3' > \"\$$runtime/handoff/http-depth-before-finality.json\"; cmp \"\$$runtime/handoff/depth-before-finality.json\" \"\$$runtime/handoff/http-depth-before-finality.json\"; fi; fi; \
	    export OCLOB_MARKET_CRASH_AFTER_CANONICAL=0; \
	    \$$compose up -d --force-recreate market-worker; \
	    docker inspect --format '{{.Id}}' \$$(\$$compose ps -q market-worker) >> \"\$$runtime/handoff/market-processes.txt\"; \
	    \$$compose run --rm market-worker oclob-market-worker --wait-rounds \$$total > \"\$$runtime/handoff/market-before-restart.json\"; \
	    if [ '$(NATIVE_CORPORATE_API)' = 1 ]; then \$$compose run --rm maker sh -c 'umask 077; oclob-corporate-api --wallet > /corporate/api-wallet-after.json'; \$$compose run --rm taker sh -c 'umask 077; oclob-corporate-api --wallet > /corporate/api-wallet-after.json'; \$$compose run --rm maker oclob-corporate-api --expect-locked 45; \$$compose run --rm taker oclob-corporate-api --expect-locked 0; \$$compose restart maker-api taker-api; \$$compose up -d --wait maker-api taker-api; \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=authorized -e OCLOB_CORPORATE_REQUEST_ID=native-market-high -e OCLOB_CORPORATE_ORDER_FILE=/corporate/\$$high maker; \$$compose run --rm maker sh -c 'umask 077; oclob-corporate-api --status > /corporate/api-queue-after.json'; fi; \
	    if [ '$(NATIVE_DEPTH)' = 1 ]; then \$$compose run --rm book-reader oclob-public-book --get 4 > \"\$$runtime/handoff/depth-final.json\"; if [ '$(NATIVE_HTTP)' = 1 ]; then \$$compose run --rm book-reader curl --fail --silent --show-error --max-time 10 'http://book-api:9880/v1/book?minimum_sequence=4' > \"\$$runtime/handoff/http-depth-final.json\"; cmp \"\$$runtime/handoff/depth-final.json\" \"\$$runtime/handoff/http-depth-final.json\"; fi; fi; \
	    if [ '$(NATIVE_BROWSER)' = 1 ]; then printf 'BROWSER_SETTLED_READY %s\\n' '$$remote_dir'; for browser_wait in \$$(seq 1 120); do [ ! -f '$$remote_dir/browser-settled-continue' ] || break; sleep 1; done; fi; \
	    \$$compose up -d --force-recreate market-worker; \
	    docker inspect --format '{{.Id}}' \$$(\$$compose ps -q market-worker) >> \"\$$runtime/handoff/market-processes.txt\"; \
	    if [ '$(NATIVE_DEPTH)' = 1 ]; then \$$compose run --rm book-reader oclob-public-book --get 4 > \"\$$runtime/handoff/depth-after-restart.json\"; if [ '$(NATIVE_HTTP)' = 1 ]; then \$$compose run --rm book-reader curl --fail --silent --show-error --max-time 10 'http://book-api:9880/v1/book?minimum_sequence=4' > \"\$$runtime/handoff/http-depth-after-restart.json\"; cmp \"\$$runtime/handoff/depth-after-restart.json\" \"\$$runtime/handoff/http-depth-after-restart.json\"; fi; fi; \
	    if [ '$(NATIVE_HTTP)' = 1 ]; then \
	      for route in unknown v1/book; do method=GET; [ \"\$$route\" != v1/book ] || method=POST; \$$compose run --rm book-reader curl --silent --show-error --max-time 5 -X \$$method --output /dev/null --write-out '%{http_code}\\n' http://book-api:9880/\$$route >> \"\$$runtime/handoff/http-statuses.txt\"; done; \
	      for query in invalid 5; do \$$compose run --rm book-reader curl --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}\\n' http://book-api:9880/v1/book?minimum_sequence=\$$query >> \"\$$runtime/handoff/http-statuses.txt\"; done; \
	      \$$compose stop public-book; \
	      \$$compose run --rm book-reader curl --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}\\n' http://book-api:9880/v1/book >> \"\$$runtime/handoff/http-statuses.txt\"; \
	      \$$compose up -d public-book; \
	    fi; \
	    \$$compose run --rm market-worker oclob-market-worker --acceptance; \
	  elif [ '$(NATIVE_EXPIRY)' = 1 ]; then \
	    nodes='node-0 node-1 node-2 node-3 node-4 node-5 node-6'; \
	    \$$compose stop \$$nodes; \
	    docker inspect --format '{{.State.Running}}' \$$(\$$compose ps -a -q \$$nodes) > \"\$$runtime/handoff/expiry-absent-nodes.txt\"; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=1 -e OCLOB_CORPORATE_REQUEST_ID=native-expiry-absent-001 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/queued-expiry-order.json maker; \
	    \$$compose up -d maker-worker; \
	    \$$compose run --rm maker oclob-corporate-worker --wait-reconciled native-expiry-absent-001 > \"\$$runtime/handoff/expiry-absent.json\"; \
	    \$$compose stop maker-worker; \
	    \$$compose up -d --wait --wait-timeout 180 \$$nodes; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=1 -e OCLOB_CORPORATE_REQUEST_ID=native-expiry-release-002 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/queued-expiry-order.json maker; \
	    stopped=0; timeout 240 \$$compose run --rm -e OCLOB_NATIVE_RECOVERY_TEST_STOP=after-reserve-before-journal maker oclob-corporate-worker || stopped=\$$?; \
	    [ \"\$$stopped\" = 75 ] || { echo 'expiry trial did not stop after real reserve' >&2; exit 1; }; \
	    \$$compose stop \$$nodes; \
	    docker inspect --format '{{.State.Running}}' \$$(\$$compose ps -a -q \$$nodes) > \"\$$runtime/handoff/expiry-release-nodes.txt\"; \
	    stopped=0; timeout 240 \$$compose run --rm -e OCLOB_NATIVE_RECOVERY_TEST_STOP=after-expiry-before-journal maker oclob-corporate-worker > \"\$$runtime/handoff/expiry-release-stop.jsonl\" || stopped=\$$?; \
	    [ \"\$$stopped\" = 75 ] || { echo 'expiry trial did not stop after real release' >&2; exit 1; }; \
	    \$$compose up -d maker-worker; \
	    \$$compose run --rm maker oclob-corporate-worker --wait-reconciled native-expiry-release-002 > \"\$$runtime/handoff/expiry-released.json\"; \
	    \$$compose run --rm maker oclob-corporate-worker --status > \"\$$runtime/handoff/expiry-before-restart.json\"; \
	    \$$compose restart maker-worker; \
	    \$$compose run --rm maker oclob-corporate-worker --wait-reconciled native-expiry-release-002; \
	    \$$compose run --rm maker oclob-corporate-worker --status > \"\$$runtime/handoff/expiry-after-restart.json\"; \
	    \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=queued-expiry maker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/queued-expiry-recovery.json --settlement-handoff /handoff/unused.json --scenario maker; \
	    \$$compose up -d --wait --wait-timeout 180 \$$nodes; \
	    \$$compose run --rm -e OCLOB_CORPORATE_REQUEST_ID=native-expiry-next-003 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/queued-expiry-reuse.json maker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/queued-expiry-next.json --settlement-handoff /handoff/queued-expiry-next-authority.json --scenario maker; \
	    \$$compose run --rm native-coordinator; \
	  else \
	  if [ '$(NATIVE_DEFERRED)' = 1 ]; then \
	    nodes='node-0 node-1 node-2 node-3 node-4 node-5 node-6'; \
	    \$$compose run --rm -e OCLOB_NATIVE_CACHE_SCOPE=1 maker; \
	    \$$compose stop \$$nodes; \
	    docker pause \$$defmi_container; \
	    docker inspect --format '{{.State.Running}}' \$$(\$$compose ps -a -q \$$nodes) > \"\$$runtime/handoff/deferred-nodes-stopped.txt\"; \
	    docker inspect --format '{{.State.Paused}}' \$$defmi_container > \"\$$runtime/handoff/deferred-defmi-paused.txt\"; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=authorized maker; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=authorized -e OCLOB_CORPORATE_REQUEST_ID=native-maker-too-large -e OCLOB_CORPORATE_ORDER_FILE=/corporate/over-capacity-order.json maker > \"\$$runtime/handoff/deferred-large-intake.log\" 2>&1 & large_pid=\$$!; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=authorized -e OCLOB_CORPORATE_REQUEST_ID=native-maker-002 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/multifill-order.json maker > \"\$$runtime/handoff/deferred-other-intake.log\" 2>&1 & other_pid=\$$!; \
	    wait \$$large_pid; wait \$$other_pid; \
	    \$$compose run --rm maker oclob-corporate-worker --preparation-status > \"\$$runtime/handoff/deferred-before.json\"; \
	    docker unpause \$$defmi_container; \
	    \$$compose up -d --wait --wait-timeout 180 \$$nodes; \
	    \$$compose up -d maker-worker; \
	    \$$compose run --rm maker oclob-corporate-worker --wait-admitted native-maker-001; \
	    \$$compose run --rm maker oclob-corporate-worker --wait-admitted native-maker-002; \
	    \$$compose run --rm maker oclob-corporate-worker --wait-reconciled native-maker-too-large > \"\$$runtime/handoff/deferred-rejected.json\"; \
	    \$$compose run --rm maker oclob-corporate-worker --preparation-status > \"\$$runtime/handoff/deferred-after.json\"; \
	    \$$compose run --rm maker oclob-corporate-worker --status > \"\$$runtime/handoff/deferred-queue-before-restart.json\"; \
	    \$$compose restart maker-worker; \
	    \$$compose run --rm maker oclob-corporate-worker --status > \"\$$runtime/handoff/deferred-queue-after-restart.json\"; \
	  fi; \
	  if [ '$(NATIVE_WORKER)' = 1 ]; then \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=1 maker; \
	    \$$compose stop node-6; \
	    \$$compose run --rm maker oclob-corporate-worker --once > \"\$$runtime/handoff/worker-waiting.json\"; \
	    \$$compose run --rm maker oclob-corporate-worker --status > \"\$$runtime/handoff/worker-queued.json\"; \
	    \$$compose up -d --wait --wait-timeout 180 node-6; \
	    stopped=0; timeout 180 \$$compose run --rm -e OCLOB_NATIVE_RECOVERY_TEST_STOP=after-reserve-before-journal maker oclob-corporate-worker > \"\$$runtime/handoff/worker-reserve-stop.jsonl\" || stopped=\$$?; \
	    [ \"\$$stopped\" = 75 ] || { echo 'worker did not stop after actual reserve' >&2; exit 1; }; \
	    stopped=0; timeout 180 \$$compose run --rm -e OCLOB_NATIVE_RECOVERY_TEST_STOP=after-node-admission-before-journal maker oclob-corporate-worker > \"\$$runtime/handoff/worker-admission-stop.jsonl\" || stopped=\$$?; \
	    [ \"\$$stopped\" = 75 ] || { echo 'worker did not stop after actual node admission' >&2; exit 1; }; \
	    \$$compose up -d maker-worker; \
	    \$$compose run --rm maker oclob-corporate-worker --wait-admitted native-maker-001 > \"\$$runtime/handoff/worker-admitted.json\"; \
	    competing=0; \$$compose run --rm maker oclob-corporate-worker --once || competing=\$$?; \
	    [ \"\$$competing\" = 1 ] || { echo 'second worker was not rejected' >&2; exit 1; }; \
	    \$$compose run --rm -e OCLOB_NATIVE_ENQUEUE=1 maker; \
	    \$$compose run --rm maker oclob-corporate-worker --status > \"\$$runtime/handoff/worker-before-restart.json\"; \
	    \$$compose restart maker-worker; \
	    \$$compose run --rm maker oclob-corporate-worker --wait-admitted native-maker-001; \
	    \$$compose run --rm maker oclob-corporate-worker --status > \"\$$runtime/handoff/worker-after-restart.json\"; \
	  fi; \
	  if [ '$(NATIVE_RECOVERY)' = 1 ]; then \
	    stopped=0; \$$compose run --rm -e OCLOB_NATIVE_RECOVERY_TEST_STOP=after-reserve-before-journal maker || stopped=\$$?; \
	    [ \"\$$stopped\" = 75 ] || { echo 'expected stop after reserve was not observed' >&2; exit 1; }; \
	    \$$compose stop node-6; \
	    partial=0; \$$compose run --rm maker || partial=\$$?; \
	    [ \"\$$partial\" != 0 ] || { echo 'partial delivery unexpectedly succeeded without node-6' >&2; exit 1; }; \
	    \$$compose up -d --wait --wait-timeout 180 node-6; \
	    stopped=0; \$$compose run --rm -e OCLOB_NATIVE_RECOVERY_TEST_STOP=after-node-admission-before-journal maker || stopped=\$$?; \
	    [ \"\$$stopped\" = 75 ] || { echo 'expected stop after node admission was not observed' >&2; exit 1; }; \
	  fi; \
	  \$$compose run --rm maker; \
	  if [ '$(NATIVE_RECOVERY)' = 1 ]; then \$$compose run --rm maker; fi; \
	  if [ '$(NATIVE_MULTIFILL)' = 1 ]; then \
	    \$$compose run --rm -e OCLOB_CORPORATE_REQUEST_ID=native-maker-002 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/multifill-order.json maker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/maker2.json --settlement-handoff /handoff/maker2-capability.json --scenario maker; \
	    if [ '$(NATIVE_CYCLE)' = 1 ]; then \$$compose run --rm -e OCLOB_CORPORATE_ORDER_FILE=/corporate/cycle-order.json taker; else \$$compose run --rm -e OCLOB_CORPORATE_ORDER_FILE=/corporate/multifill-order.json taker; fi; \
	  else \$$compose run --rm taker; fi; \
	  \$$compose run --rm native-coordinator; \
	  if [ '$(NATIVE_WALLET)' = 1 ]; then \
	  if [ '$(NATIVE_CYCLE)' = 1 ]; then \
	    for actor in maker taker; do \
	      \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=cycle-first \$$actor; \
	      \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=cycle-first \$$actor; \
	    done; \
	    \$$compose run --rm -e OCLOB_CORPORATE_REQUEST_ID=native-taker-cycle-002 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/cycle-reuse-order.json taker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/reuse-taker.json --settlement-handoff /handoff/reuse-taker-authority.json --scenario taker; \
	    if [ '$(NATIVE_LIFECYCLE)' = 1 ]; then \$$compose run --rm -e OCLOB_CORPORATE_REQUEST_ID=native-maker-002 -e OCLOB_NATIVE_CANCEL_ORDER=1 maker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/maker-cancel.json --settlement-handoff /handoff/unused-cancel.json --scenario maker; fi; \
	    \$$compose run --rm -e OCLOB_NATIVE_NEXT_MATCH=1 native-coordinator; \
	    for actor in maker taker; do \
	      for repeat in 1 2; do \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=cycle-final \$$actor oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/\$$actor-cycle-final.json --settlement-handoff /handoff/unused-\$$actor-cycle-authority.json --scenario \$$actor; done; \
	    done; \
	    if [ '$(NATIVE_LIFECYCLE)' = 1 ]; then \
	      \$$compose run --rm -e OCLOB_NATIVE_WALLET_FINALIZE=1 native-coordinator; \
	      \$$compose run --rm -e OCLOB_NATIVE_LIFECYCLE_PHASE=cancel native-coordinator; \
	      for repeat in 1 2; do \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=cancel-final maker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/maker-cancel-final.json --settlement-handoff /handoff/unused.json --scenario maker; done; \
	      \$$compose run --rm -e OCLOB_CORPORATE_REQUEST_ID=native-maker-expiry-003 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/expiry-order.json maker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/expiry-maker.json --settlement-handoff /handoff/expiry-maker-authority.json --scenario maker; \
	      \$$compose run --rm -e OCLOB_NATIVE_LIFECYCLE_PHASE=expiry native-coordinator; \
	      for repeat in 1 2; do \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=expiry-final maker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/maker-expiry-final.json --settlement-handoff /handoff/unused.json --scenario maker; done; \
	      \$$compose run --rm -e OCLOB_NATIVE_LIFECYCLE_PHASE=checkpoint native-coordinator; \
	      \$$compose restart node-0 node-1 node-2 node-3 node-4 node-5 node-6; \
	      \$$compose up -d --wait --wait-timeout 180 node-0 node-1 node-2 node-3 node-4 node-5 node-6; \
	      \$$compose run --rm -e OCLOB_NATIVE_LIFECYCLE_PHASE=final native-coordinator; \
	    fi; \
	  else \
	  \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=1 maker; \
	  \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=1 maker; \
	  \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=1 taker; \
	  \$$compose run --rm -e OCLOB_NATIVE_RECOVER_WALLET=1 -e OCLOB_NATIVE_WALLET_ACCEPTANCE=1 taker; \
	  \$$compose run --rm -e OCLOB_CORPORATE_REQUEST_ID=native-taker-002 -e OCLOB_CORPORATE_ORDER_FILE=/corporate/reuse-order.json taker oclob-edge-submit --cluster /public/cluster.json --identity /identity/client.json --handoff /handoff/reuse-taker.json --settlement-handoff /handoff/reuse-taker-authority.json --scenario taker; \
	  fi; \
	  if [ '$(NATIVE_LIFECYCLE)' = 0 ]; then \$$compose run --rm -e OCLOB_NATIVE_WALLET_FINALIZE=1 native-coordinator; fi; \
	  fi; \
	  fi; \
	  exit_code=\$$(docker wait \"\$$defmi_container\"); [ \"\$$exit_code\" = 0 ]; \
	  if [ '$(NATIVE_DEPTH)' = 1 ]; then \$$compose run --rm book-reader oclob-public-book --get 4 > \"\$$runtime/handoff/depth-after-validators.json\"; cmp \"\$$runtime/handoff/depth-final.json\" \"\$$runtime/handoff/depth-after-validators.json\"; if [ '$(NATIVE_HTTP)' = 1 ]; then \$$compose run --rm book-reader curl --fail --silent --show-error --max-time 10 'http://book-api:9880/v1/book?minimum_sequence=4' > \"\$$runtime/handoff/http-depth-after-validators.json\"; cmp \"\$$runtime/handoff/depth-after-validators.json\" \"\$$runtime/handoff/http-depth-after-validators.json\"; fi; fi; \
	  test -s \"\$$runtime/out/oclob_native_notes.json\""; \
	artifact=artifacts/oclob_native_notes.json; if [ '$(NATIVE_RECOVERY)' = 1 ]; then artifact=artifacts/oclob_native_recovery.json; fi; if [ '$(NATIVE_WALLET)' = 1 ]; then artifact=artifacts/oclob_native_wallet.json; fi; if [ '$(NATIVE_FINALITY)' = 1 ]; then artifact=artifacts/oclob_native_finality.json; fi; if [ '$(NATIVE_MULTIFILL)' = 1 ]; then artifact=artifacts/oclob_native_multifill.json; fi; if [ '$(NATIVE_CYCLE)' = 1 ]; then artifact=artifacts/oclob_native_cycle.json; fi; \
	if [ '$(NATIVE_LIFECYCLE)' = 1 ]; then artifact=artifacts/oclob_native_lifecycle.json; fi; \
	if [ '$(NATIVE_WORKER)' = 1 ]; then artifact=artifacts/oclob_native_worker.json; fi; \
	if [ '$(NATIVE_EXPIRY)' = 1 ]; then artifact=artifacts/oclob_native_expiry.json; fi; \
	if [ '$(NATIVE_DEFERRED)' = 1 ]; then artifact=artifacts/oclob_native_deferred.json; fi; \
	if [ '$(NATIVE_MARKET)' = 1 ]; then artifact=artifacts/oclob_native_market.json; fi; \
	if [ '$(NATIVE_DEPTH)' = 1 ]; then artifact=artifacts/oclob_native_depth.json; fi; \
	if [ '$(NATIVE_HTTP)' = 1 ]; then artifact=artifacts/oclob_native_http.json; fi; \
	if [ '$(NATIVE_CORPORATE_API)' = 1 ]; then artifact=artifacts/oclob_native_corporate_api.json; fi; \
	rsync -a --compress "$(REMOTE_TEST_HOST):$$remote_dir/runtime/out/oclob_native_notes.json" "$$artifact"; \
	printf 'Native run evidence retained at %s\n' "$$remote_dir"

release-gate:
	$(MAKE) remote-test \
	  REMOTE_TEST_HOST='$(REMOTE_TEST_HOST)' \
	  REMOTE_TEST_REUSE_IMAGE='$(REMOTE_TEST_REUSE_IMAGE)' \
	  REMOTE_TEST_IMAGE='$(REMOTE_TEST_IMAGE)' \
	  REMOTE_TEST_EXPORTS='Cargo.lock artifacts/oclob_rough_e2e.json oclob_demo/static/react-flow.js oclob_demo/static/react-flow.css' \
	  REMOTE_TEST_COMMAND='cargo fmt --all -- --check && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo clippy --workspace --all-targets -- -D warnings && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo test --workspace --release -j $(REMOTE_TEST_CARGO_JOBS) && cd oclob_demo/react-flow && npm ci --no-audit --no-fund && npm run build && node --check ../static/app.js && cd ../.. && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo run --release -p oclob-demo --bin oclob-demo -- --contract research/oclob_contract.json --manifest research/manifests/oclob_rough_e2e.json --receipt artifacts/oclob_rough_e2e.json --ledger /tmp/oclob-experiment-ledger.jsonl --mp-spdz-root /opt/MP-SPDZ'
