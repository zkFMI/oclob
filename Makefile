REMOTE_TEST_HOST ?= omenx_ubuntu_zerotier
REMOTE_TEST_ALLOWED_HOSTS := omenx_ubuntu_zerotier softbank-l40s
REMOTE_TEST_REUSE_IMAGE ?= 0
REMOTE_TEST_IMAGE ?= oclob-test:rust-1.97.1-mpspdz-9d809599
REMOTE_TEST_CARGO_JOBS ?= 16
REMOTE_TEST_COMMAND ?= cargo test --workspace --release -j $(REMOTE_TEST_CARGO_JOBS)
REMOTE_TEST_EXPORTS ?=

.PHONY: remote-test release-gate

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

release-gate:
	$(MAKE) remote-test \
	  REMOTE_TEST_HOST='$(REMOTE_TEST_HOST)' \
	  REMOTE_TEST_REUSE_IMAGE='$(REMOTE_TEST_REUSE_IMAGE)' \
	  REMOTE_TEST_IMAGE='$(REMOTE_TEST_IMAGE)' \
	  REMOTE_TEST_EXPORTS='artifacts/oclob_rough_e2e.json oclob_demo/static/react-flow.js oclob_demo/static/react-flow.css' \
	  REMOTE_TEST_COMMAND='cargo fmt --all -- --check && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo clippy --workspace --all-targets -- -D warnings && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo test --workspace --release -j $(REMOTE_TEST_CARGO_JOBS) && cd oclob_demo/react-flow && npm ci --no-audit --no-fund && npm run build && node --check ../static/app.js && cd ../.. && MP_SPDZ_ROOT=/opt/MP-SPDZ cargo run --release -p oclob-demo --bin oclob-demo -- --contract research/oclob_contract.json --manifest research/manifests/oclob_rough_e2e.json --receipt artifacts/oclob_rough_e2e.json --ledger /tmp/oclob-experiment-ledger.jsonl --mp-spdz-root /opt/MP-SPDZ'
