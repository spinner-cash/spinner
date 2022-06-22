# Settings
IC_VERSION=21a974b29c1360ce8dd381f123a09668b7b0b733
LAUNCHTRAIL_VERSION=1873d92
IDENTITY?=default
MODE?=upgrade

# Source file
CIRCUITSRC=src/verifier/constants.rs  src/verifier/test_input_constants.rs src/verifier/test_proof_constants.rs
LIBSRC=src/ledger.rs src/poseidon.rs src/verifier.rs src/lib.rs  $(CIRCUITSRC)

# Canister, candid, etc.
LAUNCHTRAIL=dist/launchtrail.wasm dist/launchtrail.did
BLACKHOLE=dist/blackhole.wasm dist/blackhole.did
LOGGER=dist/text_logger.wasm dist/text_logger.did dist/text_logger.did.mjs
LEDGER=dist/ledger.wasm dist/ledger.did dist/ledger.did.mjs
LEDGER_NNS=dist/ledger_nns.wasm dist/ledger_nns.did dist/ledger_nns.public.did dist/ledger_nns.public.did.mjs
LEDGER_ICP=dist/ledger_icp.wasm dist/ledger_icp.did dist/ledger_icp.did.mjs
POOL_ICP=dist/pool_icp.wasm dist/pool_icp.did dist/pool_icp.did.mjs

NAMES=launchtrail blackhole ledger_nns text_logger pool_icp ledger_icp
DEPLOYS=$(shell echo $(NAMES) | xargs -n1 | xargs --replace echo dist/.deploy-{})
CANISTERS=$(shell echo $(NAMES) | xargs -n1 | xargs --replace echo dist/.canister-{})

default: $(LOGGER) $(LEDGER_NNS) $(LEDGER_ICP) $(POOL_ICP)

src/verifier:
	mkdir -p $@

src/verifier/%.rs: ../circuits/%.rs | src/verifier
	cd src/verifier && ln -s ../../$< $(subst src/verifier/,,$@)

target/wasm32-unknown-unknown/release/%.wasm: bin/%.rs $(LIBSRC)
	cargo build --release --target=wasm32-unknown-unknown --bin $(subst bin/,,$(subst .rs,,$<))

clean:
	rm -rf dist Makefile.launchtrail dfx.json

distclean: clean
	rm -rf target
	rm -rf src/verifier

.PHONY: clean

.PRECIOUS: $(CIRCUITSRC) $(LOGGER) $(LEDGER_NNS) $(LEDGER_ICP) $(POOL_ICP) Makefile.launchtrail dfx.json

.ONESHELL:
dfx.json:
	test ! -f $@ && echo {} > $@
	for name in $(NAMES); do
	  tmpfile=$$(mktemp --tmpdir)
	  cat $@ | jq ".canisters.$${name} = {\"type\": \"custom\", \"candid\": \"dist/$${name}.did\", \"wasm\": \"dist/$${name}.wasm\", \"build\": \"\"}" > $$tmpfile
	  mv $$tmpfile $@
	done

dist:
	mkdir -p dist

dist/%.wasm: target/wasm32-unknown-unknown/release/%.wasm | dist
	wasm-opt -O2 $< -o $@

dist/%.did: dist/%.wasm
	cargo run --bin $(subst dist/,,$(subst .wasm,,$<)) > $@

dist/%.did.mjs: dist/%.did
	didc bind $< -t js > $@

dist/ledger_icp.wasm: dist/ledger.wasm
	cp $< $@

dist/ledger_icp.did: dist/ledger.did
	cp $< $@

dist/ledger_icp.did.mjs: dist/ledger.did.mjs
	cp $< $@

.INTERMEDIATE: dist/ledger_nns.wasm.gz

dist/ledger_nns.wasm.gz:
	curl -Lo $@ https://download.dfinity.systems/ic/${IC_VERSION}/canisters/ledger-canister_notify-method.wasm.gz

dist/ledger_nns.wasm: dist/ledger_nns.wasm.gz
	gunzip -c $< > $@

dist/ledger_nns.did:
	curl -Lo $@ https://raw.githubusercontent.com/dfinity/ic/${IC_VERSION}/rs/rosetta-api/ledger.did

dist/ledger_nns.public.did:
	curl -Lo $@ https://raw.githubusercontent.com/dfinity/ic/${IC_VERSION}/rs/rosetta-api/ledger_canister/ledger.did

dist/blackhole.wasm:
	curl -Lo $@ https://github.com/ninegua/ic-blackhole/releases/download/0.0.0/blackhole-opt.wasm

dist/blackhole.did:
	curl -Lo $@ https://github.com/ninegua/ic-blackhole/releases/download/0.0.0/blackhole.did

dist/identity.pem:
	dfx identity export $(IDENTITY) > $@
	chmod 0600 $@

dist/local: dist/.deploy-blackhole dist/.deploy-launchtrail
	echo "let launch_trail = principal \"$$(dfx canister id launchtrail)\";" >> $@
	echo "let blackhole = principal \"$$(dfx canister id blackhole)\";" >> $@
	echo "let account_id = \"$$(dfx ledger account-id)\";" >> $@

Makefile.launchtrail:
	curl -Lo $@ https://github.com/spinner-cash/launchtrail/releases/download/$(LAUNCHTRAIL_VERSION)/Makefile

.PHONY: deploy clean-deploy

deploy: $(DEPLOYS)

clean-deploy:
	rm $(DEPLOYS)

install: undeploy deploy

dist/.deploy-launchtrail: Makefile.launchtrail dfx.json
	$(MAKE) -f $< default deploy
	dfx ledger fabricate-cycles --t 20 --canister launchtrail && touch $@

dist/.deploy-blackhole: dist/blackhole.wasm dist/blackhole.did dfx.json
	dfx deploy blackhole && touch $@

dist/.deploy-%: dist/local dist/.canister-% dist/%.wasm dist/%.did scripts/install_%
	./scripts/install_canister.sh --$(MODE) $(subst dist/.deploy-,,$@) && touch $@

dist/.canister-%: dist/local dist/identity.pem
	./scripts/create_canister.sh $(subst dist/.canister-,,$@) && touch $@
