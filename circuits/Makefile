CIRCOM=npx circom
SNARKJS=npx snarkjs
PTAU=../data/powersOfTau28_hez_final_16.ptau
RUSTFILES=test_proof_constants.rs test_input_constants.rs constants.rs
CIRCUITFILES=circuit.circom  keypair.circom  merkleProof.circom  merkleTree.circom  transaction.circom

default: $(RUSTFILES) circuit.json

test: verification_key.json public.json proof.json
	$(SNARKJS) groth16 verify $^

circuit.json: circuit_js/circuit.wasm circuit_final.zkey compress.js
	node compress.js > $@

circuit.r1cs circuit_js/circuit.wasm &: $(CIRCUITFILES)
	circom $< --verbose -c --r1cs --wasm --sym

circuit.r1cs.json: circuit.r1cs
	$(SNARKJS) r1cs export json $< $@

witness.wtns: circuit_js/circuit.wasm input.json
	$(SNARKJS) wc $^ $@

circuit_final.zkey.0: circuit.r1cs $(PTAU)
	$(SNARKJS) groth16 setup $< $(PTAU) $@

circuit_final.zkey: circuit_final.zkey.0
	echo test | $(SNARKJS) zkey contribute $< $@

# This is currently broken in snarkjs
circuit_final.zkey.json: circuit_final.zkey
	$(SNARKJS) zkey export json $< $@

verification_key.json: circuit_final.zkey
	$(SNARKJS) zkey export verificationkey $< $@

verifier.sol: circuit_final.zkey
	$(SNARKJS) zkey export solidityverifier $< $@

constants.rs: verifier.sol
	cat $< | grep -E '[0-9]{32,}' |sed -e 's/[^0-9]//g' | \
		awk -n '(n){print "pub(crate) const C" n " : &str = \"" $$0 "\";";n=n+1} /2188824287183927522224/{n=1}' | \
		head -n30 > $@

test_proof_constants.rs: proof.json
	cat $< | grep -E '[0-9]{32,}' |sed -e 's/[^0-9]//g' | \
		awk -n 'BEGIN{n=0} {print "pub(crate) const P" n " : &str = \"" $$0 "\";";n=n+1}' > $@

test_input_constants.rs: public.json
	cat $< | grep -E '[0-9]*",?$$' |sed -e 's/[^0-9]//g' | \
		awk -n 'BEGIN{n=0} {print "pub(crate) const I" n " : &str = \"" $$0 "\";";n=n+1}' > $@

proof.json public.json &: circuit_final.zkey witness.wtns 
	$(SNARKJS) groth16 prove $^ proof.json public.json

distclean: clean
	rm -rf circuit_js/ circuit_cpp/ verifier.sol verification_key.json circuit_final.zkey* circuit.{sym,r1cs,r1cs.json} $(RUSTFILES)

clean:
	rm -f circuit.json public.json proof.json witness.wtns

.PHONY: test clean distclean default
