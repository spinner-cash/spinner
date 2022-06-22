PTAU=powersOfTau28_hez_final_16.ptau

download: $(PTAU) checksum

powersOfTau28_hez_final_16.ptau:
	curl -Lo $@ https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_16.ptau

checksum: checksum.txt
	sha256sum -c $<

distclean:
	rm -rf *.ptau

.PHONY: distclean checksum download
