#! /usr/bin/bash
# This module installs a service to "taint" the TPM right after the root disk
# has been unlocked. This prevents a disk unlock bypass by spoofing a LUKS
# volume (see the install() section for more details on how this is achieved)

check() {
	# check that all the binaries used in the taint script are available on the
	# host system
	require_binaries dd sha256sum cut tpm2_pcrextend || return 1

	# all checks succeeded
	return 0
}

depends() {
	# ensure systemd is included in the initramfs
	echo "systemd"
}

install() {
	# Installs a script that "taints" the TPM in early boot, which causes the
	# TPM to seal before pivoting to the new root. This makes the disk-unlock
	# password inaccessible after boot, preventing a TPM bypass using a spoofed
	# LUKS volume. See
	# https://oddlama.org/blog/bypassing-disk-encryption-with-tpm2-unlock/

	# add the required commands
	inst_binary dd
	inst_binary sha256sum
	inst_binary cut
	inst_binary tpm2_pcrextend

	# PCR register to taint
	# NOTE using PCR15 as it's the same register that systemd uses for its
	# own luks taint mechanism, so if you switch to systemd's implementation the
	# same PCR can still be used
	PCR=15

	# add the taint-tpm script
	TAINT_SCRIPT="/usr/local/bin/taint-tpm.sh"
	cat > "${initdir}${TAINT_SCRIPT}" <<EOF
#! /bin/bash

# calculate the hash of random data and extend the TPM taint register with it
random_hash=\$(dd if=/dev/urandom bs=1024 count=1 status=none | sha256sum | cut -d ' ' -f 1)

tpm2_pcrextend "${PCR}:sha256=\${random_hash}"
EOF

	chmod +x "${initdir}${TAINT_SCRIPT}"

	# add the tpm taint service and schedule it so that it runs right after the
	# root volume has been unlocked
	TAINT_SERVICE="taint-tpm"
	cat > "${initdir}/etc/systemd/system/${TAINT_SERVICE}.service" <<EOF
[Unit]
After=cryptsetup.target

[Service]
ExecStart=${TAINT_SCRIPT}

[Install]
WantedBy=sysinit.target
EOF

	systemctl -q --root "${initdir}" enable "${TAINT_SERVICE}"
}
