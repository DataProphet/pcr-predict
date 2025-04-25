# `pcr-predict`

**Next-Boot TPM PCR Prediction for Grub**

`pcr-predict` is a lightweight Python script that enables prediction of TPM PCR
(Platform Configuration Register) values for the next system boot. This allows
you to update TPM security policies (e.g., for auto-unlocking encrypted disks)
after a kernel or initramfs upgrade by resealing secrets to the predicted PCR
values.

While systemd-boot natively supports resealing secrets to next-boot PCR values,
if you're using Grub there's very few options to try and perform the next-boot
PCR values.

## Features

- **Predict Next-Boot PCRs**: Use the TPM event log and on-disk binaries/configuration to calculate PCR values post-reboot.
- **TPM-Compatible Output**: Designed to support workflows that reseal secrets using predicted PCR values.
- **Simple Usage**: Single-script solution; run `pcr-predict.py -h` for usage information.
- **Minimal Dependencies**: Requires only the [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) package and Python 3.
- **Works on Debian-based systems**: Tested on Ubuntu

## Usage

Run the script with the `-h` (help) flag to see usage:

```bash
./pcr-predict.py -h
```

Typical prediction workflow (note the logs are writteen to `stderr`):

```bash
./pcr-predict.py
INFO:root:using kernel image /boot/vmlinuz-5.15.0-25-generic
INFO:root:using initramfs image /boot/initrd.img-5.15.0-25-generic
INFO:root:TPM event log has 92 entries
INFO:root:calculating digests against which key will be sealed
INFO:root:PCR0 : c540cb8d372b00f0e41f7076e4305fbaa695b0eaba239f300c5b7a86cf57e363
INFO:root:PCR4 : 7c1be4d3500db898ff3602cfb7b26755a1fa8835574a0f3b4b69ab9884687ea1
INFO:root:PCR8 : 967757a1f96d8972e450e833f874eb5ea64386b504d289737241891dc36fd104
INFO:root:PCR9 : 14684a7fa973992dc6c05945309b1bfc02c1736e0e0fb951c1f1b48119bae994
INFO:root:PCR15 : 0000000000000000000000000000000000000000000000000000000000000000
{
  "0": "c540cb8d372b00f0e41f7076e4305fbaa695b0eaba239f300c5b7a86cf57e363",
  "4": "7c1be4d3500db898ff3602cfb7b26755a1fa8835574a0f3b4b69ab9884687ea1",
  "8": "967757a1f96d8972e450e833f874eb5ea64386b504d289737241891dc36fd104",
  "9": "14684a7fa973992dc6c05945309b1bfc02c1736e0e0fb951c1f1b48119bae994",
  "15": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

This reads the TPM event log, measures current on-disk files (kernel,
initramfs, etc.), and prints the expected PCR values for the next boot.

You can then use these predicted PCR values with external tooling (such as
[Clevis](https://github.com/latchset/clevis)) to reseal disk unlock secrets.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file
for details.
