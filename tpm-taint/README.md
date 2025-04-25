# TPM-taint dracut module

**45tpm-taint** is a dracut module that installs a service to *"taint"* the TPM (Trusted Platform Module) immediately after the root disk is unlocked during early boot. This prevents TPM-based disk unlock bypasses by sealing the TPM before pivoting to the real root filesystem.

This protection mitigates attacks that involve spoofing a LUKS volume to trick the TPM into releasing secrets, as described in [this blog post](https://oddlama.org/blog/bypassing-disk-encryption-with-tpm2-unlock/).

## Installation

1. Copy the `45tpm-taint` directory into your dracut modules path (usually `/usr/lib/dracut/modules.d/` or `/etc/dracut/modules.d/`):

   ```bash
   sudo cp -r 45tpm-taint /usr/lib/dracut/modules.d/
   ```

2. Regenerate your initramfs to include the module:

   ```bash
   sudo dracut -f
   ```

After installation, the TPM will be "tainted" just after the disk unlock, sealing it and preventing reuse of TPM-bound secrets during later boot stages.
