#! /usr/bin/env python3
"""
This script uses the information available in the TPM event log, and the current on-disk
config and binaries to predict what the TPM's PCR values will be the next time the host
reboots. This allows updating TPM security policies after a kernel upgrade to match the
next-boot values, ensuring that auto-unlock proceeds to work after kernel upgrades.

Here's some background to help you understand what goes on in this script:

* The TPM performs "measurements" of various components of the system by hashing text
(e.g. kernel cmdline) or binary files (e.g. kernel image) to determine the current
system state
* Each measurement is stored in one of 16 PCRs (Platform Configuration Register) in the
form of one or more hashes (e.g. a register can store both sha1 and sha256 hashes
simultaneously)
* When a PCR needs to be updated (e.g. a new file needs to be measured), the next PCR
value is calculated using the following formula (this process is called extending the
PCR). Note this method of hashing ensures that the current PCR value is the result of
combining all the previous PCR values with the new value in a one-way manner (as you
cannot set the PCR to a specific value, you can only extend it with a new hash)

```
New digest = Hash(Old digest + Measured digest)
```

* The TPM stores an event log which is a log containing all the hashes that the PCRs
have been extended with, along with the hash source (i.e. the original string or
filepath that the PCR was extended with).
* The next-boot PCR values (i.e. the PCR values after restarting the host) can be
calculated by carefully merging the digest values from the TPM event log (current state)
with the predicted values of the next boot (by recalculating some of the digests by
measuring on-disk files and config)
"""

import argparse
import json
import hashlib
import subprocess
import typing
import gzip
import re
import sys
import logging
import tempfile
import platform
from collections import namedtuple
from pathlib import Path

import yaml

# default hasher to use for digest calculations
hasher = hashlib.sha256
hash_algo = hasher().name
EMPTY_PCR = bytes([0] * hasher().digest_size)

# path to the generated grub config file
GRUB_CFG = Path("/boot/grub/grub.cfg")

# represents a single event in the event log
# NOTE the digest is the digest of the event, not the digest of the PCR at that point in
# time
Event = namedtuple("Event", ("digest", "event"))


def parse_tpm_event_log() -> dict:
    """
    Parses the TPM event log and returns the raw parsed dict
    """

    # parse the event log
    raw_log = subprocess.run(
        ["tpm2_eventlog", "/sys/kernel/security/tpm0/binary_bios_measurements"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout

    return yaml.safe_load(raw_log)


def get_current_pcr_value(index: int) -> bytes:
    """
    Returns the current digest value of the given PCR index
    """

    with tempfile.NamedTemporaryFile("rb") as f:
        # write the pcr value to a temp file
        subprocess.run(
            ["tpm2_pcrread", "-o", f.name, f"{hash_algo}:{index}"],
            check=True,
            capture_output=True,
        )

        return f.read()


def get_events(log: dict, pcr: int) -> list[Event]:
    """
    Extracts the list of Events and their digests for the given pcr index
    """

    events: list[Event] = []

    for event in log["events"]:
        # filter for the correct PCR
        if event["PCRIndex"] != pcr:
            continue

        # find the correct digest
        extracted_digest = None
        for digest in event["Digests"]:
            if digest["AlgorithmId"] != hash_algo:
                continue

            extracted_digest = bytes.fromhex(digest["Digest"])
            break

        else:
            raise RuntimeError("Could not extract digest from event")

        events.append(Event(digest=extracted_digest, event=event["Event"]))

    return events


def get_kernel_image() -> Path:
    """
    Returns a path to the default kernel image in /boot
    """

    # NOTE `vmlinuz` is a symlink to the default kernel, hence the `resolve`
    return Path("/boot/vmlinuz").resolve()


def get_initramfs_image() -> Path:
    """
    Returns the path to the default initramfs image in /boot
    """

    # NOTE ubuntu still names the initramfs `initrd`, even though it has transitioned to
    # initramfs images
    # NOTE `initrd.img` is a symlink to the default initramfs image, hence the `resolve`
    return Path("/boot/initrd.img").resolve()


def extend_pcr(pcr: bytes, new: bytes) -> bytes:
    """
    Extends the given pcr with the new bytes
    """

    return hasher(pcr + new).digest()


def str_digest(s: str) -> bytes:
    """
    Calculates the digest for the given string
    """

    return hasher(s.encode()).digest()


def file_digest(f: typing.IO[bytes]) -> bytes:
    """
    Calculates the file digest for the given file-like object (should be opened in
    binary mode)
    """

    h = hasher()
    while chunk := f.read(h.block_size):
        h.update(chunk)

    return h.digest()


def predict_pcr8(log: dict) -> bytes:
    """
    Predicts the next-boot value of PCR8, which measures all the executed grub commands,
    and executed kernel command-line
    """

    # get PCR8's events
    events = get_events(log, 8)

    # calculate the new pcr value
    pcr = EMPTY_PCR

    # extract the raw menu entries from the grub cfg (merged with the TPM event log to
    # produce the predicted grub config)
    # NOTE the menu entries are the options you see when grub starts up e.g. "Ubuntu
    # linux-5.14.133" - since they contain the kernel name they need to be updated to
    # the new kernel name for the PCR prediction, as the menu entry name is also hashed
    # as part of the TPM event log.
    MENU_ENTRY_PATTERN = re.compile(
        r"((?:^submenu[\s\S]+?^})|(?:^menuentry[\s\S]+?^}))",
        re.MULTILINE,
    )

    with GRUB_CFG.open("r") as f:
        raw_menu_entries = iter(re.findall(MENU_ENTRY_PATTERN, f.read()))

    # get the name of the next kernel image to be booted
    kernel_image = get_kernel_image()

    for event in events:
        # get the event string (grub_cmd: removed for convenience)
        estr = event.event["String"].removeprefix("grub_cmd: ")

        if estr.startswith("menuentry ") or estr.startswith("submenu "):
            # menu or submenu entry, calculate a new hash from the entries extracted
            # from the grub cfg
            # NOTE the extracted grub config is only used to replace the content inside
            # the braces, as the content before the first brace is evaled before it is
            # measured (i.e. different from the config file) and seems to be constant
            # from kernel-to-kernel
            entry = next(raw_menu_entries)
            entry = estr.partition("{")[0] + "{" + entry.partition("{")[-1]

            pcr = extend_pcr(pcr, str_digest(entry))

        elif estr.startswith("linux /vmlinuz") or estr.startswith("kernel_cmdline: "):
            # kernel image load, needs to be updated with the right path + cmdline

            # read the current cmdline and remove the BOOT_IMAGE prefix (first field in
            # cmdline, separated by space)
            cmdline = Path("/proc/cmdline").read_text().strip().partition(" ")[-1]

            # generate the new grub line
            new_line = f"/{kernel_image.name} {cmdline}"

            if estr.startswith("linux "):
                # add the linux prefix for the grub_cmd lines
                new_line = "linux " + new_line

            pcr = extend_pcr(pcr, str_digest(new_line))

        elif estr.startswith("initrd /"):
            # initramfs load, update with the right path
            new_line = f"initrd /{get_initramfs_image().name}"
            pcr = extend_pcr(pcr, str_digest(new_line))

        else:
            # if not a top-level menu or sub-menu entry, read in as-is into the pcr
            # register
            pcr = extend_pcr(pcr, event.digest)
            continue

    return pcr


def predict_pcr9(log: dict) -> bytes:
    """
    Predicts the next-boot value of PCR9, which measures the executed Grub EFI code,
    executed kernel image and the initramfs image

    When there's been a kernel or initramfs update, we expect only three elements in the
    measurements to change, namely:

    1. The hash of the on-disk generated grub config
    2. The hash of the initramfs image, and
    3. The hash of the kernel image

    The rest of the measurements are taken as-is from the TPM event log, and combined
    with the calculated measurements (from what's available on-disk) to predict the next
    PCR9 value.
    """

    # get PCR9's events
    events = get_events(log, 9)

    # this pattern matches the event that measures the grub config
    GRUB_CFG_PATTERN = re.compile(r"\(hd\d+,gpt\d+\)/grub/grub\.cfg")

    # reconstruct the pcr, skipping the last two events (manually calculated after the
    # loop)
    pcr = EMPTY_PCR

    for event in events[:-2]:
        if re.fullmatch(GRUB_CFG_PATTERN, event.event.get("String", "")):
            # this event measures the hash of the on-disk grub config file, calculate it
            # from the current on-disk config
            with GRUB_CFG.open("rb") as f:
                pcr = extend_pcr(pcr, file_digest(f))
        else:
            # re-use the existing PCR event digest
            pcr = extend_pcr(pcr, event.digest)

    # second-to-last event is the digest of the kernel image
    # NOTE on aarch64 grub first decompresses the kernel image (compressed with gzip)
    # before taking the digest, however on amd64 the digest of the compressed kernel
    # image is used as-is
    kernel_image = get_kernel_image()

    if platform.machine() == "aarch64":
        with gzip.open(kernel_image, "rb") as f:
            pcr = extend_pcr(pcr, file_digest(f))
    else:
        with kernel_image.open("rb") as f:
            pcr = extend_pcr(pcr, file_digest(f))

    # last event is the file digest of the initramfs image
    initramfs_image = get_initramfs_image()
    with initramfs_image.open("rb") as f:
        pcr = extend_pcr(pcr, file_digest(f))

    return pcr


def get_args() -> argparse.Namespace:
    """
    Parses the CLI args
    """

    # set up the arg parser with formatter to print defaults in help
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )

    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        # ensure logs are written to stderr (default)
        stream=sys.stderr,
        level=logging.INFO,
    )

    args = get_args()

    logging.info("using kernel image %s", get_kernel_image())
    logging.info("using initramfs image %s", get_initramfs_image())

    event_log = parse_tpm_event_log()
    logging.info("TPM event log has %d entries", len(event_log["events"]))

    # These are the monitored PCR indexes that will be used in the policy for sealing
    # the disk encryption secret. They were chosen to form a full chain of trust without
    # relying on a working secure boot setup (GRUB cannot perform initramfs measurements
    # when using secure boot as it can't sideload the TPM module)
    MONITORED_PCRS: list[int] = [
        0,  # uefi firmware
        4,  # grub firmware
        8,  # kernel runtime parameters (cmdline + executed grub commands)
        9,  # kernel + initramfs image hashes
        15,  # custom TPM-taint register
    ]

    # These callables aim to predict the PCR values for the next boot. Monitored PCR
    # indexes that do not have predictors are assumed to not change on the next boot
    # (i.e. the disk encryption secret will be sealed against the current PCR value)
    # NOTE PCR15 is the TPM-taint register - when the disk-unlock password is read from
    # the TPM this register will still be empty, however it is extended with random
    # bytes once the disk-unlock is complete. See the tpm-tain dracut module for more
    # details
    PCR_PREDICTORS: dict[int, typing.Callable[int, bytes]] = {
        8: predict_pcr8,
        9: predict_pcr9,
        15: lambda _: EMPTY_PCR,
    }

    # calculate the predict PCR digests
    logging.info("calculating digests against which key will be sealed")
    digests: dict[int, bytes] = {}
    for index in MONITORED_PCRS:
        # check if this index can be predicted, and if not, just use the current pcr
        # value
        if index in PCR_PREDICTORS:
            # predict the value
            digests[index] = PCR_PREDICTORS[index](event_log).hex()
        else:
            # cannot be predicted, just use current value
            digests[index] = get_current_pcr_value(index).hex()

        logging.info("PCR%d : %s", index, digests[index])

    # print the predicted digests
    print(json.dumps(digests, indent=2))
