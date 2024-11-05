from __future__ import annotations
import contextlib
import subprocess


AIREPLAY = "aireplay-ng"


def _run(args: list[str]):
    args = [AIREPLAY] + args

    print(' '.join(args))
    result = subprocess.run(args, capture_output=True)

    if result.returncode:
        print(result.stdout.decode())
        raise RuntimeError(f"{args} failed: {result.returncode}")


def fakeauth(monitoring_iface: str,
             bssid: str,
             *,
             ssid: str | None = None,
             smac: str | None = None):
    args = [
        monitoring_iface,
        "--fakeauth", "0", # One-shot
        "-o", "1",         # Number of packets per burst
        "-q", "10",        # Seconds between keep-alives
        "-a", bssid,       # Access point MAC
    ]

    if ssid:
        args.extend([
            "-e", ssid,    # Access point SSID
        ])

    if smac:
        args.extend([
            "-h", smac,    # Source MAC
        ])

    _run(args)


def deauth(monitoring_iface: str,
           bssid: str,
           *,
           dmac: str | None = None):
    args = [
        monitoring_iface,
        "--deauth", "1",   # One station
        "-a", bssid,       # Access point MAC
    ]

    if dmac:
        args.extend([
            "-c", dmac,    # Destination MAC
        ])

    _run(args)
