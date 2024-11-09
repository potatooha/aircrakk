from __future__ import annotations
import contextlib
import subprocess


AIRMON = 'airmon-ng'


def _run(args: list[str] = []):
    args = [AIRMON] + args

    result = subprocess.run(args, capture_output=True)

    if result.returncode:
        print(result.stdout.decode())
        raise RuntimeError(f"{args} failed: {result.returncode}")


def _check_availability():
    _run()


@contextlib.contextmanager
def monitoring_session(iface: str):
    _check_availability()

    print("Start monitoring...")
    _run(["start", iface])

    monitoring_iface = iface + "mon"

    try:
        yield monitoring_iface

    finally:
        print("Stop monitoring...")
        _run(["stop", monitoring_iface])
