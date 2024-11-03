from __future__ import annotations
import contextlib
import sys
import subprocess


AIRMON = "airmon-ng"


def check_availability():
    result = subprocess.run([AIRMON], capture_output=True)
    if result.returncode:
        print(result.stdout.decode())
        sys.exit(result.returncode)


@contextlib.contextmanager
def monitoring_session(iface: str):
    print("Start monitoring...")
    subprocess.check_call([AIRMON, "start", iface], stdout=subprocess.DEVNULL)

    monitoring_iface = iface + "mon"
    yield monitoring_iface

    print("Stop monitoring...")
    subprocess.check_call([AIRMON, "stop", monitoring_iface], stdout=subprocess.DEVNULL)
