from __future__ import annotations
import argparse
import dataclasses
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

from tools.airodump import AccessPoint, Station, Dump
from tools.airmon import monitoring_session
from utils.dumping import get_table, get_dataclass_getter


"""
    Dumping access points and stations
"""

ACCESS_POINT_COLUMNS = {
    "": 2, # Extra field that shows that this access point has stations
    "BSSID": 19,
    "PWR": 5,
    "Beacons": 11,
    "#Data,": 7,
    "#/s": 4,
    "CH": 5,
    "MB": 5,
    "ENC": 5,
    "CIPHER": 7,
    "AUTH": 5,
    "ESSID": 0,
}


STATION_COLUMNS = {
    "BSSID": 19,
    "STATION": 19,
    "PWR": 7,
}


def _get_access_point_getter(stations: dict[str, Station]):
    get_extra_field = lambda access_point: '*' if access_point.bssid in stations else ' '
    return lambda access_point: [get_extra_field(access_point)] + list(get_dataclass_getter()(access_point))


def _get_lines(access_points: dict[str, AccessPoint],
               stations: dict[str, Station]) -> list[str]:
    lines = []

    keys = sorted(access_points.keys(), key=lambda key: access_points[key].power, reverse=True)
    lines.extend(get_table(access_points, _get_access_point_getter(stations), keys, ACCESS_POINT_COLUMNS))

    lines.append("")

    keys = stations.keys()
    lines.extend(get_table(stations, get_dataclass_getter(), keys, STATION_COLUMNS))

    lines.append("")

    return lines


def _dump(dump: Dump,
          monitoring_time_sec: int,
          output_file: Path | None,
          hide_if_no_stations: bool):
    print("Please wait...")
    time.sleep(monitoring_time_sec)

    access_points, stations = dump.get_snapshot()

    if hide_if_no_stations:
        access_points = {key: value for key, value in access_points.items() if key in stations}

    lines = _get_lines(access_points, stations)
    text = '\n'.join(lines)

    if output_file:
        with output_file.open("w") as file:
            file.write(text)

    sys.stdout.write(text)


def dump(iface: str, *args):
    with monitoring_session(iface) as monitoring_iface:
        with Dump(monitoring_iface) as dump:
            _dump(dump, *args)


"""
    Handshaking
"""

def _get_cap_file_path(dir: Path) -> Path:
    paths = list(dir.glob("*.cap"))
    if len(paths) != 1:
        raise RuntimeError(f"Expected one .cap file, but got {paths}")

    return paths[0]


def _is_handshake_accepted(dir: Path) -> bool:
    path = _get_cap_file_path(dir)

    # TODO: call `aircrack-ng` on a small wordlist
    return True


def _handshake(dump: Dump,
               bssid: str,
               output_dir: Path):
    while not dump.has_handshake() or not _is_handshake_accepted(dump, output_dir):
        access_points, stations = dump.get_snapshot()

        if bssid not in access_points:
            time.sleep(1)
            continue

        # TODO: implement me
        time.sleep(1)


def _get_dump_output_dir(bssid: str, basic_output_dir: Path) -> Path:
    bssid = bssid.replace(":", "")
    bssid = bssid.lower()

    return basic_output_dir / bssid


def handshake(iface: str,
              channel: int,
              bssid: str,
              basic_output_dir: Path):
    with monitoring_session(iface) as monitoring_iface:
        output_dir =_get_dump_output_dir(bssid, basic_output_dir)
        os.makedirs(output_dir, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=output_dir) as temporary_dir:
            temporary_dir = Path(temporary_dir)
            dump_prefix = str(temporary_dir / "dump")

            with Dump(monitoring_iface, channel=channel, bssid=bssid, dump_prefix=dump_prefix) as dump:
                _handshake(dump, bssid, temporary_dir)

            # This capture has a handshake, it can be stored to `output_dir`
            for path in temporary_dir.glob("*"):
                shutil.copy(path, output_dir)

"""
    CLI
"""

def on_dump(args: argparse.Namespace):
    dump(args.iface, args.sec, args.output, args.hide_if_no_stations)


def on_handshake(args: argparse.Namespace):
    handshake(args.iface, args.channel, args.bssid, args.output_dir)


def main():
    parser = argparse.ArgumentParser("Wrapper over `aircrack-ng` tools")

    subparsers = parser.add_subparsers(dest='command')

    dump_parser = subparsers.add_parser("dump",
                                        help="Dump access points and stations")
    dump_parser.add_argument("iface",
                             help="Wireless iface for monitoring")
    dump_parser.add_argument("--sec",
                             help="Time to monitor",
                             type=int,
                             default=10)
    dump_parser.add_argument("--output",
                             help="Dump the table to a file",
                             type=Path)
    dump_parser.add_argument("--hide_if_no_stations",
                             help="Filter out access points without stations",
                             action='store_true')
    dump_parser.set_defaults(handler=on_dump)

    handshake_parser = subparsers.add_parser("handshake",
                                             help="Get a handshake")
    handshake_parser.add_argument("iface",
                                  help="Wireless iface for monitoring")
    handshake_parser.add_argument("--channel",
                                  help="Channel of an access point",
                                  type=int,
                                  required=True)
    handshake_parser.add_argument("--bssid",
                                  help="Mac address of an access point",
                                  required=True)
    handshake_parser.add_argument("--output_dir",
                                  help="Basic directory where dump files should be stored",
                                  type=Path,
                                  required=True)
    handshake_parser.set_defaults(handler=on_handshake)

    args = parser.parse_args()

    if args.command == None:
        parser.error("Please specify a command")

    args.handler(args)


if __name__ == "__main__":
    main()
