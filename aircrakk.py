from __future__ import annotations
import argparse
import dataclasses
import time

from tools.airodump import AccessPoint, Station, Dump
from tools.airmon import check_availability, monitoring_session


def get_header(columns: dict[str, int]):
    line = ""

    for name, width in columns.items():
        line += f"{name:<{width}}"

    return line


def get_row(something: any, columns: dict[str, int]):
    line = ""

    values = dataclasses.asdict(something).values()
    widths = columns.values()

    for value, width in zip(values, widths, strict=True):
        value = "-" if value is None else value
        line += f"{value:<{width}}"

    return line


def dump_table(items: dict[str, AccessPoint], keys: list[str], columns: dict[str, int]):
    print(get_header(columns))

    for key in keys:
        item = items[key]
        print(get_row(item, columns))


ACCESS_POINT_COLUMNS = {
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


def dump(monitoring_iface: str,
         monitoring_time_sec: int,
         keep_with_stations_only: bool):
    with Dump(monitoring_iface) as dump:
        print("Please wait...")
        time.sleep(monitoring_time_sec)

        access_points, stations = dump.get_snapshot()

        if keep_with_stations_only:
            access_points = {key: value for key, value in access_points.items() if key in stations}

        keys = sorted(access_points.keys(), key=lambda key: access_points[key].power, reverse=True)
        dump_table(access_points, keys, ACCESS_POINT_COLUMNS)

        print()

        keys = stations.keys()
        dump_table(stations, keys, STATION_COLUMNS)


def run(iface: str, *args):
    check_availability()

    with monitoring_session(iface) as monitoring_iface:
        dump(monitoring_iface, *args)


def main():
    parser = argparse.ArgumentParser("Wrapper over `aircrack-ng` tools")

    parser.add_argument("iface",
                        help="Wireless iface for monitoring")
    parser.add_argument("--sec",
                        help="Time to monitor",
                        type=int,
                        default=10)
    parser.add_argument("--with_stations_only",
                        help="Filter out access points without stations",
                        action='store_true')

    args = parser.parse_args()

    run(args.iface, args.sec, args.with_stations_only)


if __name__ == "__main__":
    main()
