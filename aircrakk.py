from __future__ import annotations
import argparse
import dataclasses
import enum
import hashlib
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time

from config.crack_tool import CrackTool
from config.progress import Progress
from config.statistics import Statistics
from config.tasks import TaskKind, TaskInfo, load_tasks, WordlistInfo, MaskInfo, create_tasks
from tools.aircrack import Aircrack
from tools.aireplay import fakeauth, deauth
from tools.airmon import monitoring_session
from tools.airodump import AccessPoint, Station, Dump
from tools.cap2hccapx import convert_aircrack_capture_to_hashcat_format
from tools.crack_info import CrackSessionMode, CrackSession
from tools.file import is_text_file
from tools.hashcat import HashcatWorkloadProfile, Hashcat, get_supported_password_lengths
from utils.ansi import printc
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


class HandshakeAttack(enum.StrEnum):
    DEAUTH = 'deauth'
    FAKEAUTH = 'fakeauth'


def _handshake(dump: Dump,
               attack: HandshakeAttack,
               bssid: str,
               output_dir: Path):
    while not dump.has_handshake() or not _is_handshake_accepted(output_dir):
        time.sleep(10)

        access_points, stations = dump.get_snapshot()

        if bssid not in access_points:
            continue

        if attack == HandshakeAttack.FAKEAUTH:
            fakeauth(dump.monitoring_iface, bssid)

        else:
            assert attack == HandshakeAttack.DEAUTH

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
              attack: HandshakeAttack,
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
                _handshake(dump, attack, bssid, temporary_dir)

            print("Got a handshake!")

            # This capture has a handshake, it can be stored to `output_dir`
            for path in temporary_dir.glob("*"):
                shutil.copy(path, output_dir)


"""
    Splitting wordlists according to supported password lengths by kernel
"""

def _split_one(wordlist_file, hashcat_file, nohashcat_file, min_length: int, max_length: int):
    for line in wordlist_file:
        password = line.removesuffix(b'\n')
        password = password.removesuffix(b'\r')

        # $HEX[666f6f626172310d0a]
        match = re.match(rb"\$HEX\[(\d+)]\s*", password)
        if match:
            length = len(match.group(1)) / 2

        else:
            length = len(password)

        if length < min_length or length > max_length:
            nohashcat_file.write(line)

        else:
            hashcat_file.write(line)


def split_wordlists(wordlist_file_paths: list[Path]):
    min_length, max_length = get_supported_password_lengths()
    print(f"Supported password length by kernel: [{min_length}, {max_length}]")

    for wordlist_file_path in wordlist_file_paths:
        original_suffix = wordlist_file_path.suffix
        hashcat_file_path = wordlist_file_path.with_suffix(".hashcat" + original_suffix)
        nohashcat_file_path = wordlist_file_path.with_suffix(".nohashcat" + original_suffix)

        with (
            wordlist_file_path.open('rb') as wordlist_file,
            hashcat_file_path.open('wb') as hashcat_file,
            nohashcat_file_path.open('wb') as nohashcat_file,
        ):
            print(f"Splitting {str(wordlist_file_path)}...")
            _split_one(wordlist_file,
                       hashcat_file,
                       nohashcat_file,
                       min_length,
                       max_length)


"""
    Creating a tasks config file
"""

WORDLIST_GLOB_PATTERNS = [
    "*list*",
    "*.txt",
    "*.lst",
    "*.list",
]


def _scan_worldlists(wordlists: list[Path], wordlist_dirs: list[Path]) -> dict[Path, WordlistInfo]:
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
        wordlists[wordlist] = WordlistInfo(file_size)

    return wordlists


def _filter_wordlists(wordlists: dict[Path, int]) -> dict[Path, WordlistInfo]:
    filtered_wordlists = {}

    for wordlist, info in wordlists.items():
        if info.file_size == 0:
            print(f"Skipped empty wordlist {wordlist}")
            continue

        if not is_text_file(wordlist):
            print(f"Skipped binary file {wordlist}")
            continue

        filtered_wordlists[wordlist] = info

    return filtered_wordlists


def _sort_wordlists(wordlists: dict[Path, WordlistInfo]) -> dict[Path, WordlistInfo]:
    sorted_keys = sorted(wordlists.keys(), key=lambda key: wordlists[key].file_size, reverse=True)
    return {key: wordlists[key] for key in sorted_keys}


def create_tasks_config_file(wordlists: list[Path],
                             wordlist_dirs: list[Path],
                             cli_masks: list[str],
                             output: Path):
    if len(wordlist_dirs) > 0:
        print("Please wait...")

    wordlists = _scan_worldlists(wordlists, wordlist_dirs)
    wordlists = _filter_wordlists(wordlists)
    wordlists = _sort_wordlists(wordlists)

    print(f"{len(wordlists)} potential worldlist(s) found (you may need to clean wordlists manually)")

    masks = {}
    for cli_mask in cli_masks:
        tokens = cli_mask.split(',')

        mask = tokens[0]
        extra_args = tokens[1:]

        masks[mask] = MaskInfo(extra_args)

    print(f"{len(masks)} mask(s) provided")

    create_tasks(output, wordlists, masks)


"""
    Cracking
"""

@dataclasses.dataclass
class CrackResult:
    key: str | None
    failed: bool

    @staticmethod
    def from_found_key(key: str) -> CrackResult:
        return CrackResult(key=key, failed=False)

    @staticmethod
    def from_failed_or_exhausted(*, failed: bool) -> CrackResult:
        return CrackResult(key=None, failed=failed)


def _crack_one(tool_cls,
               capture_file_path: Path,
               *,
               wordlist_file_path: Path | None,
               mask: str | None,
               extra_args: list[str],
               workload_profile: HashcatWorkloadProfile,
               session: CrackSession) -> CrackResult:
    with tool_cls(capture_file_path,
                  wordlist_file_path=wordlist_file_path,
                  mask=mask,
                  extra_args=extra_args,
                  workload_profile=workload_profile,
                  session=session) as tool:
        while True:
            key = tool.get_key_if_found()
            if key:
                return CrackResult.from_found_key(key)

            exit_info = tool.get_exit_info()
            if exit_info is not None:
                if exit_info.is_error:
                    printc(f"Failed to crack: {exit_info.returncode}")
                else:
                    printc("Key is not found", end='\r', flush=True)
                return CrackResult.from_failed_or_exhausted(failed=exit_info.is_error)

            info = tool.get_progress_info()
            if not info.last_passphrase:
                time.sleep(0.5)
                continue

            line = f"Candidate: '{info.last_passphrase}'"

            if info.speed:
                line += ", speed: " + info.speed

            if info.percentage:
                line += ", done: " + info.percentage

            if info.hardware_state:
                line += ", hardware:"
                for key, value in info.hardware_state.items():
                    line += " " + key + "=" + value

            line += ", keep searching..."

            printc(line, end='\r', flush=True)
            time.sleep(1)


def _make_new_session(aircrack_capture_file_path: Path, task: str) -> CrackSession:
    session_dir_name = aircrack_capture_file_path.with_suffix(".sessions").name
    session_dir = aircrack_capture_file_path.parent / session_dir_name
    session_dir.mkdir(parents=True, exist_ok=True)

    session_file_name = hashlib.md5(task.encode()).hexdigest() + ".session"
    session_file_path = session_dir / session_file_name
    session_file_path.unlink(missing_ok=True)
    return CrackSession(session_file_path, CrackSessionMode.CREATE)


def _restore_session(session_file_path: Path) -> CrackSession:
    return CrackSession(session_file_path, CrackSessionMode.RESTORE)


def _fallback_to_new_session(session: CrackSession):
    session.path.unlink(missing_ok=True)
    session.mode = CrackSessionMode.CREATE


def _crack(aircrack_capture_file_path: Path,
           hashcat_capture_file_path: Path | None,
           tasks: dict[str, TaskInfo],
           statistics: Statistics,
           progress: Progress,
           workload_profile: HashcatWorkloadProfile,
           prefer_aircrack: bool) -> str | None:
    key = progress.get_key_if_found()
    if key:
        return key

    for task, info in tasks.items():
        if progress.is_finished(task):
            printc(f"Skipping exhausted '{task}'...")
            continue

        if info.disabled:
            printc(f"Skipping disabled '{task}'...")
            continue

        if info.kind == TaskKind.WORDLIST and not Path(task).is_file():
            printc(f"Skipping not available '{task}'...")
            continue

        preferred_tool = info.preferred_tool or (CrackTool.AIRCRACK if prefer_aircrack else CrackTool.HASHCAT)

        if preferred_tool == CrackTool.AIRCRACK and info.kind == TaskKind.WORDLIST:
            tool = CrackTool.AIRCRACK
            tool_cls = Aircrack
            capture_file_path = aircrack_capture_file_path

        else:
            tool = CrackTool.HASHCAT
            tool_cls = Hashcat
            capture_file_path = hashcat_capture_file_path

        if (existing_session_file_path := progress.get_session_if_in_progress(task, tool)):
            session = _restore_session(existing_session_file_path)

        else:
            session = _make_new_session(aircrack_capture_file_path, task)

        while True:
            is_session_restoration = session.mode.should_restore()

            progress.start(task, tool, session.path)

            wordlist_file_path = Path(task) if info.kind == TaskKind.WORDLIST else None
            mask = task if info.kind == TaskKind.MASK else None

            what = task + (' ' + ' '.join(info.extra_args) if len(info.extra_args) > 0 else '')
            suffix = " (restore session)" if is_session_restoration else ""
            printc(f"Trying to crack {str(capture_file_path)} with '{what}' by {tool}{suffix}...")

            result = _crack_one(tool_cls,
                                capture_file_path,
                                wordlist_file_path=wordlist_file_path,
                                mask=mask,
                                extra_args=info.extra_args,
                                workload_profile=workload_profile,
                                session=session)

            if is_session_restoration and not result.key and result.failed:
                # Could not restore the previous session. Fallback to a new one
                _fallback_to_new_session(session)
                continue

            break

        if result.key:
            progress.finish_with_key(task, result.key)
            statistics.increment(task)
            return result.key

        elif result.failed:
            progress.finish_failed(task)

        else:
            progress.finish_exhausted(task)

    return None


def crack(aircrack_capture_file_path: Path,
          tasks_config_file_path: Path,
          statistics_file_path: Path,
          progress_file_path: Path | None,
          workload_profile: HashcatWorkloadProfile,
          prefer_aircrack: bool):
    tasks = load_tasks(tasks_config_file_path)
    has_masks = any(info.kind == TaskKind.MASK for info in tasks.values())

    # `aircrack-ng` only works with wordlists
    if not prefer_aircrack or has_masks:
        hashcat_capture_file_path = aircrack_capture_file_path.with_suffix(".hccapx")
        convert_aircrack_capture_to_hashcat_format(aircrack_capture_file_path, hashcat_capture_file_path)

    else:
        hashcat_capture_file_path = None

    progress_file_path = progress_file_path or aircrack_capture_file_path.with_suffix(".progress.json")

    with (
        Statistics(statistics_file_path) as statistics,
        Progress(progress_file_path) as progress,
    ):
        key = _crack(aircrack_capture_file_path,
                     hashcat_capture_file_path,
                     tasks,
                     statistics,
                     progress,
                     workload_profile,
                     prefer_aircrack)
        if key:
            printc(f"Found key: '{key}'!")
            return

    printc("Key is not found")


"""
    CLI
"""

def on_dump(args: argparse.Namespace):
    dump(args.iface, args.sec, args.output, args.hide_if_no_stations)


def on_handshake(args: argparse.Namespace):
    handshake(args.iface, args.attack, args.channel, args.bssid, args.output_dir)


def on_splitter(args: argparse.Namespace):
    split_wordlists(args.wordlist)


def on_tasks(args: argparse.Namespace):
    create_tasks_config_file(args.wordlist, args.wordlist_dir, args.mask, args.output)


def on_crack(args: argparse.Namespace):
    crack(args.capture,
          args.tasks,
          args.statistics,
          args.progress,
          args.workload_profile,
          args.prefer_aircrack)


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
    handshake_parser.add_argument("attack",
                                  help="Attack method for `aireplay-ng`",
                                  type=HandshakeAttack,
                                  choices=list(HandshakeAttack))
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

    splitter_parser = subparsers.add_parser("splitter")
    splitter_parser.add_argument("--wordlist",
                                 help="Wordlist to split",
                                 type=Path,
                                 action='append',
                                 default=[])
    splitter_parser.set_defaults(handler=on_splitter)

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
                              help="Brute-force attack mask (or mask,extra_arg1,extra_arg2...)",
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
    crack_parser.add_argument("--progress",
                              help="Task progress file (will create a new one if it not exists)",
                              type=Path)
    crack_parser.add_argument("--workload_profile",
                              help="`hashcat` workload profile",
                              type=HashcatWorkloadProfile,
                              choices=list(HashcatWorkloadProfile),
                              default=HashcatWorkloadProfile.HIGH)
    crack_parser.add_argument("--prefer_aircrack",
                              action='store_true')
    crack_parser.set_defaults(handler=on_crack)

    args = parser.parse_args()

    if args.command == None:
        parser.error("Please specify a command")

    args.handler(args)


if __name__ == "__main__":
    main()
