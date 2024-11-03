from __future__ import annotations
import enum
import dataclasses
import threading

from utils.parsing import Column, parse_row
from utils.runner import Reader, Runner


AIRODUMP = "airodump-ng"


@dataclasses.dataclass
class AccessPoint:
    bssid: str
    power: int
    beacons: int
    packets: int
    packets_per_second: int
    channel: int
    speed: int
    encryption: str | None
    cipher: str | None
    protocol: str | None
    name: str | None


@dataclasses.dataclass
class Station:
    bssid: str
    station: str
    power: int


# BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID
# 54:63:C8:A6:D2:28  -82        0        0    0  -1   -1                    <length:  0>
# 86:42:45:C5:A9:7E  -90        1        0    0  11  130   OPN              MY WIFI
# 85:F4:33:2E:98:48  -82        2        0    0   6  360   WPA2 CCMP   PSK  Guest
ACCESS_POINT_COLUMNS = {
    "BSSID":   Column(width=19, required=True),
    "PWR":     Column(width=5,  required=True),
    "Beacons": Column(width=7,  required=True),
    "#Data,":  Column(width=9,  required=True),
    "#/s":     Column(width=5,  required=True),
    "CH":      Column(width=4,  required=True),
    "MB":      Column(width=5,  required=True),
    "ENC":     Column(width=7,  required=False),
    "CIPHER":  Column(width=8,  required=False),
    "AUTH":    Column(width=5,  required=False),
    "ESSID":   Column(width=-1, required=True),
}

# BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes
# D8:47:32:5A:A3:B2  10:08:C1:11:2B:D5  -94    0 - 1      0        2
# F0:B4:D2:A6:AD:43  22:1F:3F:B3:9D:60  -91    0 - 1e     0        1
# F4:E5:78:AC:66:E7  3C:0B:4F:B2:9B:4E   -1   12e- 0      0        7
STATION_COLUMNS = {
    "BSSID":   Column(width=19, required=True),
    "STATION": Column(width=19, required=True),
    "PWR":     Column(width=6, required=True),
    # Other columns are ignored
}


class _DumpBlock(enum.Enum):
    ACCESS_POINT_LIST = enum.auto()
    STATION_LIST = enum.auto()


class _DumpReader(Reader):
    def __init__(self):
        super().__init__()
        self._current_block = None
        self._lock = threading.Lock()
        self._has_handshake = False
        self._access_points = {}
        self._stations = {}

    def get_snapshot(self) -> tuple[dict[str, AccessPoint], dict[str, Station]]:
        with self._lock:
            access_points = {key: value for key, value in self._access_points.items()}
            stations = {key: value for key, value in self._stations.items()}

        return access_points, stations

    def has_handshake(self) -> bool:
        with self._lock:
            return self._has_handshake

    def _process_stdout(self, line: bytes):
        line = line.decode()
        line = line.strip()
        line = line.removeprefix("\x1b[0K\x1b[1B")
        line = line.removesuffix("\x1b[0K")
        line = line.strip()

        tokens = line.split()

        # Blocks
        if all(token in tokens for token in ["BSSID", "PWR", "Beacons"]):
            self._current_block = _DumpBlock.ACCESS_POINT_LIST
            return

        elif all(token in tokens for token in ["BSSID", "STATION", "PWR"]):
            self._current_block = _DumpBlock.STATION_LIST
            return

        elif all(token in tokens for token in ["CH", "Elapsed:"]):
            self._current_block = None
            # TODO: implement me
            if "handshake" in line:
                with self._lock:
                    self._has_handshake = True

            return

        # Items in blocks
        if self._current_block == _DumpBlock.ACCESS_POINT_LIST:
            access_point = _DumpReader._parse_access_point(line)
            with self._lock:
                self._access_points[access_point.bssid] = access_point
            return

        elif self._current_block == _DumpBlock.STATION_LIST:
            station = _DumpReader._parse_station(line)
            if station:
                with self._lock:
                    self._stations[station.bssid] = station
            return

    @staticmethod
    def _parse_access_point(line: str) -> AccessPoint:
        try:
            columns = parse_row(line, ACCESS_POINT_COLUMNS)

            return AccessPoint(
                bssid=columns[0],
                power=int(columns[1]),
                beacons=int(columns[2]),
                packets=int(columns[3]),
                packets_per_second=int(columns[4]),
                channel=int(columns[5]),
                speed=int(columns[6]),
                encryption=columns[7],
                cipher=columns[8],
                protocol=columns[9],
                name=None if columns[10] == "<length:  0>" else columns[10],
            )

        except Exception:
            raise RuntimeError(f"Failed to parse line: '{line}'")

    @staticmethod
    def _parse_station(line: str) -> AccessPoint | None:
        try:
            if "(not associated)" in line:
                return None

            columns = parse_row(line, STATION_COLUMNS)

            return Station(
                bssid=columns[0],
                station=columns[1],
                power=int(columns[2]),
            )

        except Exception:
            raise RuntimeError(f"Failed to parse line: '{line}'")


class Dump(Runner):
    def __init__(self,
                 monitoring_iface: str,
                 *,
                 channel: int | None = None,
                 bssid: str | None = None,
                 dump_prefix: str | None = None):
        self._reader = _DumpReader()

        args = [
            AIRODUMP,
            monitoring_iface
        ]

        if channel:
            args.extend([
                "-c",
                str(channel),
            ])

        if bssid:
            args.extend([
                "--bssid",
                bssid,
            ])

        if dump_prefix:
            args.extend([
                "-w",
                dump_prefix,
            ])

        super().__init__(args, self._reader)

    def get_snapshot(self) -> tuple[dict[str, AccessPoint], dict[str, Station]]:
        return self._reader.get_snapshot()

    def has_handshake(self) -> bool:
        return self._reader.has_handshake()
