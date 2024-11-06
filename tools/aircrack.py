from __future__ import annotations
from pathlib import Path
import re
import subprocess
import threading


from utils.runner import Reader, Runner
from wordlists.paths import FAKE_WORDLIST_FILE_PATH


AIRCRACK = "aircrack-ng"


class _CrackReader(Reader):
    """Parses `aircrack-ng`s output:

    ```
    Current passphrase: qwerty
    KEY NOT FOUND
    KEY FOUND! [ 12345678 ]
    ```
    """
    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._speed = None
        self._percentage = None
        self._last_passphrase = None
        self._key = None

    def get_speed(self) -> str:
        with self._lock:
            return self._speed or ""

    def get_percentage(self) -> str:
        with self._lock:
            return self._percentage or ""

    def get_last_passphrase(self) -> str:
        """May lose spaces at the end (if it's not a key)."""
        with self._lock:
            return self._last_passphrase or ""

    def get_key_if_found(self) -> str | None:
        with self._lock:
            return self._key

    def _process_stdout(self, line: bytes):
        # Looks fragile, but blue tape should save us
        line = line.decode()
        line = line.strip()
        line = line.removeprefix("\x1b[11B")
        line = line.removeprefix("\x1b[8;28H\x1b[2K")
        line = line.removeprefix("\x1b[8;24H")
        line = line.strip()

        # [00:00:01] 4041/1000000 keys tested (6201.38 k/s)
        match = re.search(r"\[.+\] \d+/\d+ keys tested \((.+)\)", line, flags=re.IGNORECASE)
        if match:
            speed = match.group(1)

            with self._lock:
                self._speed = speed

            # Keep going. The next block is at the same line

        # Time left: --
        # Time left: 2 minutes, 40 seconds                           0.40%
        match = re.search(r"Time left: .+(\d+\.\d+%)", line, flags=re.IGNORECASE)
        if match:
            percentage = match.group(1)

            with self._lock:
                self._percentage = percentage

            return

        match = re.match(r"Current passphrase: (.*)", line, flags=re.IGNORECASE)
        if match:
            passphrase = match.group(1)

            with self._lock:
                if self._key:
                    raise RuntimeError(f"Unexpected line: '{line}'")

                self._last_passphrase = passphrase

            return

        match = re.match(r"KEY FOUND! \[ (.*) \]", line, flags=re.IGNORECASE)
        if match:
            passphrase = match.group(1)

            with self._lock:
                if self._key and passphrase != self._key:
                    raise RuntimeError(f"Unexpected line: '{line}'")

                self._last_passphrase = passphrase
                self._key = passphrase

            return

        if line == "KEY NOT FOUND":
            with self._lock:
                if self._key:
                    raise RuntimeError(f"Unexpected line: '{line}'")


class Crack(Runner):
    def __init__(self, capture_file_path: Path, wordlist_file_path: Path):
        self._reader = _CrackReader()

        args = [
            AIRCRACK,
            str(capture_file_path),
            "-w", str(wordlist_file_path),
        ]

        super().__init__(args, self._reader)

    def get_speed(self) -> str:
        return self._reader.get_speed()

    def get_percentage(self) -> str:
        return self._reader.get_percentage()

    def get_last_passphrase(self) -> str:
        return self._reader.get_last_passphrase()

    def get_key_if_found(self) -> str | None:
        return self._reader.get_key_if_found()


def is_capture_file_ok(path: Path) -> str:
    with Crack(path, FAKE_WORDLIST_FILE_PATH) as crack:
        return crack.wait() == 0
