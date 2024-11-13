from __future__ import annotations
from pathlib import Path
import re
import threading

from fakes.paths import FAKE_WORDLIST_FILE_PATH
from tools.crack_info import CrackProgressInfo, CrackExitInfo, CrackSession
from utils.runner import Reader, Runner


AIRCRACK = 'aircrack-ng'


class _AircrackReader(Reader):
    """Parses `aircrack-ng`s output:

    ```
    [00:00:05] 20859/10303727 keys tested (16857.63 k/s)

    Time left: 10 minutes, 9 seconds                           0.20%

                     Current passphrase: helloworld

    ...
    ```
    """
    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._speed = None
        self._percentage = None
        self._last_passphrase = None
        self._key = None

    def get_progress_info(self) -> CrackProgressInfo:
        with self._lock:
            speed = self._speed
            percentage = self._percentage
            last_passphrase = self._last_passphrase

        return CrackProgressInfo(speed, percentage, last_passphrase)

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

        # Current passphrase: qwerty
        match = re.match(r"Current passphrase: (.*)", line, flags=re.IGNORECASE)
        if match:
            passphrase = match.group(1)

            with self._lock:
                if self._key:
                    raise RuntimeError(f"Unexpected line: '{line}'")

                self._last_passphrase = passphrase

            return

        # KEY FOUND! [ 12345678 ]
        match = re.match(r"KEY FOUND! \[ (.*) \]", line, flags=re.IGNORECASE)
        if match:
            passphrase = match.group(1)

            with self._lock:
                if self._key and passphrase != self._key:
                    raise RuntimeError(f"Unexpected line: '{line}'")

                self._last_passphrase = passphrase
                self._key = passphrase

            return

        # KEY NOT FOUND
        if line == "KEY NOT FOUND":
            with self._lock:
                if self._key:
                    raise RuntimeError(f"Unexpected line: '{line}'")


class Aircrack(Runner):
    def __init__(self,
                 capture_file_path: Path,
                 *,
                 wordlist_file_path: Path,
                 mask: None = None,
                 extra_args: list[str] = [],
                 session: CrackSession | None = None,
                 **kwargs):
        self._reader = _AircrackReader()

        args = [
            AIRCRACK,
        ]

        is_session_restoration = session and session.mode.should_restore()
        if not is_session_restoration:
            args.extend([
                str(capture_file_path),
                "-w", str(wordlist_file_path),
            ])

            if mask:
                raise RuntimeError("Masks are not supported")

            if extra_args:
                args.extend(extra_args)

        if session:
            key = "-R" if session.mode.should_restore() else "-N"
            args.extend([
                key, str(session.path),
            ])

        super().__init__(args, self._reader)

    def get_progress_info(self) -> CrackProgressInfo:
        return self._reader.get_progress_info()

    def get_key_if_found(self) -> str | None:
        return self._reader.get_key_if_found()

    def get_exit_info(self) -> CrackExitInfo | None:
        returncode = self.poll()
        if returncode is None:
            return None

        return CrackExitInfo(is_error=(returncode != 0),
                             returncode=returncode)

    @staticmethod
    def is_capture_file_ok(path: Path) -> bool:
        with Aircrack(path, wordlist_file_path=FAKE_WORDLIST_FILE_PATH) as crack:
            return crack.wait() == 0
