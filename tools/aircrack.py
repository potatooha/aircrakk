from __future__ import annotations
from pathlib import Path
import re
import subprocess
import threading


from utils.runner import Reader, Runner
from wordlists.paths import FAKE_WORDLIST_FILE_PATH


AIRCRACK = "aircrack-ng"


class _CrackReader(Reader):
    """Parses `aircrack-ng`s output key line:

    ```
    Current passphrase: qwerty
    KEY NOT FOUND
    KEY FOUND! [ 12345678 ]
    ```
    """
    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._last_passphrase = None
        self._key = None

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

    def get_last_passphrase(self) -> str:
        return self._reader.get_last_passphrase()

    def get_key_if_found(self) -> str | None:
        return self._reader.get_key_if_found()


#def _run_blindly(args: list[str]) -> int:
#    args = [AIRCRACK] + args
#
#    result = subprocess.run(args, capture_output=True)
#    return result.returncode


def is_capture_file_ok(path: Path) -> str:
    with Crack(path, FAKE_WORDLIST_FILE_PATH) as crack:
        return crack.wait() == 0

    #return _run_blindly(path, FAKE_WORDLIST_FILE_PATH) == 0
