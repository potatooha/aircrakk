from __future__ import annotations
from pathlib import Path
import re
import threading

from tools.crack_info import CrackProgressInfo
from utils.runner import Reader, Writer, Runner
from wordlists.paths import FAKE_WORDLIST_FILE_PATH


HASHCAT = 'hashcat'


class _HashcatReader(Reader):
    """Parses `hashcat`s output:

    ```
    Session..........: hashcat
    Status...........: Running
    ...
    Speed.#1.........:    18101 H/s (85.36ms) @ Accel:512 Loops:1024 Thr:1 Vec:8
    Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
    Progress.........: 995038/1000000 (99.50%)
    Rejected.........: 454366/995038 (45.66%)
    Restore.Point....: 989375/1000000 (98.94%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidate.Engine.: Device Generator
    Candidates.#1....: cindi1410 -> u7fd3ert
    Hardware.Mon.#1..: Temp: 86c Util: 98%
    ```
    """
    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._speed = None
        self._percentage = None
        self._last_passphrase = None
        self._is_key_found = False

    def get_progress_info(self) -> CrackProgressInfo:
        with self._lock:
            speed = self._speed
            percentage = self._percentage
            last_passphrase = self._last_passphrase

        return CrackProgressInfo(speed, percentage, last_passphrase)

    def get_key_if_found(self) -> str | None:
        with self._lock:
            return self._last_passphrase if self._is_key_found else None

    def _process_stdout(self, line: bytes):
        line = line.decode()
        line = line.strip()

        # Speed.#1.........:    17848 H/s (10.31ms) @ Accel:256 Loops:256 Thr:1 Vec:8
        match = re.search(r"Speed.+:\s+(.+)\(", line, flags=re.IGNORECASE)
        if match:
            speed = match.group(1)

            with self._lock:
                self._speed = speed

            return

        # Progress.........: 309848/1000000 (30.98%)
        match = re.match(r"Progress.+\((\d+.\d+%)\)", line, flags=re.IGNORECASE)
        if match:
            percentage = match.group(1)

            with self._lock:
                self._percentage = percentage

            return

        # Candidates.#1....: 14061954 -> m_a_r_s95
        match = re.match(r"Candidates.+: (.+) ->", line, flags=re.IGNORECASE)
        if match:
            passphrase = match.group(1)

            with self._lock:
                if self._is_key_found:
                    raise RuntimeError(f"Unexpected line: '{line}'")

                self._last_passphrase = passphrase

            return

        # Status...........: Running
        # Status...........: Exhausted
        # Status...........: Cracked
        match = re.match(r"Status.+: (.+)", line, flags=re.IGNORECASE)
        if match:
            status = match.group(1)

            if status.casefold() == "Cracked".casefold():
                with self._lock:
                    if self._is_key_found or not self._last_passphrase:
                        raise RuntimeError(f"Unexpected line: '{line}'")

                    self._is_key_found = True

            else:
                with self._lock:
                    if self._is_key_found:
                        raise RuntimeError(f"Unexpected line: '{line}'")

            return


class _HashcatWriter(Writer):
    def __init__(self):
        super().__init__()

    def _produce_stdin(self) -> bytes:
        # [s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>
        return b"s"


class Hashcat(Runner):
    def __init__(self,
                 capture_file_path: Path,
                 *,
                 wordlist_file_path: Path | None = None,
                 mask: str | None = None):
        self._reader = _HashcatReader()
        self._writer = _HashcatWriter()

        args = [
            HASHCAT,
            "-m", "2500", "--deprecated-check-disable",
            str(capture_file_path),
        ]

        if (
            (wordlist_file_path and mask) or
            (not wordlist_file_path and not mask)
        ):
            raise RuntimeError("Provide wordlist or mask")

        if wordlist_file_path:
            args.extend([
                "-a", "0",
                str(wordlist_file_path),
            ])

        if mask:
            args.extend([
                "-a", "3",
                mask,
            ])

        super().__init__(args, self._reader, self._writer)

    def get_progress_info(self) -> CrackProgressInfo:
        return self._reader.get_progress_info()

    def get_key_if_found(self) -> str | None:
        return self._reader.get_key_if_found()

    @staticmethod
    def is_capture_file_ok(path: Path) -> bool:
        with Hashcat(path, wordlist_file_path=FAKE_WORDLIST_FILE_PATH) as crack:
            return crack.wait() == 0
