from __future__ import annotations
import signal
import select
import subprocess
import threading

from utils.stoppable import Stoppable


class Reader(Stoppable):
    def __init__(self, timeout_sec: float = 0.5):
        super().__init__()
        self.timeout_sec = timeout_sec

    def _do_chunk_of_work(self, stdout):
        rlist, _, _ = select.select([stdout], [], [], self.timeout_sec)
        if len(rlist) > 0:
            self._process_stdout(rlist[0].readline())


class Runner:
    def __init__(self, args: list[str], reader: Reader):
        self._reader = reader
        self._process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self._thread = threading.Thread(target=self._reader, args=[self._process.stdout])
        self._thread.start()

    def poll(self) -> int | None:
        return self._process.poll()

    def wait(self, timeout_sec: float | None = None) -> int:
        return self._process.wait(timeout_sec)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._process.send_signal(signal.SIGINT)
        self._reader.stop()
        self._thread.join()
