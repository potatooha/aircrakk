from __future__ import annotations
import select
import signal
import subprocess
import threading
import time

from utils.stoppable import Stoppable


class Reader(Stoppable):
    def __init__(self, timeout_sec: float = 0.5):
        super().__init__()
        self._timeout_sec = timeout_sec

    def _do_chunk_of_work(self, stdout: subprocess.IO[bytes]):
        rlist, _, _ = select.select([stdout], [], [], self._timeout_sec)
        if len(rlist) > 0:
            self._process_stdout(rlist[0].readline())


class Writer(Stoppable):
    def __init__(self, timeout_sec: float = 1.0):
        super().__init__()
        self._timeout_sec = timeout_sec

    def _do_chunk_of_work(self, stdin: subprocess.IO[bytes]):
        data = self._produce_stdin()

        try:
            stdin.write(data)
            stdin.flush()
        except BrokenPipeError:
            return

        time.sleep(self._timeout_sec)


class Runner:
    def __init__(self,
                 args: list[str],
                 reader: Reader,
                 writer: Writer | None = None):
        self._reader = reader
        self._writer = writer

        stdin = subprocess.PIPE if self._writer else None
        self._process = subprocess.Popen(args, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        self._reader_thread = threading.Thread(target=self._reader, args=[self._process.stdout])
        self._reader_thread.start()

        self._writer_thread = None
        if self._writer:
            self._writer_thread = threading.Thread(target=self._writer, args=[self._process.stdin])
            self._writer_thread.start()

    def poll(self) -> int | None:
        return self._process.poll()

    def wait(self, timeout_sec: float | None = None) -> int:
        return self._process.wait(timeout_sec)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._process.send_signal(signal.SIGINT)

        self._reader.stop()
        self._reader_thread.join()

        if self._writer and self._writer_thread:
            self._writer.stop()
            self._writer_thread.join()
