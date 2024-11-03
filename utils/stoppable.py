from __future__ import annotations
import threading


class Stoppable:
    def __init__(self):
        self.should_stop = threading.Event()

    def __call__(self, *args):
        while not self.should_stop.is_set():
            self._do_chunk_of_work(*args)

    def stop(self):
        self.should_stop.set()
