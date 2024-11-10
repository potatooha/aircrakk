from __future__ import annotations
import json
from pathlib import Path


def load_statistics(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}

    with path.open('r') as file:
        return json.load(file)


def store_statistics(path: Path, statistics: dict[str, int]):
    sorted_keys = sorted(statistics.keys(), key=lambda key: statistics[key], reverse=True)
    sorted_statistics = {key: statistics[key] for key in sorted_keys}

    with path.open('w') as file:
        json.dump(sorted_statistics, file, indent=4)


class Statistics:
    def __init__(self, path: Path):
        self._path = path
        self._statistics = load_statistics(path)

    def increment(self, what: str):
        counter = self.statistics.get(what, 0)
        counter = counter + 1
        self._statistics[what] = counter
        self.flush()

    def flush(self):
        store_statistics(self._path, self._statistics)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.flush()
