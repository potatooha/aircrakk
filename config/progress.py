from __future__ import annotations
import dataclasses
import enum
import json
from pathlib import Path

from config.crack_tool import CrackTool


class TaskStatus(enum.StrEnum):
    NOT_STARTED = 'not_started'
    IN_PROGRESS = 'in_progress'
    FAILED = 'failed'
    EXHAUSTED = 'exhausted'
    CRACKED = 'cracked'


@dataclasses.dataclass
class TaskStatusInfo:
    status: TaskStatus
    tool: CrackTool | None = None
    session_file_path: Path | None = None
    found_key: str | None = None


def load_progress(path: Path) -> dict[str, TaskStatusInfo]:
    progress = {}

    if not path.exists():
        return progress

    with path.open('r') as file:
        raw_progress = json.load(file)

    for task, fields in raw_progress.items():
        status = TaskStatus(fields['status'])
        tool = CrackTool(tool) if (tool := fields.get('tool', None)) else None
        session_file_path = Path(session) if (session := fields.get('session_file_path', None)) else None
        found_key = fields.get('found_key', None)

        progress[task] = TaskStatusInfo(status, tool, session_file_path, found_key)

    return progress


def store_progress(path: Path, progress: dict[str, TaskStatusInfo]):
    raw_progress = {}

    for task, info in progress.items():
        fields = {
            'status': info.status,
        }

        if info.tool:
            fields['tool'] = info.tool

        if info.session_file_path:
            fields['session_file_path'] = str(info.session_file_path)

        if info.found_key:
            fields['found_key'] = info.found_key

        raw_progress[task] = fields

    with path.open('w') as file:
        json.dump(raw_progress, file, indent=4)


class Progress:
    def __init__(self, path: Path):
        self._path = path
        self._progress = load_progress(self._path)

    def get_key_if_found(self) -> str | None:
        for info in self._progress.values():
            if info.found_key:
                return info.found_key

        return None

    def is_finished(self, task: str) -> bool:
        if task not in self._progress:
            return False

        return self._progress[task].status in [TaskStatus.EXHAUSTED, TaskStatus.CRACKED]

    def get_session_if_in_progress(self,
                                   task: str,
                                   tool: CrackTool) -> Path | None:
        if task not in self._progress:
            return None

        info = self._progress[task]
        if info.status != TaskStatus.IN_PROGRESS:
            return None

        if info.tool != tool:
            return None

        if not info.session_file_path or not info.session_file_path.is_file():
            return None

        if not info.session_file_path.stat().st_size:
            return None

        return info.session_file_path

    def start(self,
              task: str,
              tool: CrackTool,
              session_file_path: Path | None = None):
        info = TaskStatusInfo(TaskStatus.IN_PROGRESS, tool, session_file_path)

        self._progress[task] = info
        self.flush()

    def _finish(self, task: str, status: TaskStatus, key: str | None = None):
        info = self._progress[task]
        assert info.status == TaskStatus.IN_PROGRESS
        assert info.tool
        assert not info.found_key

        info.status = status
        info.session_file_path = None
        info.found_key = key

        self._progress[task] = info
        self.flush()

    def finish_failed(self, task: str):
        self._finish(task, TaskStatus.FAILED)

    def finish_exhausted(self, task: str):
        self._finish(task, TaskStatus.EXHAUSTED)

    def finish_with_key(self, task: str, key: str):
        self._finish(task, TaskStatus.CRACKED, key)

    def flush(self):
        store_progress(self._path, self._progress)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.flush()
