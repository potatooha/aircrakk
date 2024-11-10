from __future__ import annotations
import dataclasses
import enum
import json
from pathlib import Path

from config.crack_tool import CrackTool

class TaskKind(enum.StrEnum):
    MASK = 'mask'
    WORDLIST = 'wordlist'


@dataclasses.dataclass
class TaskInfo:
    kind: TaskKind
    preferred_tool: CrackTool | None
    extra_args: list[str]
    comment: str | None


def load_tasks(path: Path) -> dict[str, TaskInfo]:
    with path.open('r') as file:
        raw_tasks = json.load(file)

    tasks = {}

    for task, fields in raw_tasks.items():
        kind = TaskKind(fields['kind'])
        preferred_tool = CrackTool(tool) if (tool := fields.get('preferred_tool', None)) else None
        extra_args = fields.get('extra_args', [])
        comment = fields.get('comment', None)

        tasks[task] = TaskInfo(kind, preferred_tool, extra_args, comment)

    return tasks


@dataclasses.dataclass
class WordlistInfo:
    file_size: int


@dataclasses.dataclass
class MaskInfo:
    extra_args: list[str]


def create_tasks(path: Path,
                 wordlists: dict[Path, WordlistInfo],
                 masks: dict[str, MaskInfo]):
    """Creates an initial version of the task config file. You should adjust it manually."""
    tasks = {}

    # Masks first. Otherwise they will get lost after wordlists
    for mask, mask_info in masks.items():
        fields = {
            'kind': TaskKind.MASK,
        }

        if mask_info.extra_args:
            fields['extra_args'] = mask_info.extra_args

        tasks[mask] = fields

    for wordlist, wordlist_info in wordlists.items():
        file_size = str(wordlist_info.file_size)

        fields = {
            'kind': TaskKind.WORDLIST,
            'comment': f"{wordlist_info.file_size} bytes",
        }

        tasks[str(wordlist)] = fields

    with path.open('w') as file:
        json.dump(tasks, file, indent=4)
