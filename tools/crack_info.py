from __future__ import annotations
import dataclasses
import enum
import hashlib
from pathlib import Path


@dataclasses.dataclass
class CrackProgressInfo:
    """Format of these fields may vary. Do not use `last_passhrase` as a key."""
    speed: str | None
    percentage: str | None
    last_passphrase: str | None


@dataclasses.dataclass
class CrackExitInfo:
    """First check `is_error`. Not every non-zero `retuncode` means failure. It depends on a tool."""
    is_error: bool
    returncode: int


class CrackSessionMode(enum.Enum):
    CREATE = enum.auto()
    RESTORE = enum.auto()

    def should_restore(self) -> bool:
        return self == CrackSessionMode.RESTORE


@dataclasses.dataclass
class CrackSession:
    path: Path
    mode: CrackSessionMode

    def get_name_from_path(self) -> str:
        return hashlib.md5(str(self.path).encode()).hexdigest()
