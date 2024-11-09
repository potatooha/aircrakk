from __future__ import annotations
import dataclasses


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
