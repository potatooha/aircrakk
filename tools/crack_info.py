from __future__ import annotations
import dataclasses


@dataclasses.dataclass
class CrackProgressInfo:
    """Format of these fields may vary. Do not use `last_passhrase` as a key."""
    speed: str | None
    percentage: str | None
    last_passphrase: str | None
