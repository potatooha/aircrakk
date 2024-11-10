from __future__ import annotations
import enum


class CrackTool(enum.StrEnum):
    AIRCRACK = 'aircrack-ng'
    HASHCAT = 'hashcat'
