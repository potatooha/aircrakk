from __future__ import annotations


CLEAR_LINE = '\x1b[2K'


def printc(text: str, **kwargs):
    print(CLEAR_LINE + text, **kwargs)
