from __future__ import annotations
from pathlib import Path
import re
import subprocess


FILE = "file"


def _run(args: list[str]) -> str:
    args = [FILE] + args

    result = subprocess.run(args, capture_output=True)

    output = result.stdout.decode()

    if result.returncode:
        print(output)
        raise RuntimeError(f"{args} failed: {result.returncode}")

    return output


def is_text_file(path: Path) -> str:
    output = _run(["-L", str(path)])

    return re.search(r":.* text", output, flags=re.IGNORECASE) is not None
