from __future__ import annotations
from pathlib import Path
import subprocess


CAP2HCCAPX = str(Path(__file__).parent / 'bin' / 'cap2hccapx.bin')


def _run(args: list[str]):
    args = [CAP2HCCAPX] + args

    print(' '.join(args))
    result = subprocess.run(args, capture_output=True)

    if result.returncode:
        print(result.stdout.decode())
        raise RuntimeError(f"{args} failed: {result.returncode}")


def convert_aircrack_capture_to_hashcat_format(input_file_path: Path, output_file_path: Path) -> Path:
    _run([str(input_file_path), str(output_file_path)])
    return output_file_path
