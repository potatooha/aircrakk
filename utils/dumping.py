from __future__ import annotations
import dataclasses
from typing import Any, Callable


def get_header(columns: dict[str, int]) -> str:
    line = ""

    for name, width in columns.items():
        line += f"{name:<{width}}"

    return line


def get_row(something: Any,
            values_getter: Callable[[Any], list[Any]],
            columns: dict[str, int]) -> str:
    line = ""

    values = values_getter(something)
    widths = columns.values()

    for value, width in zip(values, widths, strict=True):
        value = "-" if value is None else value
        line += f"{value:<{width}}"

    return line


def get_table(items: dict[str, Any],
              values_getter: Callable[[Any], list[Any]],
              keys: list[str],
              columns: dict[str, int]) -> list[str]:
    lines = [get_header(columns)]

    for key in keys:
        item = items[key]
        lines.append(get_row(item, values_getter, columns))

    return lines


def get_dataclass_getter():
    return lambda dataclass: dataclasses.asdict(dataclass).values()
