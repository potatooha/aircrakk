from __future__ import annotations
import dataclasses


def tokenize(text: str, *, token_number: int) -> list[str]:
    assert token_number >= 1

    tokens = text.split(maxsplit=token_number - 1)

    if len(tokens) < token_number:
        raise RuntimeError(f"Cannot parse '{text}'")

    return tokens


def split_to_columns(text: str, widths: list[int]) -> list[str]:
    columns = []

    for width in widths:
        width = len(text) if width < 0 else width

        column = text[:width]
        columns.append(column)

        text = text[width:]

    return columns


def column_to_value_or_none(column: str) -> str | None:
    return None if column.isspace() else column.strip()


def column_to_value(column: str, what: str) -> str:
    value = column_to_value_or_none(column)
    if not value:
        raise RuntimeError(f"Column '{what}' must have a value")

    return value


@dataclasses.dataclass
class Column:
    width: int
    required: bool


def parse_row(text: str, column_info: dict[str, Column]) -> list[str | None]:
    # Python >= 3.6 is required

    widths = [info.width for info in column_info.values()]
    raw_columns = split_to_columns(text, widths)

    columns = []

    for index, key in enumerate(column_info.keys()):
        raw_column = raw_columns[index]
        info = column_info[key]

        column = column_to_value(raw_column, key) if info.required else column_to_value_or_none(raw_column)
        columns.append(column)

    return columns
