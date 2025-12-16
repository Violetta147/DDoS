from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import List, Tuple


def _build_short_to_cic_map() -> dict[str, str]:
    # Local import to avoid any circular dependency during module import time.
    from capture.utils import FEATURE_ORDER_SHORT, SHORT_TO_CIC2017_NAME

    mapping: dict[str, str] = {}
    for short_name in FEATURE_ORDER_SHORT:
        mapping[short_name] = SHORT_TO_CIC2017_NAME.get(short_name, short_name)

    # Validate header uniqueness for the mapped names.
    mapped_names = list(mapping.values())
    if len(set(mapped_names)) != len(mapped_names):
        raise ValueError("Mapped CIC2017 header contains duplicate names")

    return mapping


def rename_header(short_header: List[str]) -> List[str]:
    mapping = _build_short_to_cic_map()
    renamed: List[str] = []

    for name in short_header:
        renamed.append(mapping.get(name, name))

    if len(set(renamed)) != len(renamed):
        raise ValueError("Renamed header has duplicate column names")

    return renamed


def read_csv_header(csv_path: Path) -> Tuple[List[str], List[List[str]]]:
    rows: List[List[str]] = []
    with csv_path.open("r", newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            rows.append(row)
    return header, rows


def write_csv(csv_path: Path, header: List[str], rows: List[List[str]]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def main(argv: List[str]) -> int:
    if len(argv) != 3:
        print("Usage: python tmp/rename_csv_header_to_cic2017.py <input.csv> <output.csv>", file=sys.stderr)
        return 2

    input_path = Path(argv[1]).expanduser().resolve()
    output_path = Path(argv[2]).expanduser().resolve()

    if not input_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")

    header, rows = read_csv_header(input_path)
    print(f"[DEBUG] Read header columns: {len(header)}", file=sys.stderr)

    new_header = rename_header(header)
    print(f"[DEBUG] Renamed header columns: {len(new_header)}", file=sys.stderr)

    write_csv(output_path, new_header, rows)
    print(f"[DEBUG] Wrote: {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
