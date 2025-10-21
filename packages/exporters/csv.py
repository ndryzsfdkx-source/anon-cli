"""CSV exporter for detection summaries."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Tuple

Row = Tuple[str, int, str]


def write_csv(path: Path, rows: Iterable[Row]) -> None:
    """Write detection rows to ``path`` with a fixed header."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["PATH", "LINE", "CATEGORY"])
        for row in rows:
            writer.writerow(row)


__all__ = ["write_csv", "Row"]
