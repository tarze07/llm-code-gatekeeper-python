#!/usr/bin/env python3
"""Odświeża zwendorowane listy popularnych pakietów (job miesięczny).

Listy są w repo celowo — `dep-guard` nie może zależeć od dostępności zewnętrznego
zbioru danych w trakcie oceniania PR-a. Ten skrypt uruchamia się osobno,
a jego wynik przechodzi przez normalne review jak każda inna zmiana.

Użycie:
    python scripts/refresh_top_packages.py --limit 5000
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "gatekeeper" / "data"
PYPI_SOURCE = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
NPM_SOURCE = "https://raw.githubusercontent.com/anvaka/npm-rank/master/data/final.json"
NUGET_SOURCE = "https://azuresearch-usnc.nuget.org/query"

HEADER = """# Popularne pakiety {registry} — baza do wykrywania typosquatów.
# Plik generowany: `python scripts/refresh_top_packages.py`.
# Źródło: {source}
"""


def fetch(url: str) -> object:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def refresh_pypi(limit: int) -> list[str]:
    data = fetch(PYPI_SOURCE)
    rows = data["rows"] if isinstance(data, dict) else data
    return [row["project"] for row in rows[:limit]]


def refresh_npm(limit: int) -> list[str]:
    data = fetch(NPM_SOURCE)
    return [row["name"] for row in data[:limit]]


def refresh_nuget(limit: int) -> list[str]:
    # Endpoint zwraca max 300 wyników na stronę — paginacja przez `skip`.
    names: list[str] = []
    page = 300
    for skip in range(0, limit, page):
        take = min(page, limit - skip)
        url = f"{NUGET_SOURCE}?q=&take={take}&skip={skip}&sortBy=totalDownloads-desc"
        data = fetch(url)
        rows = data.get("data", []) if isinstance(data, dict) else []
        if not rows:
            break
        names.extend(row["id"] for row in rows)
    return names


def write(path: Path, names: list[str], registry: str, source: str) -> None:
    body = HEADER.format(registry=registry, source=source) + "\n".join(sorted(set(names))) + "\n"
    path.write_text(body, encoding="utf-8")
    print(f"{path.name}: {len(set(names))} nazw")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--only", choices=["pypi", "npm", "nuget"], default=None)
    args = parser.parse_args()

    if args.only in (None, "pypi"):
        write(DATA_DIR / "top_pypi.txt", refresh_pypi(args.limit), "PyPI", PYPI_SOURCE)
    if args.only in (None, "npm"):
        write(DATA_DIR / "top_npm.txt", refresh_npm(args.limit), "npm", NPM_SOURCE)
    if args.only in (None, "nuget"):
        write(DATA_DIR / "top_nuget.txt", refresh_nuget(args.limit), "NuGet", NUGET_SOURCE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
