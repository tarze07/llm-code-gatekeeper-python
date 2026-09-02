"""Adapter pokrycia różnicowego: `coverage.py` (uruchomienie) + `diff-cover` (branch-aware
przecięcie z diffem).

TOOLS.md §4.5 stawia zasadę wprost: to, co już jest dojrzałym narzędziem OSS, jest
adapterem, nie własną logiką. Rozróżnienie „linia wykonana" od „gałąź w pełni pokryta"
to dokładnie taki przypadek — `coverage.py` zapisuje to w raporcie Cobertura
(atrybut `condition-coverage`), a `diff-cover` już to poprawnie interpretuje przez
`--branch-coverage`. Odtwarzanie tego samodzielnie byłoby ponownym wynajdywaniem
gotowego narzędzia.

Uwaga o zakresie (świadome ograniczenie tej wersji, nie przeoczenie): plik
produkcyjny, którego żaden test nie zaimportował, może w ogóle nie pojawić się
w raporcie `coverage.py` (narzędzie widzi tylko to, co realnie wykonano, chyba że
skonfigurowano `[run] source =` na cały pakiet) — taki plik wtedy nie wnosi nic do
licznika ani mianownika `coverage.diff_ratio`, zamiast policzyć się jako w pełni
niepokryty. Dla kodu z agenta to akurat częsty przypadek („dodałem moduł, nikt go
nie zaimportował") — złapie go `G1.static`/`undeclared_import` (dep-guard), nie ta
bramka.
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gatekeeper_core.adapters.base import ToolFailed, run_tool
from gatekeeper_core.core.runner import Sandbox

COVERAGE_DATA_FILE = ".gatekeeper-coverage"


@dataclass(frozen=True)
class FileCoverage:
    covered: int
    total: int

    @property
    def ratio(self) -> float | None:
        return self.covered / self.total if self.total else None


@dataclass(frozen=True)
class DiffCoverageResult:
    #: Wszystkie pliki z diffa, które `diff-cover` zmierzył — **łącznie z testami**.
    #: Filtrowanie do kodu produkcyjnego to sprawa wywołującego (potrzebuje
    #: `ChangeContext.is_test_file`, którego adapter celowo nie zna).
    files: dict[str, FileCoverage] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def parse_diff_cover_json(payload: str) -> DiffCoverageResult:
    """Czysta funkcja parsująca — testowana na zapisanej próbce (`tests/data/`)."""
    data = json.loads(payload) if payload.strip() else {}
    files: dict[str, FileCoverage] = {}
    for path, stats in (data.get("src_stats") or {}).items():
        covered = len(stats.get("covered_lines") or [])
        violations = len(stats.get("violation_lines") or [])
        files[path] = FileCoverage(covered=covered, total=covered + violations)
    return DiffCoverageResult(files=files, raw=data)


def run_diff_coverage(
    repo: Path,
    sandbox: Sandbox,
    base_sha: str,
    timeout_s: float,
    env: dict[str, str],
    pytest_args: list[str] | None = None,
) -> DiffCoverageResult:
    """Uruchamia cały zestaw testów repo pod `coverage run --branch`, a wynik
    przecina z diffem przez `diff-cover`.

    Celowo **cały** zestaw testów, nie tylko nowe/zmienione (`testing.pytest_runner`
    robi to dla `G2.cross_verify`) — pytanie tu brzmi „czy diff pokrywa *jakikolwiek*
    test", nie tylko nowe.
    """
    with tempfile.TemporaryDirectory(prefix="gatekeeper-diffcov-") as tmp:
        tmp_path = Path(tmp)
        data_file = tmp_path / COVERAGE_DATA_FILE
        xml_report = tmp_path / "coverage.xml"
        json_report = tmp_path / "diffcover.json"

        run_tool(
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--branch",
                f"--data-file={data_file}",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "-p",
                "no:randomly",
                "--continue-on-collection-errors",
                "--override-ini=addopts=",
                *(pytest_args or []),
            ],
            repo,
            sandbox,
            timeout_s,
            # testy mogą być czerwone bez winy tej bramki — coverage i tak zebrało
            # dane wykonania; liczy się tylko, że `coverage run` samo nie padło.
            # 5 = pytest nie zebrał żadnego testu (repo bez testów jeszcze).
            ok_returncodes=(0, 1, 2, 5),
            env=env,
        )

        run_tool(
            [
                sys.executable,
                "-m",
                "coverage",
                "xml",
                f"--data-file={data_file}",
                "-o",
                str(xml_report),
            ],
            repo,
            sandbox,
            timeout_s,
        )
        if not xml_report.exists():
            raise ToolFailed("`coverage xml` nie wyprodukował raportu")

        try:
            run_tool(
                [
                    "diff-cover",
                    str(xml_report),
                    f"--compare-branch={base_sha}",
                    "--branch-coverage",
                    "--total-percent-float",
                    f"--format=json:{json_report}",
                    "--quiet",
                ],
                repo,
                sandbox,
                timeout_s,
            )
        except ToolFailed:
            # zwykle „brak zmian w diffie" albo problem z zakresem porównania —
            # to fakt o tym PR-ze, nie awaria narzędzia
            return DiffCoverageResult()

        if not json_report.exists():
            return DiffCoverageResult()
        return parse_diff_cover_json(json_report.read_text(encoding="utf-8"))
