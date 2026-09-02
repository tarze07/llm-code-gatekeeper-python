"""Adapter pokrycia różnicowego: `coverage.py` (uruchomienie testów pod pokryciem,
eksport Cobertury) — wywołanie `diff-cover` i parsowanie jego wyniku jest już
wspólne dla wszystkich toolchainów, patrz `gatekeeper_core.core.diffcover`.

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

import sys
import tempfile
from pathlib import Path

from gatekeeper_core.adapters.base import ToolFailed, run_tool
from gatekeeper_core.core.diffcover import (
    DiffCoverageResult,
    FileCoverage,
    parse_diff_cover_json,
    run_diff_cover_on_report,
)
from gatekeeper_core.core.runner import Sandbox

__all__ = [
    "DiffCoverageResult",
    "FileCoverage",
    "parse_diff_cover_json",
    "run_diff_coverage",
]

COVERAGE_DATA_FILE = ".gatekeeper-coverage"


def run_diff_coverage(
    repo: Path,
    sandbox: Sandbox,
    base_sha: str,
    timeout_s: float,
    env: dict[str, str],
    pytest_args: list[str] | None = None,
) -> DiffCoverageResult:
    """Uruchamia cały zestaw testów repo pod `coverage run --branch`, eksportuje
    Cobertorę i przekazuje ją do `core.diffcover.run_diff_cover_on_report`.

    Celowo **cały** zestaw testów, nie tylko nowe/zmienione (`testing.pytest_runner`
    robi to dla `G2.cross_verify`) — pytanie tu brzmi „czy diff pokrywa *jakikolwiek*
    test", nie tylko nowe.
    """
    with tempfile.TemporaryDirectory(prefix="gatekeeper-diffcov-") as tmp:
        tmp_path = Path(tmp)
        data_file = tmp_path / COVERAGE_DATA_FILE
        xml_report = tmp_path / "coverage.xml"

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

        return run_diff_cover_on_report(repo, sandbox, [xml_report], base_sha, timeout_s)
