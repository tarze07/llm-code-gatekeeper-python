"""Kontrakty pluginów drugiego poziomu.

Poziom pierwszy (`gatekeeper.gates`, patrz `gatekeeper/gates/__init__.py`) rejestruje
całe bramki. To za gruboziarniste dla `G1.static`/`G1.deps`/`G3.sca`/`G3.sast`/`G2.*`
— te bramki mają zostać **jednym** logicznym gate ID niezależnie od tego, ile pack'ów
językowych jest zainstalowanych (tego wymaga `policy/gates.yaml` i
`core.orchestrator.DEPENDENCIES`, które referencują gate ID jako stringi).

Cztery protokoły poniżej to poziom drugi: dostawca *wewnątrz* jednej bramki-agregatora,
odkrywany przez osobną, mniejszą grupę entry points. Bramka-agregator (`g1_static.py`
itd.) nie wie nic o konkretnym języku — pętla po zainstalowanych dostawcach i sumowanie
wyników to cała jej logika.

Grupy entry points (deklarowane w `pyproject.toml` pack'a, `[project.entry-points."<grupa>"]`):

- `gatekeeper.static_checkers`   → `StaticChecker`           (G1.static)
- `gatekeeper.dep_ecosystems`    → `EcosystemProvider`       (G1.deps, G3.sca)
- `gatekeeper.test_toolchains`   → `TestToolchain`           (G2.cross_verify, G2.test_sanity,
                                                                G2.diff_coverage)
- `gatekeeper.semgrep_rule_packs`→ `SemgrepRulePackProvider` (G3.sast)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .change import ChangeContext
from .finding import Finding
from .runner import Sandbox

# ---------------------------------------------------------------- G1.static


@dataclass
class StaticCheckOutcome:
    findings: list[Finding] = field(default_factory=list)
    #: Klucze już z prefiksem checkera (np. `"static.python_files_checked"`) —
    #: `StaticChecker.empty_facts()` i `check()` muszą się zgadzać co do kluczy.
    facts: dict[str, Any] = field(default_factory=dict)
    #: Ustawione => bramka-agregator zwraca `GateResult(status="error")`.
    error: str | None = None


class StaticChecker(Protocol):
    """Kompilacja/lint jednego języka na zmienionych plikach."""

    #: Namespace faktów i logów — NIE gate id (ten zostaje jeden: `G1.static`).
    checker_id: str
    #: Wartości `ChangedFile.language`, które ten checker obsługuje.
    languages: tuple[str, ...]

    def empty_facts(self) -> dict[str, Any]: ...

    def check(
        self, change: ChangeContext, config: dict[str, Any], gate_id: str, budget_s: float
    ) -> StaticCheckOutcome: ...


# ------------------------------------------------------------ G1.deps / G3.sca


class EcosystemProvider(Protocol):
    """Manifest + rejestr + typosquat + SCA jednego ekosystemu pakietów
    (PyPI/npm/NuGet/...)."""

    ecosystem: str

    def is_manifest(self, path: str) -> str | None: ...

    def parse_manifest(self, path: str, content: str) -> set[Any]:
        """Zwraca `set[deps.manifests.Dependency]` (typ nieimportowany tutaj,
        żeby core nie musiał znać całego modelu `Dependency` — patrz
        `gatekeeper.deps.manifests` po podziale)."""
        ...

    def normalize(self, name: str) -> str: ...

    def build_registry(self, cache_dir: Path) -> Any:
        """Zwraca `deps.registries.Registry`."""
        ...

    def popular_packages(self) -> frozenset[str]:
        """Baza nazw do wykrywania typosquatu/slopsquatu."""
        ...

    def scan_sca(
        self,
        repo: Path,
        sandbox: Sandbox,
        gate_id: str,
        deps: list[Any],
        timeout_s: float,
        keep_env: tuple[str, ...],
    ) -> list[Finding]:
        """Skan podatności na nowo dodanych zależnościach. Rzuca
        `adapters.base.ToolMissing`/`ToolFailed` jak dzisiejsze adaptery."""
        ...


# --------------------------------------------------------------------- G2.*


class DiscoveryResult(Protocol):
    """Wynik odkrywania testów — kształt zgodny z dzisiejszym
    `testing.discovery.TestItem`, niezależny od języka."""


class QualityIssue(Protocol):
    """Kształt zgodny z dzisiejszym `testing.quality.QualityIssue`."""


class CrossVerifyOutcome(Protocol):
    """Kształt zgodny z dzisiejszym wynikiem `pytest_runner.run_pytest` +
    rozróżnieniem asercja-poległa / błąd-kompilacji-lub-importu."""


class CoverageReport(Protocol):
    path: Path
    #: `"cobertura"` (coverlet, coverage.py) albo `"lcov"` (nyc/c8/vitest) —
    #: `core.diffcover.run_diff_cover_on_report` wspiera oba.
    format: str


class TestToolchain(Protocol):
    """Discovery + jakość testów + cross-verify + producent raportu pokrycia
    dla jednego języka. Jedyny protokół poziomu 2, który sam uruchamia
    podprocesy (test runner ocenianego repo), nie tylko klasyfikuje wynik."""

    language: str

    def discover_tests(self, change: ChangeContext) -> list[DiscoveryResult]: ...

    def lint_quality(self, tests: list[DiscoveryResult]) -> list[QualityIssue]: ...

    def run_cross_verify(
        self, change: ChangeContext, tests: list[DiscoveryResult], config: dict[str, Any]
    ) -> CrossVerifyOutcome: ...

    def produce_coverage_report(
        self, change: ChangeContext, config: dict[str, Any]
    ) -> CoverageReport: ...


# ------------------------------------------------------------------- G3.sast


class SemgrepRulePackProvider(Protocol):
    """Katalog `rules/semgrep/<pack>.yaml` + testy negatywne jednego pack'a."""

    pack_id: str

    def rules_dir(self) -> Path: ...
