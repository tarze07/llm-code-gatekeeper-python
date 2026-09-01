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


@dataclass
class EcosystemScaResult:
    findings: list[Finding] = field(default_factory=list)
    #: Nazwy pakietów, dla których to konkretne SCA nie dało dowodu (np.
    #: pojedynczy pakiet nie rozwiązał się w pip-audit) — częściowa awaria
    #: NIE ma prawa zgasić dowodu dla reszty nowych zależności tego samego
    #: ekosystemu, więc nie jest wyjątkiem, tylko wpisem na tej liście.
    unresolved: list[str] = field(default_factory=list)


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
        gate_id: str,
        deps: list[Any],
        timeout_s: float,
        keep_env: tuple[str, ...],
    ) -> EcosystemScaResult:
        """Skan podatności na nowo dodanych zależnościach. Sandbox (sieć
        włączona zawsze, `memory_mb` zależnie od narzędzia — kwirk CoreCLR
        dla NuGet) buduje sam dostawca, nie agregator: tylko on wie, czego
        jego narzędzie potrzebuje. Rzuca `adapters.base.ToolMissing` przy
        całkowitym braku narzędzia — to jedyny przypadek, w którym cały
        ekosystem zostaje bez dowodu."""
        ...


# --------------------------------------------------------------------- G2.*


class DiscoveryResult(Protocol):
    """Wynik odkrywania testów — kształt zgodny z dzisiejszym
    `testing.discovery.TestItem`, niezależny od języka."""

    file: str
    name: str
    body_hash: str
    lineno: int
    nodeid: str
    declared_escape: str | None


class QualityIssue(Protocol):
    """Kształt zgodny z dzisiejszym `testing.quality.QualityIssue`."""

    rule_id: str
    severity: Any
    title: str
    failure_scenario: str
    evidence: dict[str, Any]


class TestOutcome(Protocol):
    """Kształt zgodny z dzisiejszym `pytest_runner.TestOutcome` — rozróżnia
    asercję poległą od błędu kompilacji/importu (`outcome` przyjmuje m.in.
    `"failed"`, `"error"`, `"missing"`, `"skipped"`)."""

    nodeid: str
    outcome: str


class CoverageReport(Protocol):
    """Kształt zgodny z dzisiejszym `adapters.coverage.DiffCoverageResult`
    (patrz uwaga o zakresie w `testing/toolchain.py`: docelowo, gdy TS/C#
    dostaną własne toolchainy, ten protokół zwęzi się do surowego raportu
    Cobertura/LCOV konsumowanego centralnie przez `core.diffcover`)."""

    files: dict[str, Any]


class TestToolchain(Protocol):
    """Discovery + jakość testów + cross-verify + producent raportu pokrycia
    dla jednego języka. Jedyny protokół poziomu 2, który sam uruchamia
    podprocesy (test runner ocenianego repo), nie tylko klasyfikuje wynik."""

    language: str

    def discover_tests(self, change: ChangeContext) -> list[DiscoveryResult]: ...

    def lint_quality(
        self, change: ChangeContext, tests: list[DiscoveryResult]
    ) -> list[tuple[DiscoveryResult, QualityIssue]]: ...

    def run_cross_verify(
        self, change: ChangeContext, tests: list[DiscoveryResult], config: dict[str, Any]
    ) -> tuple[dict[str, TestOutcome], str]: ...

    def produce_coverage_report(
        self, change: ChangeContext, config: dict[str, Any]
    ) -> CoverageReport: ...


# ------------------------------------------------------------------- G3.sast


class SemgrepRulePackProvider(Protocol):
    """Katalog `rules/semgrep/<pack>.yaml` + testy negatywne jednego pack'a."""

    pack_id: str

    def rules_dir(self) -> Path: ...
