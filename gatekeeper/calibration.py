"""Zestaw kalibracyjny: deklaratywne PR-y (celowo zepsute i celowo czyste)
uruchamiane przeciw realnej polityce repo, żeby złapać regresję w regułach,
zanim złapie ją produkcja (PLAN.md §6 — „Faza 0"; TOOLS.md, kamień 3).

Przypadek to **dane**, nie kod Pythona: `calibration/cases.yaml` opisuje
oczekiwany werdykt, a `calibration/fixtures/<nazwa>/{base,head}/` to dwa
drzewa katalogów — stan repo przed i po zmianie. Recenzent bez znajomości
pytest potrafi dodać przypadek, wklejając realny PR jako dwa katalogi.

Przypadek, którego narzędzie (`requires_tools`) nie jest zainstalowane, jest
**pomijany**, nie failuje — ta sama zasada co w bramkach: brak narzędzia to
brak dowodu, a nie powód, żeby cały zestaw kalibracyjny czerwienił CI
repozytoriom, które świadomie nie mają np. semgrepa.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .core.change import ChangeContext
from .core.finding import RunResult, Verdict
from .core.orchestrator import run_gates
from .core.policy import Policy

DEFAULT_CASES_PATH = Path("calibration/cases.yaml")
DEFAULT_FIXTURES_DIR = Path("calibration/fixtures")


@dataclass(frozen=True)
class Expectation:
    verdict: Verdict | None = None
    #: Reguły, które MUSZĄ się pojawić wśród `decision.reasons` (blokują albo
    #: kierują do recenzenta — `warn_only` je stąd usuwa, patrz `warning_rules`).
    blocking_rules: tuple[str, ...] = ()
    #: Reguły, które MUSZĄ się pojawić wśród `decision.warnings` — typowe dla
    #: bramek świeżo wprowadzonych przez `warn_only` (TOOLS.md „kolejność budowy").
    warning_rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class Case:
    name: str
    description: str
    fixture: str
    expect: Expectation
    #: Programy, bez których przypadek nie da się ocenić uczciwie (np. `semgrep`).
    requires_tools: tuple[str, ...] = ()


@dataclass
class CaseResult:
    case: Case
    passed: bool
    skipped: bool = False
    reason: str = ""
    run: RunResult | None = None


@dataclass
class CalibrationReport:
    results: list[CaseResult] = field(default_factory=list)

    @property
    def failed(self) -> list[CaseResult]:
        return [r for r in self.results if not r.passed and not r.skipped]

    @property
    def ok(self) -> bool:
        return not self.failed

    def render(self) -> str:
        lines = ["# Zestaw kalibracyjny", ""]
        for r in self.results:
            icon = "⏭️" if r.skipped else ("✅" if r.passed else "❌")
            suffix = f" — {r.reason}" if r.reason else ""
            lines.append(f"{icon} `{r.case.name}`{suffix}")
        checked = [r for r in self.results if not r.skipped]
        passed = sum(1 for r in checked if r.passed)
        skipped = len(self.results) - len(checked)
        lines.append("")
        lines.append(
            f"{passed}/{len(checked)} przypadków zgodnych z oczekiwaniem "
            f"({skipped} pominiętych — brak narzędzia)"
        )
        return "\n".join(lines)


def load_cases(path: Path | str = DEFAULT_CASES_PATH) -> list[Case]:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cases: list[Case] = []
    for raw in data.get("cases") or []:
        expect_raw = raw.get("expect") or {}
        expect = Expectation(
            verdict=Verdict(expect_raw["verdict"]) if "verdict" in expect_raw else None,
            blocking_rules=tuple(expect_raw.get("blocking_rules") or ()),
            warning_rules=tuple(expect_raw.get("warning_rules") or ()),
        )
        cases.append(
            Case(
                name=raw["name"],
                description=raw.get("description", ""),
                fixture=raw.get("fixture", raw["name"]),
                expect=expect,
                requires_tools=tuple(raw.get("requires_tools") or ()),
            )
        )
    return cases


def run_calibration(
    cases: list[Case],
    policy: Policy,
    fixtures_dir: Path | str = DEFAULT_FIXTURES_DIR,
) -> CalibrationReport:
    fixtures_dir = Path(fixtures_dir)
    report = CalibrationReport()
    for case in cases:
        missing = next((t for t in case.requires_tools if shutil.which(t) is None), None)
        if missing:
            report.results.append(
                CaseResult(
                    case=case, passed=True, skipped=True, reason=f"narzędzie niedostępne: {missing}"
                )
            )
            continue
        with _build_case_repo(fixtures_dir / case.fixture) as (repo_path, base_sha, head_sha):
            change = ChangeContext.from_git(repo_path, base_sha, head_sha)
            result = run_gates(change, policy)
        report.results.append(_check(case, result))
    return report


def _check(case: Case, result: RunResult) -> CaseResult:
    blocking_rules = {r.rule for r in result.decision.reasons}
    warning_rules = {w.rule for w in result.decision.warnings}
    problems: list[str] = []

    if case.expect.verdict is not None and result.decision.verdict != case.expect.verdict:
        problems.append(
            f"oczekiwano werdyktu {case.expect.verdict.value}, dostano "
            f"{result.decision.verdict.value}"
        )
    missing_blocking = [r for r in case.expect.blocking_rules if r not in blocking_rules]
    if missing_blocking:
        problems.append(f"brak oczekiwanych reguł blokujących: {', '.join(missing_blocking)}")
    missing_warning = [r for r in case.expect.warning_rules if r not in warning_rules]
    if missing_warning:
        problems.append(f"brak oczekiwanych ostrzeżeń: {', '.join(missing_warning)}")

    return CaseResult(case=case, passed=not problems, reason="; ".join(problems), run=result)


# --------------------------------------------------------------------------
# budowa repo z pary katalogów base/head
# --------------------------------------------------------------------------


@contextmanager
def _build_case_repo(fixture_dir: Path) -> Iterator[tuple[Path, str, str]]:
    if not fixture_dir.exists():
        raise FileNotFoundError(f"brak fixture'u kalibracyjnego: {fixture_dir}")
    with tempfile.TemporaryDirectory(prefix="gatekeeper-calib-") as tmp:
        repo_path = Path(tmp) / "repo"
        repo_path.mkdir()
        _git(repo_path, "init", "-q", "-b", "main")
        _git(repo_path, "config", "user.email", "calibration@example.com")
        _git(repo_path, "config", "user.name", "Kalibracja")
        _git(repo_path, "config", "commit.gpgsign", "false")

        _sync_tree(repo_path, fixture_dir / "base")
        base_sha = _commit(repo_path, "kalibracja: stan bazowy")
        _sync_tree(repo_path, fixture_dir / "head")
        head_sha = _commit(repo_path, "kalibracja: zmiana pod testem")
        yield repo_path, base_sha, head_sha


def _sync_tree(repo_path: Path, src: Path) -> None:
    """Sprowadza drzewo robocze do dokładnej zawartości `src` (poza `.git`).

    Bez tego usunięcie pliku między `base/` a `head/` nie zostałoby wykryte
    jako usunięcie w diffie — worktree zachowałby stary plik.
    """
    for item in repo_path.iterdir():
        if item.name == ".git":
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    if src.exists():
        for item in src.iterdir():
            dest = repo_path / item.name
            if item.is_dir():
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)


def _commit(repo_path: Path, message: str) -> str:
    _git(repo_path, "add", "-A")
    # `--allow-empty`: `base/` bywa identyczny z poprzednim stanem (np. gdy
    # fixture zaczyna od pustego repo) i to nie jest błąd fixture'u.
    _git(repo_path, "commit", "-q", "--allow-empty", "-m", message)
    return _git(repo_path, "rev-parse", "HEAD").strip()


def _git(repo_path: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_path), *args], capture_output=True, text=True, check=True
    )
    return proc.stdout
