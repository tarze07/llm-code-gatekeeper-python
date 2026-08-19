"""Uruchamianie pytesta i czytanie wyniku per test.

Wynik czytamy z JUnit XML (`--junitxml`), a nie z tekstu na stdout. Format jest
stabilny między wersjami pytesta i — co tu najważniejsze — **odróżnia porażkę
asercji od błędu importu**. Ta różnica jest sednem cross-verify: test, który
poległ na asercji, dowodzi czegoś o zachowaniu; test, który nie zaimportował
nieistniejącego jeszcze modułu, dowodzi znacznie mniej.
"""

from __future__ import annotations

import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..core.runner import Sandbox, SandboxPolicy, SandboxUnavailable, scrub_environment

Outcome = Literal["passed", "failed", "error", "skipped", "missing"]


class PytestUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class TestOutcome:
    nodeid: str
    outcome: Outcome
    message: str = ""

    @property
    def proves_difference(self) -> bool:
        """Czy wynik dowodzi, że test odróżnia stary kod od nowego."""
        return self.outcome == "failed"


@dataclass
class RunOutput:
    outcomes: dict[str, TestOutcome]
    returncode: int
    stdout: str
    stderr: str


def build_env(
    worktree: Path,
    extra_paths: list[str] | None = None,
    keep_env: tuple[str, ...] = (),
) -> dict[str, str]:
    """Środowisko wskazujące na kod z worktree, a nie z katalogu roboczego.

    Czyszczenie poświadczeń robi `core.runner` — tu tylko ścieżki importu.
    """
    env = scrub_environment(dict(os.environ), keep_env)
    roots = [str(worktree)]
    for rel in extra_paths or ["src"]:
        candidate = worktree / rel
        if candidate.is_dir():
            roots.append(str(candidate))
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join(roots + ([previous] if previous else []))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTEST_ADDOPTS", None)
    return env


def module_origin(
    module: str, worktree: Path, env: dict[str, str], sandbox: Sandbox | None = None
) -> str | None:
    """Skąd zostałby zaimportowany dany moduł w tym środowisku."""
    code = (
        "import importlib.util,sys\n"
        f"spec = importlib.util.find_spec({module!r})\n"
        "print(spec.origin if spec else '')\n"
    )
    result = (sandbox or Sandbox()).run(
        [sys.executable, "-c", code], cwd=worktree, env=env, timeout_s=60
    )
    return result.stdout.strip() or None


def run_pytest(
    worktree: Path,
    nodeids: list[str],
    env: dict[str, str],
    timeout_s: float = 600.0,
    extra_args: list[str] | None = None,
    sandbox: Sandbox | None = None,
) -> RunOutput:
    """Uruchamia wskazane testy w piaskownicy — **bez dostępu do sieci**.

    To jest kod napisany przez agenta, wykonywany na naszej maszynie. Test,
    który „przypadkiem" woła zewnętrzny endpoint, nie ma jak tego zrobić.
    """
    if not nodeids:
        return RunOutput({}, 0, "", "")
    sandbox = sandbox or Sandbox(SandboxPolicy(timeout_s=timeout_s))
    with tempfile.TemporaryDirectory(prefix="gatekeeper-junit-") as tmp:
        report = Path(tmp) / "junit.xml"
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:randomly",
            "--continue-on-collection-errors",
            "--override-ini=addopts=",
            f"--junitxml={report}",
            "-q",
            *(extra_args or []),
            *nodeids,
        ]
        try:
            result = sandbox.run(cmd, cwd=worktree, env=env, timeout_s=timeout_s)
        except SandboxUnavailable as exc:
            raise PytestUnavailable(str(exc)) from exc
        if result.timed_out:
            raise PytestUnavailable(f"pytest przekroczył limit {timeout_s:g}s")
        if result.returncode == 4 and "No module named pytest" in result.stderr:
            raise PytestUnavailable("pytest nie jest zainstalowany w tym środowisku")
        outcomes = (
            parse_junit(report.read_text(encoding="utf-8"), expected=nodeids)
            if report.exists()
            else {}
        )
        return RunOutput(outcomes, result.returncode, result.stdout, result.stderr)


def parse_junit(payload: str, expected: list[str] | None = None) -> dict[str, TestOutcome]:
    """JUnit XML → mapa nodeid → wynik.

    Domyślny format pytesta (`xunit2`) **nie zapisuje atrybutu `file`** — jest
    tylko `classname` w postaci kropkowanej. Dlatego wyniki dopasowujemy do
    listy testów, o które pytaliśmy, zamiast odtwarzać ścieżkę z nazwy modułu
    (kropkowana nazwa jest wieloznaczna: `a.b` to `a/b.py` albo `a/b/__init__.py`).

    Parametryzację (`test_x[1]`) sprowadzamy do nazwy bazowej — dla cross-verify
    liczy się test, nie pojedynczy przypadek parametru.
    """
    outcomes: dict[str, TestOutcome] = {}
    if not payload.strip():
        return outcomes
    lookup = _expected_lookup(expected or [])
    root = ET.fromstring(payload)
    for case in root.iter("testcase"):
        name = (case.get("name") or "").split("[")[0]
        classname = case.get("classname") or ""
        nodeid = lookup.get((classname, name)) or _nodeid(case)
        if not nodeid:
            # Najczęściej błąd zbierania (`<testcase classname="" name="plik.py">`).
            # Test zostaje bez wyniku, czyli trafi do „słabych dowodów" — i dobrze,
            # bo o zachowaniu kodu rzeczywiście niczego nie powiedział.
            continue
        outcome: Outcome = "passed"
        message = ""
        if case.find("failure") is not None:
            outcome, message = "failed", _text(case.find("failure"))
        elif case.find("error") is not None:
            outcome, message = "error", _text(case.find("error"))
        elif case.find("skipped") is not None:
            outcome, message = "skipped", _text(case.find("skipped"))

        # Test parametryzowany: wystarczy jeden przypadek, który poległ, żeby
        # uznać, że test odróżnia stary kod od nowego.
        previous = outcomes.get(nodeid)
        if previous is None or _rank(outcome) > _rank(previous.outcome):
            outcomes[nodeid] = TestOutcome(nodeid, outcome, message[:2000])
    return outcomes


def _rank(outcome: Outcome) -> int:
    return {"passed": 0, "skipped": 1, "missing": 1, "error": 2, "failed": 3}[outcome]


def _expected_lookup(expected: list[str]) -> dict[tuple[str, str], str]:
    """(classname, nazwa) → nodeid, dla testów, o które pytaliśmy."""
    lookup: dict[tuple[str, str], str] = {}
    for nodeid in expected:
        parts = nodeid.split("::")
        module = parts[0].removesuffix(".py").replace("/", ".")
        class_name = parts[1] if len(parts) == 3 else None
        classname = f"{module}.{class_name}" if class_name else module
        lookup[(classname, parts[-1])] = nodeid
    return lookup


def _nodeid(case: ET.Element) -> str | None:
    """Zapasowa ścieżka dla formatu `xunit1`, który zapisuje atrybut `file`."""
    file = case.get("file")
    name = (case.get("name") or "").split("[")[0]
    classname = case.get("classname") or ""
    if not file or not name:
        return None
    module_dotted = file.removesuffix(".py").replace("/", ".")
    class_part = classname.removeprefix(module_dotted).strip(".")
    return f"{file}::{class_part}::{name}" if class_part else f"{file}::{name}"


def _text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return (element.get("message") or "") + "\n" + (element.text or "")
