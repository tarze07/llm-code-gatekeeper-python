"""Wspólna warstwa adapterów narzędzi zewnętrznych.

Adaptery psują się przy zmianie wersji narzędzia i tylko golden file to
wychwytuje — dlatego parsowanie jest zawsze **czystą funkcją** oddzieloną od
uruchamiania, a każdy adapter ma test na zapisanej próbce prawdziwego wyjścia.

Druga zasada: **brak narzędzia to brak dowodu**, nigdy „przeszło". Adapter
zgłasza to jawnie, a polityka decyduje, czy to blokuje.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from ..core.change import ChangeContext
from ..core.finding import Finding, Severity
from ..core.runner import ExecResult, Sandbox, SandboxUnavailable


class ToolMissing(RuntimeError):
    pass


class ToolFailed(RuntimeError):
    pass


@dataclass
class ToolRun:
    result: ExecResult
    parsed: list[Finding]


def run_tool(
    command: Sequence[str],
    cwd: Path,
    sandbox: Sandbox,
    timeout_s: float,
    network: bool = False,
    ok_returncodes: tuple[int, ...] = (0,),
    env: dict[str, str] | None = None,
) -> ExecResult:
    """Uruchamia narzędzie i zamienia jego awarie na jawne wyjątki.

    `env=None` (domyślnie): sandbox dziedziczy `os.environ` (oczyszczone
    z poświadczeń) — tak działa większość adapterów. Jawny `env` jest
    potrzebny tam, gdzie narzędzie musi widzieć kod z innej ścieżki niż
    bieżący katalog roboczy (np. `PYTHONPATH` w `adapters/coverage.py`,
    ten sam problem co `testing/pytest_runner.py::build_env`).
    """
    try:
        result = sandbox.run(command, cwd=cwd, env=env, timeout_s=timeout_s, network=network)
    except SandboxUnavailable as exc:
        raise ToolMissing(str(exc)) from exc
    if result.timed_out:
        raise ToolFailed(f"{command[0]} przekroczył limit {timeout_s:g}s")
    if result.returncode not in ok_returncodes:
        raise ToolFailed(f"{command[0]} zakończył się kodem {result.returncode}: {result.tail()}")
    return result


def relative_to_repo(path: str, repo: Path) -> str:
    """Ścieżka względem repozytorium — z `file://` i ze ścieżek bezwzględnych.

    Narzędzia zwracają ścieżki w co najmniej trzech postaciach. Bez sprowadzenia
    ich do jednej porównanie ze zmienionymi plikami zawsze zwraca „brak
    trafienia", a wtedy filtrowanie do diffa po cichu wycina wszystko.
    """
    if not path:
        return ""
    if path.startswith("file://"):
        path = unquote(urlparse(path).path)
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            return candidate.as_posix()
    return candidate.as_posix().removeprefix("./")


def only_changed_lines(
    findings: Sequence[Finding], change: ChangeContext, context: int = 3
) -> list[Finding]:
    """Zostawia znaleziska w zmienionych liniach (z marginesem).

    Bez tego pierwszy przebieg na starszym repozytorium daje tysiące błędów
    i projekt umiera w dniu wdrożenia. Dług techniczny to osobny raport,
    nie blokada tego PR-a.
    """
    changed = {f.path: f.added_lines for f in change.files}
    out: list[Finding] = []
    for finding in findings:
        if finding.file is None:
            continue
        lines = changed.get(finding.file)
        if lines is None:
            continue
        if finding.line is None or any(abs(finding.line - line) <= context for line in lines):
            out.append(finding)
    return out


# --------------------------------------------------------------------------
# SARIF — format pośredni, który mówi większość narzędzi statycznych
# --------------------------------------------------------------------------

SARIF_LEVELS = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def parse_sarif(
    payload: str,
    repo: Path,
    gate: str,
    rule_prefix: str,
    scenario: Callable[[str, str], str],
    severity_of: Callable[[str, str], Severity] | None = None,
) -> list[Finding]:
    data = json.loads(payload or "{}")
    findings: list[Finding] = []
    for run in data.get("runs") or []:
        for item in run.get("results") or []:
            rule_id = str(item.get("ruleId") or "unknown")
            message = ((item.get("message") or {}).get("text") or "").strip()
            level = str(item.get("level") or "warning").lower()
            file, line = _sarif_location(item, repo)
            severity = (
                severity_of(rule_id, level)
                if severity_of
                else SARIF_LEVELS.get(level, Severity.MEDIUM)
            )
            findings.append(
                Finding(
                    gate=gate,
                    rule_id=f"{rule_prefix}.{rule_id}",
                    severity=severity,
                    title=message or rule_id,
                    failure_scenario=scenario(rule_id, message),
                    file=file,
                    line=line,
                    evidence={"snippet": f"{rule_id}:{message}", "level": level},
                )
            )
    return findings


# --------------------------------------------------------------------------
# Diagnostyka kompilatora — format, którym mówi zarówno tsc, jak i MSBuild
# (`dotnet build`): `plik(linia,kolumna): poziom KODxxxx: treść [projekt]`.
# Żadne z tych dwóch narzędzi nie ma trybu JSON, więc to jest format
# pośredni analogiczny do SARIF-a dla tej rodziny narzędzi.
# --------------------------------------------------------------------------

_COMPILER_DIAGNOSTIC_RE = re.compile(
    r"^(?P<file>.+?)\((?P<line>\d+),(?P<col>\d+)\):\s*"
    r"(?P<level>error|warning)\s+(?P<code>[A-Za-z]+\d+):\s*"
    r"(?P<message>.*?)"
    r"(?:\s*\[(?P<project>[^\[\]]+)\])?$"
)


def parse_compiler_diagnostics(
    payload: str,
    repo: Path,
    gate: str,
    rule_prefix: str,
    scenario: Callable[[str, str, str], str],
    severity_of: Callable[[str, str], Severity] | None = None,
) -> list[Finding]:
    """`tsc --noEmit --pretty false` / `dotnet build -v quiet` → `Finding`.

    Jedna linia = jedna diagnostyka; linie, które nie pasują do formatu
    (postęp budowania, podsumowanie, puste linie), są po cichu pomijane —
    tak samo jak `parse_mypy` pomija śmieci przed właściwym JSON Lines.
    """
    findings: list[Finding] = []
    for line in payload.splitlines():
        match = _COMPILER_DIAGNOSTIC_RE.match(line.strip())
        if not match:
            continue
        level = match.group("level")
        code = match.group("code")
        message = match.group("message").strip()
        file = relative_to_repo(match.group("file").strip(), repo)
        severity = (
            severity_of(level, code) if severity_of else SARIF_LEVELS.get(level, Severity.MEDIUM)
        )
        findings.append(
            Finding(
                gate=gate,
                rule_id=f"{rule_prefix}.{code}",
                severity=severity,
                title=message,
                failure_scenario=scenario(level, code, message),
                file=file,
                line=int(match.group("line")),
                evidence={"snippet": f"{code}:{message}", "level": level},
            )
        )
    return findings


def _sarif_location(item: dict[str, Any], repo: Path) -> tuple[str | None, int | None]:
    for location in item.get("locations") or []:
        physical = location.get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        region = physical.get("region") or {}
        if uri:
            return relative_to_repo(str(uri), repo), region.get("startLine")
    return None, None
