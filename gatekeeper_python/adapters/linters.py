"""Adaptery lintera i kontroli typów: ruff, mypy.

Typy w trybie strict wyłapują dużą część halucynacji API — wywołanie metody,
której nie ma, albo argumentu o innej nazwie. To jest tania bramka o wysokiej
trafności. `ruff`/`mypy` pełnią tu dla Pythona dokładnie tę samą rolę, co
`tsc`/`eslint` dla TS/JS (`llm-code-gatekeeper-ts`, `adapters/linters.py`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gatekeeper_core.adapters.base import ToolFailed, ToolMissing, parse_sarif, run_tool
from gatekeeper_core.core.change import ChangeContext
from gatekeeper_core.core.finding import Finding, Severity
from gatekeeper_core.core.plugins import StaticCheckOutcome
from gatekeeper_core.core.runner import Sandbox, SandboxPolicy

RUFF = "ruff"
MYPY = "mypy"

#: Reguły ruffa, które są realnym defektem, a nie kwestią stylu. Reszta
#: raportuje się jako `low` — zgłoszenie stylistyczne udające błąd to
#: najprostszy sposób na to, żeby zespół przestał czytać raporty.
RUFF_HIGH_PREFIXES = ("F", "B", "S", "ASYNC", "PL")


def ruff_severity(rule_id: str, level: str) -> Severity:
    if rule_id.startswith(RUFF_HIGH_PREFIXES):
        return Severity.MEDIUM if level != "error" else Severity.HIGH
    return Severity.LOW


def ruff_scenario(rule_id: str, message: str) -> str:
    return (
        f"Linter zgłasza `{rule_id}`: {message}. Reguły z rodzin F/B/S wskazują kod, "
        "który zachowa się inaczej, niż wygląda (nieużywana zmienna, złapany zły wyjątek, "
        "niebezpieczne wywołanie), a nie kwestię formatowania."
    )


def parse_ruff(payload: str, repo: Path, gate: str) -> list[Finding]:
    """SARIF z ruffa. Uwaga: `uri` jest ścieżką **bezwzględną** w `file://`."""
    return parse_sarif(
        payload,
        repo=repo,
        gate=gate,
        rule_prefix="ruff",
        scenario=ruff_scenario,
        severity_of=ruff_severity,
    )


def run_ruff(
    repo: Path, sandbox: Sandbox, gate: str, timeout_s: float = 120.0, args: list[str] | None = None
) -> list[Finding]:
    command = [RUFF, "check", "--output-format", "sarif", *(args or []), "."]
    # ruff kończy się kodem 1, gdy znajdzie problemy — to nie jest awaria narzędzia
    result = run_tool(command, repo, sandbox, timeout_s, ok_returncodes=(0, 1))
    return parse_ruff(result.stdout, repo, gate)


def parse_mypy(payload: str, repo: Path, gate: str) -> list[Finding]:
    """mypy `--output=json` daje JSON Lines, po jednym obiekcie na linię."""
    findings: list[Finding] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        severity = str(item.get("severity") or "error")
        if severity == "note":
            continue  # notatki to podpowiedzi narzędzia, nie defekty
        code = str(item.get("code") or "error")
        message = str(item.get("message") or "").strip()
        findings.append(
            Finding(
                gate=gate,
                rule_id=f"mypy.{code}",
                severity=Severity.HIGH if severity == "error" else Severity.MEDIUM,
                title=message,
                failure_scenario=(
                    f"Kontrola typów odrzuca ten kod (`{code}`): {message}. W kodzie od agenta "
                    "ta klasa błędów zwykle oznacza wywołanie API, które nie istnieje albo "
                    "przyjmuje inne argumenty — czyli awarię przy pierwszym uruchomieniu "
                    "tej ścieżki, nie przy budowaniu."
                ),
                file=str(item.get("file") or "") or None,
                line=item.get("line"),
                evidence={"snippet": f"{code}:{message}", "severity": severity},
            )
        )
    return findings


def run_mypy(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    targets: list[str],
    timeout_s: float = 180.0,
    args: list[str] | None = None,
) -> list[Finding]:
    if not targets:
        return []
    command = [MYPY, "--output=json", "--no-error-summary", *(args or []), *targets]
    # mypy: 0 = czysto, 1 = znalezione błędy, 2 = błąd użycia
    result = run_tool(command, repo, sandbox, timeout_s, ok_returncodes=(0, 1))
    return parse_mypy(result.stdout, repo, gate)


class PythonStaticChecker:
    """`StaticChecker` (`gatekeeper_core.core.plugins`) dla Pythona: ruff + mypy."""

    checker_id = "python"
    languages = ("python",)

    def empty_facts(self) -> dict[str, Any]:
        return {
            "static.python_files_checked": 0,
            "static.ruff_available": True,
            "static.mypy_available": True,
        }

    def check(
        self, change: ChangeContext, config: dict[str, Any], gate_id: str, budget_s: float
    ) -> StaticCheckOutcome:
        facts = self.empty_facts()
        findings: list[Finding] = []
        python_files = [
            f.path for f in change.effective_files if f.language == "python" and f.status != "D"
        ]
        facts["static.python_files_checked"] = len(python_files)
        if not python_files:
            return StaticCheckOutcome(findings=findings, facts=facts)

        require_ruff = bool(config.get("require_ruff", True))
        require_mypy = bool(config.get("require_mypy", False))
        sandbox = Sandbox(
            SandboxPolicy(
                network=False, timeout_s=budget_s, keep_env=tuple(config.get("keep_env", ()))
            )
        )

        try:
            findings.extend(run_ruff(change.repo, sandbox, gate_id, timeout_s=budget_s / 4))
        except ToolMissing as exc:
            facts["static.ruff_available"] = False
            if require_ruff:
                # Brak narzędzia nie jest zieloną bramką — to brak dowodu.
                return StaticCheckOutcome(findings=findings, facts=facts, error=str(exc))
        except ToolFailed as exc:
            return StaticCheckOutcome(findings=findings, facts=facts, error=str(exc))

        try:
            findings.extend(
                run_mypy(
                    change.repo,
                    sandbox,
                    gate_id,
                    targets=python_files,
                    timeout_s=budget_s / 4,
                    args=list(config.get("mypy_args", [])),
                )
            )
        except ToolMissing as exc:
            facts["static.mypy_available"] = False
            if require_mypy:
                return StaticCheckOutcome(findings=findings, facts=facts, error=str(exc))
        except ToolFailed as exc:
            if require_mypy:
                return StaticCheckOutcome(findings=findings, facts=facts, error=str(exc))
            # mypy potrafi się wywrócić na błędzie konfiguracji (target spoza
            # pakietu, brak stubów) — bez `require_mypy` to brak dowodu z tego
            # narzędzia, nie defekt w kodzie PR-a.
            facts["static.mypy_available"] = False
        return StaticCheckOutcome(findings=findings, facts=facts)
