"""Adaptery lintera i kontroli typów: ruff, mypy.

Typy w trybie strict wyłapują dużą część halucynacji API — wywołanie metody,
której nie ma, albo argumentu o innej nazwie. To jest tania bramka o wysokiej
trafności i dlatego jest w kamieniu 3, a nie później.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Finding, Severity
from ..core.runner import Sandbox
from .base import parse_sarif, run_tool

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
