"""Adaptery lintera i kontroli typów: ruff, mypy, tsc, eslint.

Typy w trybie strict wyłapują dużą część halucynacji API — wywołanie metody,
której nie ma, albo argumentu o innej nazwie. To jest tania bramka o wysokiej
trafności i dlatego jest w kamieniu 3, a nie później. `tsc`/`eslint` pełnią tu
dla TS/JS dokładnie tę samą rolę, co `mypy`/`ruff` dla Pythona.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Finding, Severity
from ..core.runner import Sandbox
from .base import parse_compiler_diagnostics, parse_sarif, relative_to_repo, run_tool

RUFF = "ruff"
MYPY = "mypy"
TSC = "tsc"
ESLINT = "eslint"

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


# --------------------------------------------------------------------------
# tsc — kontrola typów TypeScriptu; dla TS/JS pełni tę samą rolę co mypy
# --------------------------------------------------------------------------


def resolve_bin(repo: Path, name: str) -> str:
    """Preferuj binarkę przypiętą w `node_modules/.bin` repozytorium nad
    globalną — projekt ma zwykle zablokowaną konkretną wersję tsc/eslinta
    w `package.json`, a `PATH` może wskazywać coś zupełnie innego."""
    local = repo / "node_modules" / ".bin" / name
    return str(local) if local.is_file() else name


def tsc_scenario(level: str, code: str, message: str) -> str:
    return (
        f"Kompilator TypeScriptu zgłasza `{code}`: {message}. W kodzie od agenta ta klasa "
        "błędów zwykle oznacza wywołanie API, które nie istnieje albo przyjmuje inne "
        "argumenty — czyli awarię przy pierwszym uruchomieniu tej ścieżki, nie przy "
        "budowaniu."
    )


def parse_tsc(payload: str, repo: Path, gate: str) -> list[Finding]:
    def severity_of(level: str, code: str) -> Severity:
        return Severity.HIGH if level == "error" else Severity.MEDIUM

    return parse_compiler_diagnostics(payload, repo, gate, "tsc", tsc_scenario, severity_of)


def run_tsc(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    timeout_s: float = 120.0,
    args: list[str] | None = None,
) -> list[Finding]:
    tsc_bin = resolve_bin(repo, "tsc")
    command = [tsc_bin, "--noEmit", "--pretty", "false", *(args or [])]
    # tsc: 0 = czysto, 1 = znalezione błędy, 2 = błąd konfiguracji/użycia
    result = run_tool(command, repo, sandbox, timeout_s, ok_returncodes=(0, 1))
    return parse_tsc(result.stdout, repo, gate)


# --------------------------------------------------------------------------
# eslint
# --------------------------------------------------------------------------

#: Rdzeniowe reguły „problem” (błąd, nie styl) — analogia do
#: `RUFF_HIGH_PREFIXES`. Reszta reguł `error`-level w konfiguracji zespołu
#: (a wiele configów ma ich dziesiątki, w tym czysto stylistyczne) trafia do
#: MEDIUM — inaczej pierwszy config ze `"semi": "error"` zalewa raport.
ESLINT_HIGH_RULES = frozenset(
    {
        "no-undef",
        "no-unreachable",
        "no-dupe-keys",
        "no-dupe-args",
        "no-dupe-class-members",
        "no-unsafe-negation",
        "no-unsafe-optional-chaining",
        "no-const-assign",
        "no-cond-assign",
        "no-func-assign",
        "no-import-assign",
        "no-self-compare",
        "use-isnan",
        "no-invalid-regexp",
        "no-eval",
        "no-implied-eval",
        "@typescript-eslint/no-unsafe-assignment",
        "@typescript-eslint/no-unsafe-call",
        "@typescript-eslint/no-unsafe-member-access",
        "@typescript-eslint/no-unsafe-return",
    }
)


def eslint_severity(rule_id: str | None, level: int) -> Severity:
    if level >= 2:
        return Severity.HIGH if rule_id in ESLINT_HIGH_RULES else Severity.MEDIUM
    return Severity.LOW


def eslint_scenario(rule_id: str, message: str) -> str:
    return (
        f"Linter zgłasza `{rule_id}`: {message}. Reguły „problem” (no-undef, no-unreachable, "
        "no-eval i podobne) wskazują kod, który zachowa się inaczej, niż wygląda, albo "
        "wykona coś niebezpiecznego — nie kwestię formatowania."
    )


def parse_eslint(payload: str, repo: Path, gate: str) -> list[Finding]:
    try:
        data = json.loads(payload or "[]")
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for file_result in data:
        file = relative_to_repo(str(file_result.get("filePath") or ""), repo)
        for item in file_result.get("messages") or []:
            rule_id = item.get("ruleId")  # `None` dla błędów parsera eslinta
            message = str(item.get("message") or "").strip()
            findings.append(
                Finding(
                    gate=gate,
                    rule_id=f"eslint.{rule_id or 'parse-error'}",
                    severity=eslint_severity(rule_id, int(item.get("severity") or 1)),
                    title=message,
                    failure_scenario=eslint_scenario(rule_id or "parse-error", message),
                    file=file,
                    line=item.get("line"),
                    evidence={"snippet": f"{rule_id}:{message}", "level": item.get("severity")},
                )
            )
    return findings


def run_eslint(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    timeout_s: float = 120.0,
    args: list[str] | None = None,
) -> list[Finding]:
    eslint_bin = resolve_bin(repo, "eslint")
    command = [eslint_bin, "--format", "json", *(args or []), "."]
    # eslint: 0 = czysto, 1 = znaleziska, 2 = błąd konfiguracji/użycia
    result = run_tool(command, repo, sandbox, timeout_s, ok_returncodes=(0, 1))
    return parse_eslint(result.stdout, repo, gate)
