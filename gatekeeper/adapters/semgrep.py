"""Adapter semgrepa — nośnik reguł „nigdy".

Reguły są w `rules/semgrep/` i mają własne testy (`semgrep --test`). Reguła bez
testu negatywnego prędzej czy później zaczyna blokować poprawny kod i podkopuje
zaufanie do całej bramy, więc test negatywny jest tu obowiązkowy tak samo jak
pozytywny.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Finding, Severity
from ..core.runner import Sandbox
from .base import relative_to_repo, run_tool

SEMGREP = "semgrep"
RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep"

SEVERITY = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}


def parse_semgrep(payload: str, repo: Path, gate: str) -> list[Finding]:
    data = json.loads(payload or "{}")
    findings: list[Finding] = []
    for item in data.get("results") or []:
        rule_id = str(item.get("check_id") or "unknown").split(".")[-1]
        extra = item.get("extra") or {}
        message = str(extra.get("message") or "").strip()
        metadata = extra.get("metadata") or {}
        findings.append(
            Finding(
                gate=gate,
                rule_id=f"sast.{rule_id}",
                severity=SEVERITY.get(str(extra.get("severity") or "WARNING"), Severity.HIGH),
                title=message.split("\n")[0] or rule_id,
                failure_scenario=(
                    str(metadata.get("failure_scenario") or "").strip()
                    or f"{message} Reguła należy do zestawu „nigdy”: ten wzorzec nie ma "
                    "poprawnego zastosowania w tym repozytorium, więc trafienie oznacza "
                    "albo błąd, albo świadome obejście zabezpieczenia."
                ),
                file=relative_to_repo(str(item.get("path") or ""), repo),
                line=(item.get("start") or {}).get("line"),
                evidence={
                    "snippet": f"{rule_id}:{item.get('path')}",
                    "cwe": metadata.get("cwe"),
                    "owasp": metadata.get("owasp"),
                },
            )
        )
    return findings


def run_semgrep(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    config: Path | str = RULES_DIR,
    targets: list[str] | None = None,
    timeout_s: float = 300.0,
    max_memory_mb: int = 2000,
) -> list[Finding]:
    command = [
        SEMGREP,
        "--config",
        str(config),
        "--json",
        "--quiet",
        "--metrics=off",  # bez telemetrii: kod firmowy nie wychodzi na zewnątrz
        "--disable-version-check",
        # Limit pamięci narzędzia, NIE `RLIMIT_AS` z sandboksa: silnik semgrepa
        # (OCaml) rezerwuje kilka GB przestrzeni adresowej na starcie niezależnie
        # od realnego zużycia, więc twardy `ulimit -v` zabija go segfaultem przy
        # limitach, na których każde inne narzędzie w tym repo działa bez
        # problemu — zweryfikowane na żywym binarium, nie z dokumentacji.
        "--max-memory",
        str(max_memory_mb),
        *(targets or ["."]),
    ]
    # semgrep: 0 = czysto, 1 = znaleziska
    result = run_tool(command, repo, sandbox, timeout_s, ok_returncodes=(0, 1))
    return parse_semgrep(result.stdout, repo, gate)
