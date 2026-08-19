"""Adapter pip-audit — podatności w nowo dodanych zależnościach Pythona.

Blokujemy wyłącznie na podatnościach w pakietach, które ten PR **wprowadza**
(TOOLS.md §5.1). Dług w już zastanych zależnościach idzie do osobnego
raportu tygodniowego — inaczej pierwszy przebieg na starszym repo blokuje
wszystko i bramka ląduje w koszu jak każda inna bez tego zawężenia.

pip-audit jest jedynym narzędziem w G3, które **musi** dostać sieć — pyta
o znane podatności w PyPI/OSV. Dlatego jako jedyny adapter woła
`Sandbox.run(..., network=True)` jawnie, zamiast dziedziczyć domyślną
izolację.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Finding, Severity
from ..core.runner import Sandbox
from .base import ToolFailed, run_tool

PIP_AUDIT = "pip-audit"


def parse_pip_audit(
    payload: str, manifest: str, new_packages: set[str], gate: str
) -> list[Finding]:
    """`pip-audit -f json` → `Finding`, tylko dla pakietów z `new_packages`.

    `new_packages` to znormalizowane nazwy (PEP 503) nowo dodanych zależności —
    filtr, bez którego bramka raportowałaby cały dług zastanych zależności
    przy pierwszym uruchomieniu.
    """
    data = json.loads(payload or "{}")
    findings: list[Finding] = []
    for dep in data.get("dependencies") or []:
        name = str(dep.get("name") or "")
        if _normalize(name) not in new_packages:
            continue
        version = str(dep.get("version") or "?")
        seen: set[str] = set()
        for vuln in dep.get("vulns") or []:
            vuln_id = str(vuln.get("id") or "unknown")
            if vuln_id in seen:
                # pip-audit potrafi zwrócić ten sam wpis dwa razy, gdy trafia
                # go zarówno źródło OSV, jak i alias PYSEC/GHSA/CVE.
                continue
            seen.add(vuln_id)
            fix_versions = vuln.get("fix_versions") or []
            fixes = ", ".join(fix_versions) or "brak opublikowanej poprawki"
            findings.append(
                Finding(
                    gate=gate,
                    rule_id=f"sca.{vuln_id}",
                    severity=Severity.HIGH,
                    title=f"{name}=={version}: {vuln_id}",
                    failure_scenario=(
                        f"Nowo dodany pakiet `{name}=={version}` ma znaną podatność "
                        f"{vuln_id} (poprawka: {fixes}). To dług wnoszony do repozytorium "
                        "w tym PR-ze, nie coś, co już w nim było — instalacja tej wersji "
                        "naraża produkcję na lukę, która ma już publiczny identyfikator."
                    ),
                    file=manifest,
                    evidence={
                        "snippet": f"{name}=={version}:{vuln_id}",
                        "package": name,
                        "version": version,
                        "aliases": vuln.get("aliases") or [],
                        "fix_versions": fix_versions,
                    },
                )
            )
    return findings


def run_pip_audit(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    requirements: Path,
    new_packages: set[str],
    manifest: str,
    timeout_s: float = 180.0,
) -> list[Finding]:
    command = [
        PIP_AUDIT,
        "-f",
        "json",
        "-r",
        str(requirements),
        "--progress-spinner",
        "off",
    ]
    # pip-audit: 0 = czysto, 1 = ZARÓWNO „znaleziono podatności", JAK I
    # „rozwiązywanie zależności padło" (np. nieistniejący pakiet). Jedyny
    # sposób odróżnienia jednego od drugiego to obecność wyjścia JSON —
    # przy błędzie rozwiązywania stdout jest pusty, a treść leci na stderr.
    result = run_tool(command, repo, sandbox, timeout_s, network=True, ok_returncodes=(0, 1))
    if not result.stdout.strip():
        raise ToolFailed(f"pip-audit nie zwrócił wyniku: {result.tail()}")
    return parse_pip_audit(result.stdout, manifest, new_packages, gate)


def _normalize(name: str) -> str:
    from ..deps.manifests import PYPI, normalize

    return normalize(PYPI, name)
