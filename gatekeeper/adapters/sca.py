"""Adaptery SCA — podatności w nowo dodanych zależnościach: pip-audit
(PyPI), npm audit (npm) i `dotnet list package --vulnerable` (NuGet, w
`adapters/dotnet.py` — współdzieli logikę odnajdywania projektów z G1.static).

Blokujemy wyłącznie na podatnościach w pakietach, które ten PR **wprowadza**
(TOOLS.md §5.1). Dług w już zastanych zależnościach idzie do osobnego
raportu tygodniowego — inaczej pierwszy przebieg na starszym repo blokuje
wszystko i bramka ląduje w koszu jak każda inna bez tego zawężenia.

pip-audit i npm audit **muszą** dostać sieć — pytają o znane podatności w
PyPI/OSV i w bazie doradczej npm. Dlatego oba jawnie wołają
`Sandbox.run(..., network=True)`, zamiast dziedziczyć domyślną izolację
(tak samo NuGet w `adapters/dotnet.py::run_dotnet_list_vulnerable`).
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


# --------------------------------------------------------------------------
# npm audit — podatności w nowo dodanych zależnościach npm
# --------------------------------------------------------------------------

NPM_AUDIT = "npm"


def parse_npm_audit(payload: str, new_packages: set[str], gate: str) -> list[Finding]:
    """`npm audit --json` → `Finding`, tylko dla pakietów z `new_packages`.

    `via` w raporcie npm miesza dwa kształty w tej samej liście: obiekty to
    własne podatności pakietu, stringi to nazwy *innych* pakietów, przez
    które dotarła podatność tranzytywna (np. `request` → `via: [{...}, "form-data",
    "qs"]`). Te drugie pomijamy — to nie jest advisory tego pakietu, tylko
    odsyłacz do wpisu, który i tak jest już w `vulnerabilities` pod własnym
    kluczem i zostanie zgłoszony osobno, jeśli sam też jest `new_packages`.
    """
    data = json.loads(payload or "{}")
    findings: list[Finding] = []
    for name, vuln in (data.get("vulnerabilities") or {}).items():
        from ..deps.manifests import NPM, normalize

        if normalize(NPM, name) not in new_packages:
            continue
        seen: set[str] = set()
        for via in vuln.get("via") or []:
            if not isinstance(via, dict):
                continue  # string = nazwa zależności, nie advisory
            advisory_id = str(via.get("source") or via.get("url") or "unknown")
            if advisory_id in seen:
                continue
            seen.add(advisory_id)
            title = str(via.get("title") or "podatność bez tytułu")
            severity = str(via.get("severity") or vuln.get("severity") or "high")
            url = str(via.get("url") or "")
            findings.append(
                Finding(
                    gate=gate,
                    rule_id=f"sca.{advisory_id}",
                    severity=Severity.HIGH,
                    title=f"{name}: {title}",
                    failure_scenario=(
                        f"Nowo dodany pakiet npm `{name}` ma znaną podatność {severity} "
                        f"({title}{f', {url}' if url else ''}). To dług wnoszony do "
                        "repozytorium w tym PR-ze, nie coś, co już w nim było — instalacja "
                        "tej wersji naraża produkcję na lukę, która ma już publiczny "
                        "identyfikator."
                    ),
                    file="package.json",
                    evidence={
                        "snippet": f"{name}:{advisory_id}",
                        "package": name,
                        "advisory_severity": severity,
                        "url": url,
                    },
                )
            )
    return findings


def run_npm_audit(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    new_packages: set[str],
    timeout_s: float = 180.0,
) -> list[Finding]:
    command = [NPM_AUDIT, "audit", "--json"]
    # npm audit: 0 = czysto, 1 = ZARÓWNO „znaleziono podatności", JAK I błąd
    # (np. brak `package-lock.json`) — ten sam kwirk co pip-audit. Różnica:
    # npm zawsze zwraca poprawny JSON, więc rozróżnienie idzie po kluczu
    # `error`, nie po pustym stdout.
    result = run_tool(command, repo, sandbox, timeout_s, network=True, ok_returncodes=(0, 1))
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ToolFailed(f"npm audit nie zwrócił poprawnego JSON-a: {result.tail()}") from exc
    if "error" in data:
        summary = (data["error"] or {}).get("summary") or data["error"]
        raise ToolFailed(f"npm audit: {summary}")
    return parse_npm_audit(result.stdout, new_packages, gate)
