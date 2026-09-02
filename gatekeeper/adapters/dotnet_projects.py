"""Odnajdywanie projektów .NET i `dotnet list package --vulnerable` (G3.sca).

Wydzielone z `adapters/dotnet.py`, bo to jedyna część adaptera .NET, która
**nie jest** wyłącznie sprawą csharp-packu: `find_project_for`/`projects_for`
są potrzebne zarówno `CsharpStaticChecker` (G1.static, csharp-pack) jak i
`deps.ecosystems.NuGetEcosystem.scan_sca` (G3.sca, core) — oba muszą wiedzieć,
do którego `.csproj` należy zmieniony plik/manifest. Reszta modułu
(`dotnet_build_scenario`, `parse_dotnet_build`, `run_dotnet_build`,
`CsharpStaticChecker`) zostaje w `adapters/dotnet.py` po stronie csharp-packu.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Finding, Severity
from ..core.runner import Sandbox
from .base import relative_to_repo, run_tool

DOTNET = "dotnet"


def find_project_for(repo: Path, file_path: str) -> str | None:
    """Najbliższy przodkowy `.csproj`/`.fsproj` zmienionego pliku `.cs`.

    Szuka w górę od katalogu pliku do korzenia repo — tak jak MSBuild sam
    dopasowuje plik źródłowy do projektu, który go kompiluje. Zwraca ścieżkę
    względną wobec repo, albo `None`, gdy żaden projekt go nie obejmuje.
    """
    current = (repo / file_path).resolve().parent
    root = repo.resolve()
    while True:
        matches = sorted(current.glob("*.csproj")) + sorted(current.glob("*.fsproj"))
        if matches:
            try:
                return matches[0].relative_to(root).as_posix()
            except ValueError:
                return None
        if current == root or current.parent == current:
            return None
        current = current.parent


def projects_for(repo: Path, file_paths: list[str]) -> list[str]:
    """Unikalny, posortowany zestaw projektów dotkniętych zmienionymi plikami."""
    found = {find_project_for(repo, path) for path in file_paths}
    return sorted(p for p in found if p is not None)


def project_for_manifest(repo: Path, manifest_path: str) -> str | None:
    """Projekt, do którego odnosi się zmieniony manifest zależności NuGet.

    `.csproj`/`.fsproj` *są* projektem — zwracane wprost. `packages.config`
    (legacy) leży zwykle obok projektu, który opisuje — szukamy `.csproj` w
    tym samym katalogu. `Directory.Packages.props` (central package
    management) obowiązuje repo-wide i nie da się go tanio przypisać do
    jednego projektu bez pełnej analizy grafu importów MSBuild — `None`
    jest tu uczciwą odpowiedzią, nie zgadywanką.
    """
    if manifest_path.endswith((".csproj", ".fsproj")):
        return manifest_path
    if Path(manifest_path).name == "packages.config":
        directory = Path(manifest_path).parent
        candidates = sorted((repo / directory).glob("*.csproj"))
        return (directory / candidates[0].name).as_posix() if candidates else None
    return None


# --------------------------------------------------------------------------
# `dotnet list package --vulnerable` — G3.sca
# --------------------------------------------------------------------------


def parse_dotnet_list_vulnerable(
    payload: str, repo: Path, new_packages: set[str], gate: str
) -> list[Finding]:
    """`dotnet list package --vulnerable --format json` → `Finding`.

    Filtrowane do `new_packages` (znormalizowane, małe litery id-y NuGet) —
    tak samo jak `parse_pip_audit`: dług w zastanych zależnościach to osobny
    raport, nie blokada tego PR-a. Format obejmuje zarówno pakiety
    bezpośrednie (`topLevelPackages`), jak i tranzytywne (`transitivePackages`)
    — oba mają ten sam kształt wpisu.
    """
    try:
        data = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for project in data.get("projects") or []:
        project_path = relative_to_repo(str(project.get("path") or ""), repo)
        for framework in project.get("frameworks") or []:
            packages = (framework.get("topLevelPackages") or []) + (
                framework.get("transitivePackages") or []
            )
            for pkg in packages:
                name = str(pkg.get("id") or "")
                if name.lower() not in new_packages:
                    continue
                version = str(pkg.get("resolvedVersion") or pkg.get("requestedVersion") or "?")
                for vuln in pkg.get("vulnerabilities") or []:
                    url = str(vuln.get("advisoryurl") or "")
                    advisory_id = url.rsplit("/", 1)[-1] or "unknown"
                    severity = str(vuln.get("severity") or "High")
                    findings.append(
                        Finding(
                            gate=gate,
                            rule_id=f"sca.{advisory_id}",
                            severity=Severity.HIGH,
                            title=f"{name}=={version}: {advisory_id}",
                            failure_scenario=(
                                f"Nowo dodany pakiet NuGet `{name}` w wersji `{version}` ma "
                                f"znaną podatność {severity.lower()} ({url or 'brak URL-a'}). "
                                "To dług wnoszony do repozytorium w tym PR-ze, nie coś, co już "
                                "w nim było — instalacja tej wersji naraża produkcję na lukę, "
                                "która ma już publiczny identyfikator."
                            ),
                            file=project_path,
                            evidence={
                                "snippet": f"{name}=={version}:{advisory_id}",
                                "package": name,
                                "version": version,
                                "advisory_severity": severity,
                                "url": url,
                            },
                        )
                    )
    return findings


def run_dotnet_list_vulnerable(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    project: str,
    new_packages: set[str],
    timeout_s: float = 180.0,
) -> list[Finding]:
    command = [
        DOTNET,
        "list",
        project,
        "package",
        "--vulnerable",
        "--include-transitive",
        "--format",
        "json",
    ]
    # `dotnet list package`: 0 zawsze, niezależnie od tego, czy znalazł
    # podatności — trzeba czytać JSON, nie kod wyjścia.
    result = run_tool(command, repo, sandbox, timeout_s, network=True, ok_returncodes=(0,))
    return parse_dotnet_list_vulnerable(result.stdout, repo, new_packages, gate)
